"""ReachabilityRunner — checks if client code can reach vulnerable functions."""

from __future__ import annotations

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnsentinel.core.github import parse_repo_url
from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.engines.reachability.diff_parser import extract_functions_from_diff
from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.services.client_vuln_service import ClientVulnService
from vulnsentinel.services.library_service import LibraryService
from vulnsentinel.services.project_service import ProjectService
from vulnsentinel.services.upstream_vuln_service import UpstreamVulnService
from z_code_analyzer.api import CodeAnalyzer, VulnImpactRequest

log = structlog.get_logger("vulnsentinel.engine.reachability")


class ReachabilityRunner:
    """Poll pending client_vulns and check reachability via zca."""

    def __init__(
        self,
        client_vuln_service: ClientVulnService,
        upstream_vuln_service: UpstreamVulnService,
        library_service: LibraryService,
        project_service: ProjectService,
        code_analyzer: CodeAnalyzer,
        github_client: GitHubClient,
    ) -> None:
        self._cv_service = client_vuln_service
        self._uv_service = upstream_vuln_service
        self._lib_service = library_service
        self._project_service = project_service
        self._analyzer = code_analyzer
        self._github = github_client

    async def analyze_one(
        self,
        session: AsyncSession,
        client_vuln: ClientVuln,
    ) -> None:
        """Run reachability analysis for a single client_vuln.

        Steps:
        1. Load upstream_vuln → get affected_functions and commit_sha.
        2. Load library (needed for diff fallback and reachability check).
        3. If affected_functions is empty → diff fallback via GitHub API.
        4. Call CodeAnalyzer.investigate_vuln() with client + library repo info.
        5. Write reachable_path + finalize pipeline.
        """
        # Mark pipeline as path_searching
        await self._cv_service.update_pipeline(
            session,
            client_vuln.id,
            pipeline_status="path_searching",
            clear_error=True,
        )

        # 1. Load upstream vuln
        uv_detail = await self._uv_service.get(session, client_vuln.upstream_vuln_id)
        upstream_vuln = uv_detail["vuln"]
        affected_functions: list[str] = upstream_vuln.affected_functions or []

        # 2. Load library (needed for both diff fallback and reachability check)
        library = await self._lib_service.get_by_id(session, upstream_vuln.library_id)

        # 3. Diff fallback when affected_functions is empty
        if not affected_functions and upstream_vuln.commit_sha:
            if library is not None:
                try:
                    owner, repo = parse_repo_url(library.repo_url)
                    affected_functions = await extract_functions_from_diff(
                        self._github, owner, repo, upstream_vuln.commit_sha
                    )
                except Exception:
                    log.warning(
                        "reachability.diff_fallback_failed",
                        client_vuln_id=str(client_vuln.id),
                        exc_info=True,
                    )

        # 4. Build request and run investigation
        project = await self._project_service.get_project(session, client_vuln.project_id)
        if project is None:
            # Unrecoverable: finalize as not_affect to avoid infinite retry
            log.error(
                "reachability.project_not_found",
                client_vuln_id=str(client_vuln.id),
                project_id=str(client_vuln.project_id),
            )
            await self._cv_service.update_pipeline(
                session,
                client_vuln.id,
                pipeline_status="path_searching",
                error_message="project not found",
            )
            await self._cv_service.finalize(session, client_vuln.id, is_affected=False)
            return

        client_version = project.current_version or "main"
        library_repo_url = library.repo_url if library else ""
        library_version = client_vuln.resolved_version or upstream_vuln.commit_sha

        request = VulnImpactRequest(
            client_repo_url=project.repo_url,
            client_version=client_version,
            library_repo_url=library_repo_url,
            library_version=library_version,
            affected_functions=affected_functions,
            commit_sha=upstream_vuln.commit_sha,
        )
        result = await self._analyzer.investigate_vuln(request)

        # 4. Handle errors — stay in path_searching and record error,
        #    but do NOT revert to pending (avoids infinite retry loop).
        if result.error:
            log.info(
                "reachability.check_error",
                client_vuln_id=str(client_vuln.id),
                error=result.error,
            )
            await self._cv_service.update_pipeline(
                session,
                client_vuln.id,
                pipeline_status="path_searching",
                error_message=f"reachability: {result.error}",
            )
            await self._cv_service.finalize(session, client_vuln.id, is_affected=False)
            return

        # 5. Write reachable_path result, then finalize in one flow
        reachable_path = {
            "found": result.is_reachable,
            "strategy": result.strategy,
            "searched_functions": result.searched_functions,
            "client_snapshot_id": result.client_snapshot_id,
            "library_snapshot_id": result.library_snapshot_id,
        }
        if result.depth is not None:
            reachable_path["depth"] = result.depth
        if result.paths:
            reachable_path["call_chain"] = result.paths

        await self._cv_service.update_pipeline(
            session,
            client_vuln.id,
            pipeline_status="path_searching",
            is_affected=result.is_reachable,
            reachable_path=reachable_path,
        )
        await self._cv_service.finalize(session, client_vuln.id, is_affected=result.is_reachable)

        log.info(
            "reachability.done",
            client_vuln_id=str(client_vuln.id),
            is_reachable=result.is_reachable,
            strategy=result.strategy,
        )

    async def run_batch(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        limit: int = 20,
    ) -> int:
        """Poll pending pipeline client_vulns and analyze reachability.

        Each client_vuln is processed in its own session for isolation.
        Returns the number of client_vulns processed.
        """
        async with session_factory() as session:
            pending = await self._cv_service.list_pending_pipeline(session, limit)
        if not pending:
            return 0

        processed = 0
        for cv in pending:
            try:
                async with session_factory() as session:
                    await self.analyze_one(session, cv)
                    await session.commit()
                    processed += 1
            except Exception:
                log.error(
                    "reachability.batch_failed",
                    client_vuln_id=str(cv.id),
                    exc_info=True,
                )

        return processed
