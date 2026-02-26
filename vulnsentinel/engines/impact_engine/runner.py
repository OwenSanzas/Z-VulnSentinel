"""ImpactRunner — polls published vulns, creates client_vuln records."""

from __future__ import annotations

import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.engines.impact_engine.assessor import assess_impact
from vulnsentinel.models.upstream_vuln import UpstreamVuln
from vulnsentinel.services.client_vuln_service import ClientVulnService
from vulnsentinel.services.upstream_vuln_service import UpstreamVulnService

log = structlog.get_logger("vulnsentinel.engine")


class ImpactRunner:
    """Integrated mode: poll published vulns and create client_vuln records."""

    def __init__(
        self,
        upstream_vuln_service: UpstreamVulnService,
        client_vuln_service: ClientVulnService,
        project_dependency_dao: ProjectDependencyDAO,
    ) -> None:
        self._vuln_service = upstream_vuln_service
        self._cv_service = client_vuln_service
        self._dep_dao = project_dependency_dao

    async def process_one(
        self,
        session: AsyncSession,
        upstream_vuln: UpstreamVuln,
    ) -> int:
        """Assess impact for a single upstream vuln, creating client_vulns.

        Returns the number of client_vuln records created.
        """
        deps = await self._dep_dao.list_by_library(session, upstream_vuln.library_id)
        if not deps:
            log.info(
                "impact.no_dependents",
                upstream_vuln_id=str(upstream_vuln.id),
                library_id=str(upstream_vuln.library_id),
            )
            return 0

        results = assess_impact(upstream_vuln.id, deps)
        created = 0

        for r in results:
            try:
                await self._cv_service.create(
                    session,
                    upstream_vuln_id=r.upstream_vuln_id,
                    project_id=r.project_id,
                    constraint_expr=r.constraint_expr,
                    constraint_source=r.constraint_source,
                    resolved_version=r.resolved_version,
                )
                created += 1
            except IntegrityError:
                await session.rollback()
                log.debug(
                    "impact.duplicate_skipped",
                    upstream_vuln_id=str(r.upstream_vuln_id),
                    project_id=str(r.project_id),
                )

        log.info(
            "impact.processed",
            upstream_vuln_id=str(upstream_vuln.id),
            dependents=len(deps),
            created=created,
        )
        return created

    async def run_batch(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        limit: int = 20,
    ) -> int:
        """Poll and process up to *limit* published vulns.

        Each upstream_vuln is processed in its own session for event-level
        isolation — a failure in one does not affect others.

        Returns total number of client_vuln records created.
        """
        async with session_factory() as session:
            vulns = await self._vuln_service.list_published_without_impact(session, limit)
        if not vulns:
            return 0

        total_created = 0
        for vuln in vulns:
            try:
                async with session_factory() as session:
                    created = await self.process_one(session, vuln)
                    await session.commit()
                    total_created += created
            except Exception:
                log.error(
                    "impact.batch_vuln_failed",
                    upstream_vuln_id=str(vuln.id),
                    exc_info=True,
                )

        return total_created
