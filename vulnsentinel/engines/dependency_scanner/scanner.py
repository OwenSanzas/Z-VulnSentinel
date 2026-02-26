"""DependencyScanner — standalone scan + integrated DB sync."""

from __future__ import annotations

import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

# Ensure parsers are registered before any scan runs.
import vulnsentinel.engines.dependency_scanner.parsers  # noqa: F401
from vulnsentinel.engines.dependency_scanner.models import ScannedDependency, ScanResult
from vulnsentinel.engines.dependency_scanner.registry import discover_manifests
from vulnsentinel.engines.dependency_scanner.repo import shallow_clone
from vulnsentinel.services.library_service import LibraryService
from vulnsentinel.services.project_service import ProjectService

log = structlog.get_logger("vulnsentinel.engine")


def scan(repo_path: Path) -> list[ScannedDependency]:
    """Scan a local repo directory for dependencies (no DB required)."""
    matches = discover_manifests(repo_path)
    results: list[ScannedDependency] = []
    for parser, file_path in matches:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        parsed = parser.parse(file_path, content)
        # Fix source_file to be relative to repo root
        rel = str(file_path.relative_to(repo_path))
        for dep in parsed:
            dep.source_file = rel
        results.extend(parsed)
    return results


class DependencyScanner:
    """Integrated mode: scan + sync to DB via Service layer."""

    def __init__(
        self,
        project_service: ProjectService,
        library_service: LibraryService,
    ) -> None:
        self._project_service = project_service
        self._library_service = library_service

    # ── integrated mode ──────────────────────────────────────────────────

    async def run(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
    ) -> ScanResult:
        """Full pipeline: clone -> scan -> upsert libraries -> upsert deps -> delete stale.

        Returns a :class:`ScanResult` summarising what happened.

        The clone + scan phase does not perform any DB access, keeping
        the session idle during potentially slow git I/O.
        """
        project = await self._project_service.get_project(session, project_id)
        if project is None:
            raise ValueError(f"project {project_id} not found")

        if not project.auto_sync_deps:
            return ScanResult(scanned=[], synced_count=0, deleted_count=0, skipped=True)

        ref = project.pinned_ref or project.default_branch

        # ── Clone + scan (no DB access) ──────────────────────────────────
        scanned = await self._clone_and_scan(project.repo_url, ref)

        # ── DB sync ──────────────────────────────────────────────────────
        # Split into resolvable (has repo_url) and unresolved
        resolvable = [d for d in scanned if d.library_repo_url is not None]
        unresolved = [d for d in scanned if d.library_repo_url is None]

        # Upsert libraries and collect IDs
        lib_id_map: dict[str, uuid.UUID] = {}
        for dep in resolvable:
            lib = await self._library_service.upsert(
                session,
                name=dep.library_name,
                repo_url=dep.library_repo_url,  # type: ignore[arg-type]
            )
            lib_id_map[dep.library_name] = lib.id

        # Batch upsert dependencies + delete stale
        dep_map: dict[uuid.UUID, dict] = {}
        for dep in resolvable:
            lib_id = lib_id_map[dep.library_name]
            prev = dep_map.get(lib_id)
            if prev is not None:
                log.debug(
                    "scanner.dep_overwritten",
                    library_id=str(lib_id),
                    old_source=prev["constraint_source"],
                    new_source=dep.source_file,
                )
            dep_map[lib_id] = {
                "project_id": project_id,
                "library_id": lib_id,
                "constraint_expr": dep.constraint_expr,
                "resolved_version": dep.resolved_version,
                "constraint_source": dep.source_file,
            }
        dep_rows = list(dep_map.values())
        keep_ids = set(lib_id_map.values())

        synced_count, deleted_count = await self._project_service.sync_dependencies(
            session, project_id, dep_rows, keep_ids
        )

        # Update project timestamp
        await self._project_service.update_scan_timestamp(
            session, project_id, datetime.now(timezone.utc)
        )

        return ScanResult(
            scanned=scanned,
            synced_count=synced_count,
            deleted_count=deleted_count,
            unresolved=unresolved,
        )

    @staticmethod
    async def _clone_and_scan(repo_url: str, ref: str) -> list[ScannedDependency]:
        """Clone a repo and scan for dependencies (no DB access)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = await shallow_clone(repo_url, ref, Path(tmpdir))
            return scan(repo_path)
