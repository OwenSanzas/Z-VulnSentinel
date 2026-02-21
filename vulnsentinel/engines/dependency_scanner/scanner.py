"""DependencyScanner — standalone scan + integrated DB sync."""

from __future__ import annotations

import logging
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

# Ensure parsers are registered before any scan runs.
import vulnsentinel.engines.dependency_scanner.parsers  # noqa: F401
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.engines.dependency_scanner.models import ScannedDependency, ScanResult
from vulnsentinel.engines.dependency_scanner.registry import discover_manifests
from vulnsentinel.engines.dependency_scanner.repo import shallow_clone
from vulnsentinel.services.library_service import LibraryService

logger = logging.getLogger(__name__)


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
    """Integrated mode: scan + sync to DB."""

    def __init__(
        self,
        project_dao: ProjectDAO,
        dep_dao: ProjectDependencyDAO,
        library_service: LibraryService,
    ) -> None:
        self._project_dao = project_dao
        self._dep_dao = dep_dao
        self._library_service = library_service

    # ── integrated mode ──────────────────────────────────────────────────

    async def run(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
    ) -> ScanResult:
        """Full pipeline: clone -> scan -> upsert libraries -> upsert deps -> delete stale.

        Returns a :class:`ScanResult` summarising what happened.
        """
        project = await self._project_dao.get_by_id(session, project_id)
        if project is None:
            raise ValueError(f"project {project_id} not found")

        if not project.auto_sync_deps:
            return ScanResult(scanned=[], synced_count=0, deleted_count=0, skipped=True)

        ref = project.pinned_ref or project.default_branch

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = await shallow_clone(project.repo_url, ref, Path(tmpdir))
            scanned = scan(repo_path)

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

        # Batch upsert dependencies (dedup by library_id — last manifest wins)
        dep_map: dict[uuid.UUID, dict] = {}
        for dep in resolvable:
            lib_id = lib_id_map[dep.library_name]
            dep_map[lib_id] = {
                "project_id": project_id,
                "library_id": lib_id,
                "constraint_expr": dep.constraint_expr,
                "resolved_version": dep.resolved_version,
                "constraint_source": dep.source_file,
            }
        dep_rows = list(dep_map.values())
        upserted = await self._dep_dao.batch_upsert(session, dep_rows)

        # Delete stale scanner deps
        keep_ids = set(lib_id_map.values())
        deleted = await self._dep_dao.delete_stale_scanner_deps(
            session, project_id, keep_ids
        )

        # Update project timestamp
        await self._project_dao.update(
            session,
            project_id,
            last_scanned_at=datetime.now(timezone.utc),
        )

        return ScanResult(
            scanned=scanned,
            synced_count=len(upserted),
            deleted_count=deleted,
            unresolved=unresolved,
        )
