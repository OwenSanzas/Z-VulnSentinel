"""ProjectService — project onboarding and management."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.core.github import verify_git_ref
from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.models.library import Library
from vulnsentinel.models.project import Project
from vulnsentinel.models.project_dependency import ProjectDependency
from vulnsentinel.services import ConflictError, NotFoundError, ValidationError
from vulnsentinel.services.library_service import LibraryService


@dataclass
class DependencyInput:
    """Input for a single dependency during project creation."""

    library_name: str
    library_repo_url: str
    constraint_expr: str | None = None
    resolved_version: str | None = None
    platform: str = "github"
    default_branch: str = "main"


class ProjectService:
    """Stateless service for project CRUD and client onboarding."""

    def __init__(
        self,
        project_dao: ProjectDAO,
        project_dependency_dao: ProjectDependencyDAO,
        client_vuln_dao: ClientVulnDAO,
        library_service: LibraryService,
    ) -> None:
        self._project_dao = project_dao
        self._dep_dao = project_dependency_dao
        self._client_vuln_dao = client_vuln_dao
        self._library_service = library_service

    async def get(self, session: AsyncSession, project_id: uuid.UUID) -> dict:
        """Return project detail with deps_count and vuln_count.

        Raises :class:`NotFoundError` if the project does not exist.
        """
        project = await self._project_dao.get_by_id(session, project_id)
        if project is None:
            raise NotFoundError("project not found")

        deps_count = await self._dep_dao.count_by_project(session, project.id)
        vuln_count = await self._client_vuln_dao.active_count_by_project(session, project.id)

        return {
            "project": project,
            "deps_count": deps_count,
            "vuln_count": vuln_count,
        }

    async def list(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> dict:
        """Return paginated project list with deps_count and vuln_count per project."""
        page = await self._project_dao.list_paginated(session, cursor, page_size)
        total = await self._project_dao.count(session)

        # Batch: 2 aggregate queries instead of 2*N individual queries
        project_ids = [p.id for p in page.data]
        counts = await self._project_dao.batch_counts(session, project_ids)

        items = []
        for project in page.data:
            c = counts.get(project.id, {"deps_count": 0, "vuln_count": 0})
            items.append(
                {
                    "project": project,
                    "deps_count": c["deps_count"],
                    "vuln_count": c["vuln_count"],
                }
            )

        return {
            "data": items,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
            "total": total,
        }

    async def count(self, session: AsyncSession) -> int:
        """Return total number of projects."""
        return await self._project_dao.count(session)

    async def create(
        self,
        session: AsyncSession,
        *,
        name: str,
        repo_url: str,
        organization: str | None = None,
        contact: str | None = None,
        platform: str = "github",
        default_branch: str = "main",
        auto_sync_deps: bool = True,
        pinned_ref: str | None = None,
        dependencies: list[DependencyInput] | None = None,
    ) -> Project:
        """Create a project and register its dependencies (single transaction).

        For each dependency, the corresponding library is upserted via
        LibraryService (idempotent). Dependencies are batch-upserted via
        ON CONFLICT DO UPDATE (idempotent).
        """
        # 1. Check uniqueness
        existing = await self._project_dao.get_by_field(session, repo_url=repo_url)
        if existing is not None:
            raise ConflictError(f"project with repo_url '{repo_url}' already exists")

        # 2. Validate pinned_ref against GitHub
        if pinned_ref is not None:
            await self._validate_ref(repo_url, pinned_ref)

        # 3. Create project
        project = await self._project_dao.create(
            session,
            name=name,
            repo_url=repo_url,
            organization=organization,
            contact=contact,
            platform=platform,
            default_branch=default_branch,
            auto_sync_deps=auto_sync_deps,
            pinned_ref=pinned_ref,
        )

        # 3. Register dependencies
        if dependencies:
            deps_rows = []
            for dep in dependencies:
                library = await self._library_service.upsert(
                    session,
                    name=dep.library_name,
                    repo_url=dep.library_repo_url,
                    platform=dep.platform,
                    default_branch=dep.default_branch,
                )
                deps_rows.append(
                    {
                        "project_id": project.id,
                        "library_id": library.id,
                        "constraint_expr": dep.constraint_expr,
                        "resolved_version": dep.resolved_version,
                        "constraint_source": "manual",
                    }
                )

            # 4. Batch upsert dependencies
            await self._dep_dao.batch_upsert(session, deps_rows)

        return project

    async def update(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        *,
        fields_set: set[str],
        **fields: object,
    ) -> dict:
        """Update mutable project fields.

        *fields_set* contains the field names the user explicitly provided
        (from Pydantic's ``model_fields_set``).  This distinguishes
        "user sent null" (clear the value) from "user didn't send this field"
        (leave unchanged).
        """
        project = await self._ensure_project(session, project_id)

        # Only include fields the user explicitly sent
        updates = {k: v for k, v in fields.items() if k in fields_set}
        # For non-nullable fields, still skip None (user can't null-out name)
        updates = {
            k: v
            for k, v in updates.items()
            if v is not None or k in ("pinned_ref", "contact", "organization")
        }
        if not updates:
            return await self.get(session, project_id)

        # Validate pinned_ref against GitHub if being set (not cleared)
        if "pinned_ref" in updates and updates["pinned_ref"] is not None:
            await self._validate_ref(project.repo_url, str(updates["pinned_ref"]))

        updated = await self._project_dao.update(session, project.id, **updates)
        deps_count = await self._dep_dao.count_by_project(session, project_id)
        vuln_count = await self._client_vuln_dao.active_count_by_project(session, project_id)
        return {
            "project": updated,
            "deps_count": deps_count,
            "vuln_count": vuln_count,
        }

    # ── dependency management ─────────────────────────────────────────

    async def list_dependencies(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> dict:
        """Return paginated dependencies for a project, enriched with library_name."""
        await self._ensure_project(session, project_id)
        page = await self._dep_dao.list_by_project_with_library(
            session, project_id, cursor, page_size,
        )

        return {
            "data": page.data,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
        }

    async def add_dependency(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        dependency: DependencyInput,
    ) -> dict:
        """Add a single dependency (upsert library + create dep row)."""
        await self._ensure_project(session, project_id)

        library = await self._library_service.upsert(
            session,
            name=dependency.library_name,
            repo_url=dependency.library_repo_url,
            platform=dependency.platform,
            default_branch=dependency.default_branch,
        )
        rows = await self._dep_dao.batch_upsert(
            session,
            [
                {
                    "project_id": project_id,
                    "library_id": library.id,
                    "constraint_expr": dependency.constraint_expr,
                    "resolved_version": dependency.resolved_version,
                    "constraint_source": "manual",
                }
            ],
        )
        return {"dep": rows[0], "library_name": library.name}

    async def remove_dependency(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        dep_id: uuid.UUID,
    ) -> None:
        """Delete a dependency (must belong to the project)."""
        dep = await self._get_dep_for_project(session, project_id, dep_id)
        await self._dep_dao.delete(session, dep.id)

    async def update_dependency_notify(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        dep_id: uuid.UUID,
        notify_enabled: bool,
    ) -> dict:
        """Toggle notify_enabled for a dependency."""
        dep = await self._get_dep_for_project(session, project_id, dep_id)
        updated = await self._dep_dao.update(session, dep.id, notify_enabled=notify_enabled)
        lib = await session.get(Library, updated.library_id)  # type: ignore[union-attr]
        return {"dep": updated, "library_name": lib.name if lib else ""}

    # ── private helpers ───────────────────────────────────────────────

    @staticmethod
    async def _validate_ref(repo_url: str, ref: str) -> None:
        """Validate that a git ref exists in the remote repo."""
        if not await verify_git_ref(repo_url, ref):
            raise ValidationError(f"ref '{ref}' not found in {repo_url}")

    async def _ensure_project(self, session: AsyncSession, project_id: uuid.UUID) -> Project:
        project = await self._project_dao.get_by_id(session, project_id)
        if project is None:
            raise NotFoundError("project not found")
        return project

    async def _get_dep_for_project(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        dep_id: uuid.UUID,
    ) -> ProjectDependency:
        await self._ensure_project(session, project_id)
        dep = await self._dep_dao.get_by_id(session, dep_id)
        if dep is None or dep.project_id != project_id:
            raise NotFoundError("dependency not found")
        return dep

    # ── engine support ─────────────────────────────────────────────

    async def list_due_for_scan(self, session: AsyncSession) -> list[Project]:
        """Return projects due for a dependency scan."""
        return await self._project_dao.list_due_for_scan(session)

    async def get_project(self, session: AsyncSession, project_id: uuid.UUID) -> Project | None:
        """Return raw Project model or None (no enrichment)."""
        return await self._project_dao.get_by_id(session, project_id)

    async def update_scan_timestamp(
        self, session: AsyncSession, project_id: uuid.UUID, last_scanned_at: datetime
    ) -> None:
        """Update last_scanned_at after a dependency scan."""
        await self._project_dao.update(session, project_id, last_scanned_at=last_scanned_at)

    async def update_scan_status(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        *,
        status: str,
        error: str | None,
        detail: dict | None = None,
    ) -> None:
        """Update scan_status, scan_error, and scan_detail."""
        kwargs: dict = {"scan_status": status, "scan_error": error}
        if detail is not None:
            kwargs["scan_detail"] = detail
        await self._project_dao.update(session, project_id, **kwargs)

    async def sync_dependencies(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        rows: list[dict],
        keep_library_ids: set[uuid.UUID],
    ) -> tuple[int, int]:
        """Batch upsert dependencies and delete stale ones.

        Returns (upserted_count, deleted_count).
        """
        upserted = await self._dep_dao.batch_upsert(session, rows)
        deleted = await self._dep_dao.delete_stale_scanner_deps(
            session, project_id, keep_library_ids
        )
        return len(upserted), deleted
