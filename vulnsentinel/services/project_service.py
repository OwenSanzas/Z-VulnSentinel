"""ProjectService — project onboarding and management."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.models.library import Library
from vulnsentinel.models.project import Project
from vulnsentinel.models.project_dependency import ProjectDependency
from vulnsentinel.services import ConflictError, NotFoundError
from vulnsentinel.services.library_service import LibraryService


@dataclass
class DependencyInput:
    """Input for a single dependency during project creation."""

    library_name: str
    library_repo_url: str
    constraint_expr: str | None = None
    resolved_version: str | None = None
    constraint_source: str = "manifest"
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

        # v1: loop per project for counts; v2: batch subquery
        items = []
        for project in page.data:
            deps_count = await self._dep_dao.count_by_project(session, project.id)
            vuln_count = await self._client_vuln_dao.active_count_by_project(session, project.id)
            items.append(
                {
                    "project": project,
                    "deps_count": deps_count,
                    "vuln_count": vuln_count,
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

        # 2. Create project
        project = await self._project_dao.create(
            session,
            name=name,
            repo_url=repo_url,
            organization=organization,
            contact=contact,
            platform=platform,
            default_branch=default_branch,
            auto_sync_deps=auto_sync_deps,
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
                        "constraint_source": dep.constraint_source,
                    }
                )

            # 4. Batch upsert dependencies
            await self._dep_dao.batch_create(session, deps_rows)

        return project

    async def update(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        **fields: object,
    ) -> dict:
        """Update mutable project fields (name, organization, contact, auto_sync_deps)."""
        project = await self._ensure_project(session, project_id)
        # Filter out None values — only update explicitly provided fields
        updates = {k: v for k, v in fields.items() if v is not None}
        if not updates:
            return await self.get(session, project_id)
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
        page = await self._dep_dao.list_by_project(session, project_id, cursor, page_size)

        items = []
        for dep in page.data:
            lib = await session.get(Library, dep.library_id)
            items.append({"dep": dep, "library_name": lib.name if lib else ""})

        return {
            "data": items,
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
        rows = await self._dep_dao.batch_create(
            session,
            [
                {
                    "project_id": project_id,
                    "library_id": library.id,
                    "constraint_expr": dependency.constraint_expr,
                    "resolved_version": dependency.resolved_version,
                    "constraint_source": dependency.constraint_source,
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
