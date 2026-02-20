"""ProjectDependencyDAO — project_dependencies table operations."""

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.project_dependency import ProjectDependency


class ProjectDependencyDAO(BaseDAO[ProjectDependency]):
    model = ProjectDependency

    # ── read ──────────────────────────────────────────────────────────────

    async def list_by_project(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> Page[ProjectDependency]:
        """Paginated dependencies for a project (API — Dependencies tab)."""
        query = select(ProjectDependency).where(ProjectDependency.project_id == project_id)
        return await self.paginate(session, query, cursor, page_size)

    async def list_by_library(
        self,
        session: AsyncSession,
        library_id: uuid.UUID,
    ) -> list[ProjectDependency]:
        """All dependencies that reference a library (API — Used By).

        Data volume is small per library, so no pagination needed.
        """
        stmt = select(ProjectDependency).where(ProjectDependency.library_id == library_id)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def find_projects_by_library(
        self,
        session: AsyncSession,
        library_id: uuid.UUID,
    ) -> list[ProjectDependency]:
        """Find all project dependencies for a library (ImpactEngine).

        Returns lightweight rows with project_id, constraint_expr,
        resolved_version, and constraint_source.
        """
        stmt = select(ProjectDependency).where(ProjectDependency.library_id == library_id)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_project(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
    ) -> int:
        """Count dependencies for a project (API — deps_count)."""
        stmt = (
            select(func.count())
            .select_from(ProjectDependency)
            .where(ProjectDependency.project_id == project_id)
        )
        result = await session.execute(stmt)
        return result.scalar_one()

    # ── write ─────────────────────────────────────────────────────────────

    async def batch_create(
        self,
        session: AsyncSession,
        deps: list[dict[str, Any]],
    ) -> list[ProjectDependency]:
        """Batch upsert dependencies.

        ON CONFLICT (project_id, library_id, constraint_source) updates
        constraint_expr and resolved_version.

        Returns all upserted rows.
        """
        if not deps:
            return []

        ins = insert(ProjectDependency).values(deps)
        stmt = ins.on_conflict_do_update(
            constraint="uq_projdeps_project_library_source",
            set_={
                "constraint_expr": ins.excluded.constraint_expr,
                "resolved_version": ins.excluded.resolved_version,
            },
        ).returning(ProjectDependency)
        result = await session.execute(stmt)
        return list(result.scalars().all())
