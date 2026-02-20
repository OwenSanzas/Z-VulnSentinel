"""ProjectDependencyDAO — project_dependencies table operations."""

import uuid
from typing import Any

from sqlalchemy import case, delete, func, select
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

    async def batch_upsert(
        self,
        session: AsyncSession,
        deps: list[dict[str, Any]],
    ) -> list[ProjectDependency]:
        """Batch upsert dependencies.

        ON CONFLICT (project_id, library_id) updates constraint_expr,
        resolved_version, and constraint_source — but preserves
        constraint_source = 'manual' when it already exists.

        Returns all upserted rows.
        """
        if not deps:
            return []

        ins = insert(ProjectDependency).values(deps)
        stmt = ins.on_conflict_do_update(
            constraint="uq_projdeps_project_library",
            set_={
                "constraint_expr": ins.excluded.constraint_expr,
                "resolved_version": ins.excluded.resolved_version,
                "constraint_source": case(
                    (
                        ProjectDependency.__table__.c.constraint_source == "manual",
                        "manual",
                    ),
                    else_=ins.excluded.constraint_source,
                ),
            },
        ).returning(ProjectDependency)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def delete_stale_scanner_deps(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        keep_library_ids: set[uuid.UUID],
    ) -> int:
        """Delete non-manual dependencies not in *keep_library_ids*.

        Returns the number of deleted rows.
        """
        stmt = (
            delete(ProjectDependency)
            .where(ProjectDependency.project_id == project_id)
            .where(ProjectDependency.constraint_source != "manual")
        )
        if keep_library_ids:
            stmt = stmt.where(ProjectDependency.library_id.notin_(keep_library_ids))
        result = await session.execute(stmt)
        return result.rowcount
