"""ProjectDAO — projects table operations."""

import os
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.models.project import Project
from vulnsentinel.models.project_dependency import ProjectDependency


class ProjectDAO(BaseDAO[Project]):
    model = Project

    async def list_paginated(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> Page[Project]:
        """Paginated project list for the API."""
        query = select(Project)
        return await self.paginate(session, query, cursor, page_size)

    async def batch_counts(
        self,
        session: AsyncSession,
        project_ids: list[uuid.UUID],
    ) -> dict[uuid.UUID, dict[str, int]]:
        """Return deps_count and vuln_count for multiple projects in 2 queries."""
        if not project_ids:
            return {}

        # deps_count per project
        deps_stmt = (
            select(
                ProjectDependency.project_id,
                func.count().label("cnt"),
            )
            .where(ProjectDependency.project_id.in_(project_ids))
            .group_by(ProjectDependency.project_id)
        )
        deps_result = await session.execute(deps_stmt)
        deps_map = {row.project_id: row.cnt for row in deps_result}

        # active vuln_count per project (excludes fixed / not_affect)
        vuln_stmt = (
            select(
                ClientVuln.project_id,
                func.count().label("cnt"),
            )
            .where(
                ClientVuln.project_id.in_(project_ids),
                or_(
                    ClientVuln.status.notin_(["fixed", "not_affect"]),
                    ClientVuln.status.is_(None),
                ),
            )
            .group_by(ClientVuln.project_id)
        )
        vuln_result = await session.execute(vuln_stmt)
        vuln_map = {row.project_id: row.cnt for row in vuln_result}

        return {
            pid: {
                "deps_count": deps_map.get(pid, 0),
                "vuln_count": vuln_map.get(pid, 0),
            }
            for pid in project_ids
        }

    async def list_due_for_scan(self, session: AsyncSession) -> list[Project]:
        """Return projects that are due for a dependency scan.

        Criteria:
        - auto_sync_deps is true
        - pinned_ref is NULL (not pinned to a specific ref)
        - last_scanned_at is NULL or older than VULNSENTINEL_SCAN_CUTOFF_MINUTES
        """
        cutoff_minutes = int(os.environ.get("VULNSENTINEL_SCAN_CUTOFF_MINUTES", "60"))
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=cutoff_minutes)
        stmt = (
            select(Project)
            .where(Project.auto_sync_deps.is_(True))
            .where(Project.pinned_ref.is_(None))
            .where((Project.last_scanned_at.is_(None)) | (Project.last_scanned_at < cutoff))
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
