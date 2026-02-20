"""ProjectDAO — projects table operations."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.project import Project


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

    async def list_due_for_scan(self, session: AsyncSession) -> list[Project]:
        """Return projects that are due for a dependency scan.

        Criteria:
        - auto_sync_deps is true
        - pinned_ref is NULL (not pinned to a specific ref)
        - last_scanned_at is NULL or older than 1 hour
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        stmt = (
            select(Project)
            .where(Project.auto_sync_deps.is_(True))
            .where(Project.pinned_ref.is_(None))
            .where(
                (Project.last_scanned_at.is_(None)) | (Project.last_scanned_at < cutoff)
            )
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
