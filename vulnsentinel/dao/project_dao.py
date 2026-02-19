"""ProjectDAO — projects table operations."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.project import Project


class ProjectDAO(BaseDAO[Project]):
    model = Project

    async def list_paginated(
        self,
        session: AsyncSession,
        cursor_str: str | None = None,
        page_size: int = 20,
    ) -> Page[Project]:
        """Paginated project list for the API."""
        query = select(Project)
        return await self.paginate(session, query, cursor_str, page_size)
