"""LibraryService — library management and upsert deduplication."""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.library_dao import LibraryConflictError, LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.models.library import Library
from vulnsentinel.services import ConflictError, NotFoundError


class LibraryService:
    """Stateless service for library CRUD and idempotent registration."""

    def __init__(
        self,
        library_dao: LibraryDAO,
        project_dao: ProjectDAO,
        project_dependency_dao: ProjectDependencyDAO,
        event_dao: EventDAO,
    ) -> None:
        self._library_dao = library_dao
        self._project_dao = project_dao
        self._dep_dao = project_dependency_dao
        self._event_dao = event_dao

    async def get(self, session: AsyncSession, library_id: uuid.UUID) -> dict:
        """Return library detail with used_by list and event count.

        Raises :class:`NotFoundError` if the library does not exist.
        """
        library = await self._library_dao.get_by_id(session, library_id)
        if library is None:
            raise NotFoundError("library not found")

        deps = await self._dep_dao.list_by_library(session, library.id)
        events_tracked = await self._event_dao.count(session, library_id=library.id)

        # Enrich used_by with project names (v1: loop, v2: batch query)
        used_by = []
        for dep in deps:
            project = await self._project_dao.get_by_id(session, dep.project_id)
            used_by.append(
                {
                    "project_id": dep.project_id,
                    "project_name": project.name if project else None,
                    "constraint_expr": dep.constraint_expr,
                    "resolved_version": dep.resolved_version,
                    "constraint_source": dep.constraint_source,
                }
            )

        return {
            "library": library,
            "used_by": used_by,
            "events_tracked": events_tracked,
        }

    async def list(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> dict:
        """Return paginated library list with total count."""
        page = await self._library_dao.list_paginated(session, cursor, page_size)
        total = await self._library_dao.count(session)

        return {
            "data": page.data,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
            "total": total,
        }

    async def count(self, session: AsyncSession) -> int:
        """Return total number of libraries."""
        return await self._library_dao.count(session)

    async def upsert(
        self,
        session: AsyncSession,
        *,
        name: str,
        repo_url: str,
        platform: str = "github",
        default_branch: str = "main",
    ) -> Library:
        """Idempotent library registration.

        Used by ProjectService during client onboarding.

        Raises :class:`ConflictError` if a library with the same name
        but a different repo_url already exists (fork protection).
        """
        try:
            return await self._library_dao.upsert_by_name(
                session,
                name=name,
                repo_url=repo_url,
                platform=platform,
                default_branch=default_branch,
            )
        except LibraryConflictError as exc:
            raise ConflictError(str(exc)) from exc
