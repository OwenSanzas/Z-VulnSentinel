"""LibraryDAO — libraries table operations."""

import uuid
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.library import Library


class LibraryConflictError(ValueError):
    """Raised when upserting a library with a name that exists but different repo_url."""


class LibraryDAO(BaseDAO[Library]):
    model = Library

    # ── read ──────────────────────────────────────────────────────────────

    async def list_paginated(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> Page[Library]:
        """Paginated library list for the API."""
        query = select(Library)
        return await self.paginate(session, query, cursor, page_size)

    async def get_all_monitored(self, session: AsyncSession) -> list[Library]:
        """Return all libraries ordered by name (MonitorEngine full scan)."""
        stmt = select(Library).order_by(Library.name)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    # ── write ─────────────────────────────────────────────────────────────

    async def upsert_by_name(
        self,
        session: AsyncSession,
        *,
        name: str,
        repo_url: str,
        platform: str = "github",
        default_branch: str = "main",
    ) -> Library:
        """Insert a new library or do nothing if name already exists.

        Used during client onboarding to register libraries idempotently.
        Returns the library row (new or existing).
        """
        stmt = (
            insert(Library)
            .values(
                name=name,
                repo_url=repo_url,
                platform=platform,
                default_branch=default_branch,
            )
            .on_conflict_do_nothing(index_elements=["name"])
            .returning(Library)
        )
        result = await session.execute(stmt)
        row = result.scalars().first()
        if row is None:
            # Conflict — library already existed, fetch it
            existing = await self.get_by_field(session, name=name)
            if existing.repo_url != repo_url:
                raise LibraryConflictError(
                    f"Library '{name}' already exists with repo_url "
                    f"'{existing.repo_url}', cannot register with "
                    f"'{repo_url}'"
                )
            return existing
        return row

    async def update_pointers(
        self,
        session: AsyncSession,
        pk: uuid.UUID,
        *,
        latest_commit_sha: str | None = None,
        latest_tag_version: str | None = None,
        last_activity_at: datetime | None = None,
    ) -> None:
        """Update monitoring pointers using COALESCE to skip None values.

        MonitorEngine calls this after each polling cycle.
        """
        self._require_pk(pk)
        table = Library.__table__
        stmt = (
            update(Library)
            .where(table.c.id == pk)
            .values(
                latest_commit_sha=func.coalesce(latest_commit_sha, table.c.latest_commit_sha),
                latest_tag_version=func.coalesce(latest_tag_version, table.c.latest_tag_version),
                last_activity_at=func.coalesce(last_activity_at, table.c.last_activity_at),
            )
        )
        await session.execute(stmt)
