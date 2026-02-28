"""EventDAO — events table operations."""

import uuid
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.event import Event
from vulnsentinel.models.project_dependency import ProjectDependency
from vulnsentinel.models.upstream_vuln import UpstreamVuln


class EventDAO(BaseDAO[Event]):
    model = Event

    # ── read ──────────────────────────────────────────────────────────────

    async def list_paginated(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
        library_id: uuid.UUID | None = None,
    ) -> Page[Event]:
        """Paginated event list, optionally filtered by library (API)."""
        query = select(Event)
        if library_id is not None:
            query = query.where(Event.library_id == library_id)
        return await self.paginate(session, query, cursor, page_size)

    async def count(
        self,
        session: AsyncSession,
        query=None,
        library_id: uuid.UUID | None = None,
    ) -> int:
        """Count events, optionally filtered by library."""
        if library_id is not None:
            q = select(Event).where(Event.library_id == library_id)
            return await super().count(session, q)
        return await super().count(session, query)

    async def list_unclassified(self, session: AsyncSession, limit: int) -> list[Event]:
        """Return unclassified events for ClassifierEngine polling.

        Only includes events whose library is used by at least one project,
        to avoid wasting LLM calls on libraries nobody depends on.
        """
        has_dep = (
            select(ProjectDependency.id)
            .where(ProjectDependency.library_id == Event.library_id)
            .exists()
        )
        stmt = (
            select(Event)
            .where(Event.classification.is_(None), has_dep)
            .order_by(Event.created_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def list_bugfix_without_vuln(self, session: AsyncSession, limit: int) -> list[Event]:
        """Return bugfix events without an upstream_vuln record (AnalyzerEngine).

        Only includes events whose library is used by at least one project.
        """
        has_dep = (
            select(ProjectDependency.id)
            .where(ProjectDependency.library_id == Event.library_id)
            .exists()
        )
        vuln_exists = select(UpstreamVuln.id).where(UpstreamVuln.event_id == Event.id).exists()
        stmt = (
            select(Event)
            .where(Event.is_bugfix.is_(True), ~vuln_exists, has_dep)
            .order_by(Event.created_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    # ── write ─────────────────────────────────────────────────────────────

    async def batch_create(self, session: AsyncSession, events: list[dict[str, Any]]) -> int:
        """Batch insert events, skipping duplicates (MonitorEngine).

        ON CONFLICT (library_id, type, ref) DO NOTHING.
        Returns the number of rows actually inserted.
        """
        if not events:
            return 0

        stmt = (
            insert(Event)
            .values(events)
            .on_conflict_do_nothing(
                constraint="uq_events_library_type_ref",
            )
        )
        result = await session.execute(stmt)
        return result.rowcount

    async def update_classification(
        self,
        session: AsyncSession,
        pk: uuid.UUID,
        *,
        classification: str,
        confidence: float,
        is_bugfix: bool,
    ) -> None:
        """Update classification result from ClassifierEngine."""
        self._require_pk(pk)
        stmt = (
            update(Event)
            .where(Event.id == pk)
            .values(
                classification=classification,
                confidence=confidence,
                is_bugfix=is_bugfix,
            )
        )
        await session.execute(stmt)
