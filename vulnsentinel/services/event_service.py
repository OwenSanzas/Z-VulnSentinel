"""EventService — event management and classification."""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.models.event import Event
from vulnsentinel.services import NotFoundError


class EventService:
    """Stateless service for event lifecycle and classification."""

    def __init__(self, event_dao: EventDAO, upstream_vuln_dao: UpstreamVulnDAO) -> None:
        self._event_dao = event_dao
        self._upstream_vuln_dao = upstream_vuln_dao

    async def get(self, session: AsyncSession, event_id: uuid.UUID) -> dict:
        """Return event detail with related upstream vulns (if bugfix).

        Raises :class:`NotFoundError` if not found.
        """
        event = await self._event_dao.get_by_id(session, event_id)
        if event is None:
            raise NotFoundError("event not found")

        related_vulns = []
        if event.is_bugfix:
            related_vulns = await self._upstream_vuln_dao.list_by_event(session, event.id)

        return {
            "event": event,
            "related_vulns": related_vulns,
        }

    async def list(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
        library_id: uuid.UUID | None = None,
    ) -> dict:
        """Return paginated event list, optionally filtered by library."""
        page = await self._event_dao.list_paginated(
            session, cursor, page_size, library_id=library_id
        )
        total = await self._event_dao.count(session, library_id=library_id)

        return {
            "data": page.data,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
            "total": total,
        }

    async def count(self, session: AsyncSession, library_id: uuid.UUID | None = None) -> int:
        """Return event count, optionally filtered by library."""
        return await self._event_dao.count(session, library_id=library_id)

    async def batch_create(self, session: AsyncSession, events: list[dict]) -> int:
        """Batch insert events (idempotent, ON CONFLICT DO NOTHING).

        Returns the number of rows actually inserted.
        """
        return await self._event_dao.batch_create(session, events)

    async def list_unclassified(self, session: AsyncSession, limit: int) -> list[Event]:
        """Return unclassified events for ClassifierEngine polling."""
        return await self._event_dao.list_unclassified(session, limit)

    async def list_bugfix_without_vuln(self, session: AsyncSession, limit: int) -> list[Event]:
        """Return bugfix events without upstream_vuln records for AnalyzerEngine."""
        return await self._event_dao.list_bugfix_without_vuln(session, limit)

    async def update_classification(
        self,
        session: AsyncSession,
        event_id: uuid.UUID,
        *,
        classification: str,
        confidence: float,
    ) -> None:
        """Write LLM classification result.

        Core business rule: ``is_bugfix`` is derived from ``classification``.
        Only ``security_bugfix`` sets ``is_bugfix=True``.
        """
        is_bugfix = classification == "security_bugfix"
        await self._event_dao.update_classification(
            session,
            event_id,
            classification=classification,
            confidence=confidence,
            is_bugfix=is_bugfix,
        )
