"""UpstreamVulnService — upstream vulnerability lifecycle."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.models.upstream_vuln import UpstreamVuln
from vulnsentinel.services import NotFoundError


class UpstreamVulnService:
    """Stateless service for upstream vulnerability analysis lifecycle."""

    def __init__(self, upstream_vuln_dao: UpstreamVulnDAO, client_vuln_dao: ClientVulnDAO) -> None:
        self._uv_dao = upstream_vuln_dao
        self._cv_dao = client_vuln_dao

    async def get(self, session: AsyncSession, vuln_id: uuid.UUID) -> dict:
        """Return upstream vuln detail with client impact list.

        Raises :class:`NotFoundError` if not found.
        """
        vuln = await self._uv_dao.get_by_id(session, vuln_id)
        if vuln is None:
            raise NotFoundError("upstream vulnerability not found")

        client_impact = await self._cv_dao.list_by_upstream_vuln(session, vuln.id)
        return {
            "vuln": vuln,
            "client_impact": client_impact,
        }

    async def list(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
        library_id: uuid.UUID | None = None,
    ) -> dict:
        """Return paginated upstream vuln list, optionally filtered by library."""
        page = await self._uv_dao.list_paginated(session, cursor, page_size, library_id=library_id)
        total = await self._uv_dao.count(session, library_id=library_id)
        return {
            "data": page.data,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
            "total": total,
        }

    async def count(self, session: AsyncSession, library_id: uuid.UUID | None = None) -> int:
        """Return upstream vuln count, optionally filtered by library."""
        return await self._uv_dao.count(session, library_id=library_id)

    async def create(
        self,
        session: AsyncSession,
        *,
        event_id: uuid.UUID,
        library_id: uuid.UUID,
        commit_sha: str,
    ) -> UpstreamVuln:
        """Create an upstream vuln record (status defaults to 'analyzing').

        Called by AnalyzerEngine when a bugfix event is detected.
        """
        return await self._uv_dao.create(
            session,
            event_id=event_id,
            library_id=library_id,
            commit_sha=commit_sha,
        )

    async def update_analysis(
        self,
        session: AsyncSession,
        vuln_id: uuid.UUID,
        *,
        vuln_type: str,
        severity: str,
        affected_versions: str,
        summary: str,
        reasoning: str,
        upstream_poc: dict[str, Any] | None = None,
    ) -> None:
        """Write LLM analysis results for an upstream vuln."""
        await self._uv_dao.update_analysis(
            session,
            vuln_id,
            vuln_type=vuln_type,
            severity=severity,
            affected_versions=affected_versions,
            summary=summary,
            reasoning=reasoning,
            upstream_poc=upstream_poc,
        )

    async def publish(self, session: AsyncSession, vuln_id: uuid.UUID) -> None:
        """Publish a vuln: status → 'published', published_at → now().

        Does NOT create client_vulns — ImpactEngine polls for published
        vulns and handles client impact creation (DB state decoupling).
        """
        await self._uv_dao.publish(session, vuln_id)

    async def list_published_without_impact(
        self, session: AsyncSession, limit: int = 20
    ) -> list[UpstreamVuln]:
        """Published vulns needing impact assessment (passthrough to DAO)."""
        return await self._uv_dao.list_published_without_impact(session, limit)

    async def set_error(
        self, session: AsyncSession, vuln_id: uuid.UUID, error_message: str
    ) -> None:
        """Record an analysis error (status unchanged, Engine decides retry)."""
        await self._uv_dao.set_error(session, vuln_id, error_message)
