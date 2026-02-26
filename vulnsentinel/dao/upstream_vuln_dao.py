"""UpstreamVulnDAO — upstream_vulns table operations."""

import uuid
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.models.project_dependency import ProjectDependency
from vulnsentinel.models.upstream_vuln import UpstreamVuln


class UpstreamVulnDAO(BaseDAO[UpstreamVuln]):
    model = UpstreamVuln

    # ── read ──────────────────────────────────────────────────────────────

    async def list_paginated(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
        library_id: uuid.UUID | None = None,
    ) -> Page[UpstreamVuln]:
        """Paginated vuln list, optionally filtered by library (API)."""
        query = select(UpstreamVuln)
        if library_id is not None:
            query = query.where(UpstreamVuln.library_id == library_id)
        return await self.paginate(session, query, cursor, page_size)

    async def count(
        self,
        session: AsyncSession,
        query=None,
        library_id: uuid.UUID | None = None,
    ) -> int:
        """Count vulns, optionally filtered by library."""
        if library_id is not None:
            q = select(UpstreamVuln).where(UpstreamVuln.library_id == library_id)
            return await super().count(session, q)
        return await super().count(session, query)

    async def list_by_event(self, session: AsyncSession, event_id: uuid.UUID) -> list[UpstreamVuln]:
        """Return all vulns linked to an event (API — event detail page)."""
        stmt = select(UpstreamVuln).where(UpstreamVuln.event_id == event_id)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def list_published_without_impact(
        self,
        session: AsyncSession,
        limit: int = 20,
    ) -> list[UpstreamVuln]:
        """Published vulns that have no client_vulns yet and whose library has dependents.

        Used by ImpactEngine to find vulns needing impact assessment.
        """
        stmt = (
            select(UpstreamVuln)
            .where(
                UpstreamVuln.status == "published",
                ~select(ClientVuln.id)
                .where(ClientVuln.upstream_vuln_id == UpstreamVuln.id)
                .correlate(UpstreamVuln)
                .exists(),
                select(ProjectDependency.id)
                .where(ProjectDependency.library_id == UpstreamVuln.library_id)
                .correlate(UpstreamVuln)
                .exists(),
            )
            .order_by(UpstreamVuln.published_at.asc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    # ── write ─────────────────────────────────────────────────────────────

    async def update_analysis(
        self,
        session: AsyncSession,
        pk: uuid.UUID,
        *,
        vuln_type: str,
        severity: str,
        affected_versions: str,
        summary: str,
        reasoning: str,
        upstream_poc: dict[str, Any] | None = None,
        affected_functions: list[str] | None = None,
    ) -> None:
        """Write analysis results from AnalyzerEngine."""
        self._require_pk(pk)
        values: dict[str, Any] = {
            "vuln_type": vuln_type,
            "severity": severity,
            "affected_versions": affected_versions,
            "summary": summary,
            "reasoning": reasoning,
        }
        if upstream_poc is not None:
            values["upstream_poc"] = upstream_poc
        if affected_functions is not None:
            values["affected_functions"] = affected_functions

        stmt = update(UpstreamVuln).where(UpstreamVuln.id == pk).values(**values)
        await session.execute(stmt)

    async def publish(self, session: AsyncSession, pk: uuid.UUID) -> None:
        """Publish a vuln: status → 'published', published_at → now()."""
        self._require_pk(pk)
        stmt = (
            update(UpstreamVuln)
            .where(UpstreamVuln.id == pk)
            .values(status="published", published_at=func.now())
        )
        await session.execute(stmt)

    async def set_error(self, session: AsyncSession, pk: uuid.UUID, error_message: str) -> None:
        """Record an analysis error."""
        self._require_pk(pk)
        stmt = update(UpstreamVuln).where(UpstreamVuln.id == pk).values(error_message=error_message)
        await session.execute(stmt)
