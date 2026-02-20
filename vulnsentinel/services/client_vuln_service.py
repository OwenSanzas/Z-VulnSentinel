"""ClientVulnService — client vulnerability pipeline and status management."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO, ClientVulnFilters
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.services import NotFoundError, ValidationError

# Vuln status valid transitions (maintainer feedback).
_VALID_TRANSITIONS: dict[str, list[str]] = {
    "recorded": ["reported"],
    "reported": ["confirmed"],
    "confirmed": ["fixed"],
}


class ClientVulnService:
    """Stateless service for client vulnerability pipeline and lifecycle."""

    def __init__(self, client_vuln_dao: ClientVulnDAO, upstream_vuln_dao: UpstreamVulnDAO) -> None:
        self._cv_dao = client_vuln_dao
        self._uv_dao = upstream_vuln_dao

    # ── API reads ──────────────────────────────────────────────────────────

    async def get(self, session: AsyncSession, vuln_id: uuid.UUID) -> dict:
        """Return client vuln detail with upstream vuln info.

        Raises :class:`NotFoundError` if not found.
        """
        cv = await self._cv_dao.get_by_id(session, vuln_id)
        if cv is None:
            raise NotFoundError("client vulnerability not found")

        upstream = await self._uv_dao.get_by_id(session, cv.upstream_vuln_id)
        return {
            "client_vuln": cv,
            "upstream_vuln": upstream,
        }

    async def list(
        self,
        session: AsyncSession,
        cursor: str | None = None,
        page_size: int = 20,
        filters: ClientVulnFilters | None = None,
    ) -> dict:
        """Return paginated client vuln list with stats summary."""
        page = await self._cv_dao.list_paginated(session, cursor, page_size, filters=filters)
        total = await self._cv_dao.count(session, filters=filters)
        project_id = filters.project_id if filters else None
        stats = await self._cv_dao.count_by_status(session, project_id=project_id)
        return {
            "data": page.data,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
            "total": total,
            "stats": stats,
        }

    async def list_by_project(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> dict:
        """Return paginated client vulns for a project."""
        page = await self._cv_dao.list_by_project(session, project_id, cursor, page_size)
        return {
            "data": page.data,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
        }

    async def get_stats(
        self, session: AsyncSession, project_id: uuid.UUID | None = None
    ) -> dict[str, int]:
        """Return forward-inclusive vuln status counts."""
        return await self._cv_dao.count_by_status(session, project_id=project_id)

    # ── ImpactEngine writes ───────────────────────────────────────────────

    async def create(
        self,
        session: AsyncSession,
        *,
        upstream_vuln_id: uuid.UUID,
        project_id: uuid.UUID,
        constraint_expr: str | None = None,
        constraint_source: str | None = None,
        resolved_version: str | None = None,
        fix_version: str | None = None,
        verdict: str | None = None,
    ) -> ClientVuln:
        """Create a client vuln record (pipeline defaults to 'pending').

        Called by ImpactEngine when an upstream vuln is published.
        """
        return await self._cv_dao.create(
            session,
            upstream_vuln_id=upstream_vuln_id,
            project_id=project_id,
            constraint_expr=constraint_expr,
            constraint_source=constraint_source,
            resolved_version=resolved_version,
            fix_version=fix_version,
            verdict=verdict,
        )

    async def list_pending_pipeline(self, session: AsyncSession, limit: int) -> list[ClientVuln]:
        """Return client vulns with pending pipeline work for ImpactEngine."""
        return await self._cv_dao.list_pending_pipeline(session, limit)

    async def update_pipeline(
        self,
        session: AsyncSession,
        vuln_id: uuid.UUID,
        *,
        pipeline_status: str,
        is_affected: bool | None = None,
        reachable_path: dict[str, Any] | None = None,
        poc_results: dict[str, Any] | None = None,
        error_message: str | None = None,
        clear_error: bool = False,
    ) -> None:
        """Advance pipeline status (ImpactEngine)."""
        await self._cv_dao.update_pipeline(
            session,
            vuln_id,
            pipeline_status=pipeline_status,
            is_affected=is_affected,
            reachable_path=reachable_path,
            poc_results=poc_results,
            error_message=error_message,
            clear_error=clear_error,
        )

    async def finalize(
        self,
        session: AsyncSession,
        vuln_id: uuid.UUID,
        *,
        is_affected: bool,
    ) -> None:
        """Finalize pipeline: set terminal status based on is_affected.

        - is_affected=True  → pipeline_status='verified', status='recorded'
        - is_affected=False → pipeline_status='not_affect', status='not_affect'
        """
        if is_affected:
            await self._cv_dao.finalize(
                session,
                vuln_id,
                pipeline_status="verified",
                status="recorded",
                is_affected=True,
            )
        else:
            await self._cv_dao.finalize(
                session,
                vuln_id,
                pipeline_status="not_affect",
                status="not_affect",
                is_affected=False,
            )

    # ── Maintainer feedback ───────────────────────────────────────────────

    async def update_status(
        self,
        session: AsyncSession,
        vuln_id: uuid.UUID,
        *,
        status: str,
        msg: str | None = None,
    ) -> None:
        """Update client vuln status from maintainer feedback.

        Validates state transition before writing. Only valid transitions:
        recorded → reported → confirmed → fixed.

        Raises :class:`NotFoundError` if not found.
        Raises :class:`ValidationError` on invalid transition.
        """
        cv = await self._cv_dao.get_by_id(session, vuln_id)
        if cv is None:
            raise NotFoundError("client vulnerability not found")

        allowed = _VALID_TRANSITIONS.get(cv.status)
        if allowed is None:
            raise ValidationError(f"cannot transition from terminal status '{cv.status}'")
        if status not in allowed:
            raise ValidationError(f"invalid transition: '{cv.status}' → '{status}'")

        await self._cv_dao.update_status(session, vuln_id, status=status, msg=msg)
