"""ClientVulnDAO — client_vulns table operations."""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.models.upstream_vuln import UpstreamVuln


@dataclass
class ClientVulnFilters:
    """Optional filters for client_vulns list queries."""

    status: str | None = None
    severity: str | None = None  # JOIN upstream_vulns
    library_id: uuid.UUID | None = None  # JOIN upstream_vulns
    project_id: uuid.UUID | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None


class ClientVulnDAO(BaseDAO[ClientVuln]):
    model = ClientVuln

    # ── private ────────────────────────────────────────────────────────────

    @staticmethod
    def _apply_filters(query: Select, filters: ClientVulnFilters) -> Select:
        """Apply ClientVulnFilters to a SELECT query.

        Joins upstream_vulns only when severity / library_id filtering is needed.
        """
        if filters.severity is not None or filters.library_id is not None:
            query = query.join(
                UpstreamVuln,
                UpstreamVuln.id == ClientVuln.upstream_vuln_id,
            )
        if filters.status is not None:
            query = query.where(ClientVuln.status == filters.status)
        if filters.severity is not None:
            query = query.where(UpstreamVuln.severity == filters.severity)
        if filters.library_id is not None:
            query = query.where(UpstreamVuln.library_id == filters.library_id)
        if filters.project_id is not None:
            query = query.where(ClientVuln.project_id == filters.project_id)
        if filters.date_from is not None:
            query = query.where(ClientVuln.created_at >= filters.date_from)
        if filters.date_to is not None:
            query = query.where(ClientVuln.created_at <= filters.date_to)
        return query

    # ── read ──────────────────────────────────────────────────────────────

    async def list_paginated(
        self,
        session: AsyncSession,
        cursor_str: str | None = None,
        page_size: int = 20,
        filters: ClientVulnFilters | None = None,
    ) -> Page[ClientVuln]:
        """Paginated client vuln list with optional multi-condition filters."""
        query = select(ClientVuln)
        if filters:
            query = self._apply_filters(query, filters)
        return await self.paginate(session, query, cursor_str, page_size)

    async def count(
        self,
        session: AsyncSession,
        query=None,
        filters: ClientVulnFilters | None = None,
    ) -> int:
        """Count client vulns with optional filters."""
        if filters:
            q = self._apply_filters(select(ClientVuln), filters)
            return await super().count(session, q)
        return await super().count(session, query)

    async def count_by_status(
        self,
        session: AsyncSession,
        project_id: uuid.UUID | None = None,
    ) -> dict[str, int]:
        """Count client vulns by status with forward-inclusive counting.

        Returns::
            {
                "total_recorded": ...,   # recorded + reported + confirmed + fixed
                "total_reported": ...,   # reported + confirmed + fixed
                "total_confirmed": ...,  # confirmed + fixed
                "total_fixed": ...,      # fixed only
            }
        """
        stmt = select(
            func.count()
            .filter(ClientVuln.status.in_(["recorded", "reported", "confirmed", "fixed"]))
            .label("total_recorded"),
            func.count()
            .filter(ClientVuln.status.in_(["reported", "confirmed", "fixed"]))
            .label("total_reported"),
            func.count()
            .filter(ClientVuln.status.in_(["confirmed", "fixed"]))
            .label("total_confirmed"),
            func.count().filter(ClientVuln.status == "fixed").label("total_fixed"),
        )
        if project_id is not None:
            stmt = stmt.where(ClientVuln.project_id == project_id)

        result = await session.execute(stmt)
        row = result.one()
        return {
            "total_recorded": row.total_recorded,
            "total_reported": row.total_reported,
            "total_confirmed": row.total_confirmed,
            "total_fixed": row.total_fixed,
        }

    async def list_by_upstream_vuln(
        self, session: AsyncSession, upstream_vuln_id: uuid.UUID
    ) -> list[ClientVuln]:
        """All client vulns for an upstream vuln (API — Client Impact)."""
        stmt = select(ClientVuln).where(ClientVuln.upstream_vuln_id == upstream_vuln_id)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def list_by_project(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        cursor_str: str | None = None,
        page_size: int = 20,
    ) -> Page[ClientVuln]:
        """Paginated vulns for a project (API — Vulnerabilities tab)."""
        query = select(ClientVuln).where(ClientVuln.project_id == project_id)
        return await self.paginate(session, query, cursor_str, page_size)

    async def active_count_by_project(self, session: AsyncSession, project_id: uuid.UUID) -> int:
        """Count active vulns for a project (excludes fixed / not_affect)."""
        stmt = (
            select(func.count())
            .select_from(ClientVuln)
            .where(
                ClientVuln.project_id == project_id,
                or_(
                    ClientVuln.status.notin_(["fixed", "not_affect"]),
                    ClientVuln.status.is_(None),
                ),
            )
        )
        result = await session.execute(stmt)
        return result.scalar_one()

    async def list_pending_pipeline(self, session: AsyncSession, limit: int) -> list[ClientVuln]:
        """Find vulns with pending pipeline work (ImpactEngine polling).

        Uses idx_clientvulns_pipeline partial index.
        """
        stmt = (
            select(ClientVuln)
            .where(ClientVuln.pipeline_status.in_(["pending", "path_searching", "poc_generating"]))
            .order_by(ClientVuln.created_at.asc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    # ── write ─────────────────────────────────────────────────────────────

    async def update_pipeline(
        self,
        session: AsyncSession,
        pk: uuid.UUID,
        *,
        pipeline_status: str,
        is_affected: bool | None = None,
        reachable_path: dict[str, Any] | None = None,
        poc_results: dict[str, Any] | None = None,
        error_message: str | None = None,
        clear_error: bool = False,
    ) -> None:
        """Advance pipeline status (ImpactEngine).

        Pass ``clear_error=True`` to reset error_message to NULL (e.g. on retry).
        """
        self._require_pk(pk)
        values: dict[str, Any] = {"pipeline_status": pipeline_status}
        if is_affected is not None:
            values["is_affected"] = is_affected
        if reachable_path is not None:
            values["reachable_path"] = reachable_path
        if poc_results is not None:
            values["poc_results"] = poc_results
        if error_message is not None:
            values["error_message"] = error_message
        elif clear_error:
            values["error_message"] = None

        stmt = update(ClientVuln).where(ClientVuln.id == pk).values(**values)
        await session.execute(stmt)

    async def finalize(
        self,
        session: AsyncSession,
        pk: uuid.UUID,
        *,
        pipeline_status: str,
        status: str,
        is_affected: bool,
    ) -> None:
        """Finalize pipeline: set terminal status and timestamps.

        Sets analysis_completed_at = now().
        Sets recorded_at or not_affect_at depending on status.
        """
        self._require_pk(pk)
        values: dict[str, Any] = {
            "pipeline_status": pipeline_status,
            "status": status,
            "is_affected": is_affected,
            "analysis_completed_at": func.now(),
            "recorded_at": func.now() if status == "recorded" else None,
            "not_affect_at": func.now() if status == "not_affect" else None,
        }
        stmt = update(ClientVuln).where(ClientVuln.id == pk).values(**values)
        await session.execute(stmt)

    async def update_status(
        self,
        session: AsyncSession,
        pk: uuid.UUID,
        *,
        status: str,
        msg: str | None = None,
    ) -> None:
        """Update client vuln status from maintainer feedback.

        Sets reported_at for 'reported',
        confirmed_at/confirmed_msg for 'confirmed',
        fixed_at/fixed_msg for 'fixed'.
        """
        self._require_pk(pk)
        values: dict[str, Any] = {"status": status}
        if status == "reported":
            values["reported_at"] = func.now()
        elif status == "confirmed":
            values["confirmed_at"] = func.now()
            if msg is not None:
                values["confirmed_msg"] = msg
        elif status == "fixed":
            values["fixed_at"] = func.now()
            if msg is not None:
                values["fixed_msg"] = msg

        stmt = update(ClientVuln).where(ClientVuln.id == pk).values(**values)
        await session.execute(stmt)
