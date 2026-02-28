"""LibraryDAO — libraries table operations."""

import os
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.library import Library
from vulnsentinel.models.project_dependency import ProjectDependency

_SENTINEL = object()  # distinguish "not passed" from explicit None
_SORT_COLUMNS = {"name", "platform", "last_scanned_at", "collect_status", "created_at", "used_by_count"}


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

    async def list_due_for_collect(
        self, session: AsyncSession, interval_minutes: int | None = None,
    ) -> list[Library]:
        """Return GitHub libraries that haven't been collected recently.

        A library is due when last_scanned_at is NULL or older than *interval_minutes*.
        """
        if interval_minutes is None:
            interval_minutes = int(os.environ.get("VULNSENTINEL_COLLECT_CUTOFF_MINUTES", "10"))
        stmt = (
            select(Library)
            .where(
                Library.platform == "github",
                or_(
                    Library.last_scanned_at.is_(None),
                    Library.last_scanned_at
                    < datetime.now(timezone.utc) - timedelta(minutes=interval_minutes),
                ),
            )
            .order_by(Library.name)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def get_all_monitored(self, session: AsyncSession) -> list[Library]:
        """Return all libraries ordered by name (MonitorEngine full scan)."""
        stmt = select(Library).order_by(Library.name)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def batch_used_by_count(
        self,
        session: AsyncSession,
        library_ids: list[uuid.UUID],
    ) -> dict[uuid.UUID, int]:
        """Count how many projects depend on each library in one query."""
        if not library_ids:
            return {}
        stmt = (
            select(
                ProjectDependency.library_id,
                func.count().label("cnt"),
            )
            .where(ProjectDependency.library_id.in_(library_ids))
            .group_by(ProjectDependency.library_id)
        )
        result = await session.execute(stmt)
        return {row.library_id: row.cnt for row in result}

    async def list_offset(
        self,
        session: AsyncSession,
        *,
        page: int = 0,
        page_size: int = 20,
        sort_by: str = "name",
        sort_dir: str = "asc",
        status: str | None = None,
        ecosystem: str | None = None,
    ) -> tuple[list[Library], dict[uuid.UUID, int], int]:
        """Offset-paginated library list with cascading sort.

        Primary sort is user-selected; remaining columns from the priority
        chain (collect_status → used_by_count → name) are appended automatically.
        Returns (rows, used_by_counts, total_count).
        """
        if sort_by not in _SORT_COLUMNS:
            sort_by = "name"
        if sort_dir not in ("asc", "desc"):
            sort_dir = "asc"

        pd = ProjectDependency.__table__
        cnt_label = func.count(pd.c.project_id).label("used_by_count")

        # Always JOIN so used_by_count is available for cascading sort
        query = (
            select(Library, cnt_label)
            .outerjoin(pd, Library.id == pd.c.library_id)
            .group_by(Library.id)
        )
        if status:
            query = query.where(Library.collect_status == status)
        if ecosystem:
            query = query.where(Library.ecosystem == ecosystem)

        # Count query (before pagination)
        filters = []
        if status:
            filters.append(Library.collect_status == status)
        if ecosystem:
            filters.append(Library.ecosystem == ecosystem)

        if filters:
            count_query = select(func.count()).select_from(
                select(Library.id).where(*filters).subquery()
            )
        else:
            count_query = select(func.count()).select_from(select(Library.id).correlate(None))
        count_result = await session.execute(count_query)
        total = count_result.scalar_one()

        # Build cascading ORDER BY:
        # primary = user choice, then auto-append from priority chain
        _cascade_defaults = [
            ("collect_status", "asc"),
            ("used_by_count", "desc"),
            ("name", "asc"),
        ]

        def _resolve_col(col_name: str):
            if col_name == "used_by_count":
                return cnt_label
            return getattr(Library, col_name)

        def _directed(col, direction: str):
            if direction == "desc":
                return col.desc().nullslast()
            return col.asc().nullsfirst()

        # Primary sort
        order_clauses = [_directed(_resolve_col(sort_by), sort_dir)]
        # Cascade: append remaining priority columns
        for col_name, default_dir in _cascade_defaults:
            if col_name != sort_by:
                order_clauses.append(_directed(_resolve_col(col_name), default_dir))

        query = query.order_by(*order_clauses)
        query = query.offset(page * page_size).limit(page_size)
        result = await session.execute(query)

        rows_with_counts = list(result.all())
        libraries = [row[0] for row in rows_with_counts]
        used_by = {row[0].id: row[1] for row in rows_with_counts}

        return libraries, used_by, total

    async def health_summary(self, session: AsyncSession) -> dict:
        """Health summary: per-ecosystem healthy/unhealthy counts + alert totals."""
        pd = ProjectDependency.__table__

        # Per-ecosystem breakdown
        eco_stmt = (
            select(
                Library.ecosystem,
                Library.collect_status,
                func.count().label("cnt"),
            )
            .group_by(Library.ecosystem, Library.collect_status)
        )
        eco_result = await session.execute(eco_stmt)
        platforms: dict[str, dict[str, int]] = {}
        for row in eco_result:
            p = platforms.setdefault(row.ecosystem, {"healthy": 0, "unhealthy": 0})
            p[row.collect_status] = row.cnt

        # Unhealthy with/without clients (for alert banners)
        # Subquery: per-library dep count, filtered to unhealthy only
        dep_count = (
            select(
                Library.id.label("lib_id"),
                func.count(pd.c.project_id).label("dep_cnt"),
            )
            .outerjoin(pd, Library.id == pd.c.library_id)
            .where(Library.collect_status == "unhealthy")
            .group_by(Library.id)
        ).subquery()

        has_clients = (dep_count.c.dep_cnt > 0).label("has_clients")
        alert_stmt = (
            select(has_clients, func.count().label("cnt"))
            .select_from(dep_count)
            .group_by(has_clients)
        )
        alert_result = await session.execute(alert_stmt)
        unhealthy_with_clients = 0
        unhealthy_no_clients = 0
        for row in alert_result:
            if row.has_clients:
                unhealthy_with_clients = row.cnt
            else:
                unhealthy_no_clients = row.cnt

        return {
            "platforms": platforms,
            "unhealthy_with_clients": unhealthy_with_clients,
            "unhealthy_no_clients": unhealthy_no_clients,
        }

    # ── write ─────────────────────────────────────────────────────────────

    async def upsert_by_name(
        self,
        session: AsyncSession,
        *,
        name: str,
        repo_url: str,
        platform: str = "github",
        default_branch: str = "main",
        ecosystem: str = "c_cpp",
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
                ecosystem=ecosystem,
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
        last_scanned_at: datetime | None = None,
        collect_status: str | None = None,
        collect_error: str | None = _SENTINEL,
        collect_detail: dict | None = _SENTINEL,
    ) -> None:
        """Update monitoring pointers using COALESCE to skip None values.

        MonitorEngine calls this after each polling cycle.
        ``collect_status`` and ``collect_error`` are set directly when provided.
        Pass ``collect_error=None`` explicitly to clear the error.
        """
        self._require_pk(pk)
        table = Library.__table__
        values: dict = {
            "latest_commit_sha": func.coalesce(latest_commit_sha, table.c.latest_commit_sha),
            "latest_tag_version": func.coalesce(latest_tag_version, table.c.latest_tag_version),
            "last_scanned_at": func.coalesce(last_scanned_at, table.c.last_scanned_at),
        }
        if collect_status is not None:
            values["collect_status"] = collect_status
        if collect_error is not _SENTINEL:
            values["collect_error"] = collect_error
        if collect_detail is not _SENTINEL:
            values["collect_detail"] = collect_detail
        stmt = update(Library).where(table.c.id == pk).values(**values)
        await session.execute(stmt)
