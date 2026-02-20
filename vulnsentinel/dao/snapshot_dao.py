"""SnapshotDAO — snapshots table operations."""

import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO, Page
from vulnsentinel.models.snapshot import Snapshot


class SnapshotDAO(BaseDAO[Snapshot]):
    model = Snapshot

    # ── read ──────────────────────────────────────────────────────────────

    async def list_by_project(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> Page[Snapshot]:
        """Paginated snapshots for a project (API — Snapshots tab)."""
        query = select(Snapshot).where(Snapshot.project_id == project_id)
        return await self.paginate(session, query, cursor, page_size)

    async def get_active_by_project(
        self, session: AsyncSession, project_id: uuid.UUID
    ) -> Snapshot | None:
        """Return the currently active snapshot for a project (ImpactEngine)."""
        stmt = select(Snapshot).where(
            Snapshot.project_id == project_id,
            Snapshot.is_active.is_(True),
        )
        result = await session.execute(stmt)
        return result.scalars().first()

    async def list_building(self, session: AsyncSession) -> list[Snapshot]:
        """Return all snapshots with status='building' (Engine polling)."""
        stmt = select(Snapshot).where(Snapshot.status == "building")
        result = await session.execute(stmt)
        return list(result.scalars().all())

    # ── write ─────────────────────────────────────────────────────────────

    async def update_status(
        self,
        session: AsyncSession,
        pk: uuid.UUID,
        *,
        status: str,
        error: str | None = None,
        node_count: int | None = None,
        edge_count: int | None = None,
        analysis_duration_sec: float | None = None,
        storage_path: str | None = None,
        fuzzer_names: list[str] | None = None,
        language: str | None = None,
        size_bytes: int | None = None,
    ) -> None:
        """Update snapshot build status and optional metadata (Engine).

        Only provided (non-None) fields are updated.
        """
        self._require_pk(pk)
        values: dict = {"status": status}
        if error is not None:
            values["error"] = error
        if node_count is not None:
            values["node_count"] = node_count
        if edge_count is not None:
            values["edge_count"] = edge_count
        if analysis_duration_sec is not None:
            values["analysis_duration_sec"] = analysis_duration_sec
        if storage_path is not None:
            values["storage_path"] = storage_path
        if fuzzer_names is not None:
            values["fuzzer_names"] = fuzzer_names
        if language is not None:
            values["language"] = language
        if size_bytes is not None:
            values["size_bytes"] = size_bytes

        stmt = update(Snapshot).where(Snapshot.id == pk).values(**values)
        await session.execute(stmt)

    async def activate(self, session: AsyncSession, pk: uuid.UUID) -> None:
        """Set a snapshot as the active one for its project.

        Deactivates any other active snapshot for the same project first.
        Both statements run within the caller's transaction.
        """
        self._require_pk(pk)
        snapshot = await session.get(Snapshot, pk)
        if snapshot is None:
            raise ValueError(f"Snapshot {pk} not found")

        # Deactivate current active snapshot for this project
        deactivate = (
            update(Snapshot)
            .where(
                Snapshot.project_id == snapshot.project_id,
                Snapshot.is_active.is_(True),
            )
            .values(is_active=False)
        )
        await session.execute(deactivate)

        # Activate the target snapshot
        activate_stmt = (
            update(Snapshot).where(Snapshot.id == pk).values(is_active=True, status="completed")
        )
        await session.execute(activate_stmt)
