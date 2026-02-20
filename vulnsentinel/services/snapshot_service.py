"""SnapshotService — snapshot lifecycle management."""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.snapshot_dao import SnapshotDAO
from vulnsentinel.models.snapshot import Snapshot
from vulnsentinel.services import NotFoundError


class SnapshotService:
    """Stateless service for snapshot CRUD and lifecycle."""

    def __init__(self, snapshot_dao: SnapshotDAO) -> None:
        self._snapshot_dao = snapshot_dao

    async def get(self, session: AsyncSession, snapshot_id: uuid.UUID) -> Snapshot:
        """Return snapshot by ID.

        Raises :class:`NotFoundError` if not found.
        """
        snapshot = await self._snapshot_dao.get_by_id(session, snapshot_id)
        if snapshot is None:
            raise NotFoundError("snapshot not found")
        return snapshot

    async def list_by_project(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        cursor: str | None = None,
        page_size: int = 20,
    ) -> dict:
        """Return paginated snapshots for a project."""
        page = await self._snapshot_dao.list_by_project(session, project_id, cursor, page_size)
        return {
            "data": page.data,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
        }

    async def create(
        self,
        session: AsyncSession,
        *,
        project_id: uuid.UUID,
        repo_url: str,
        repo_name: str,
        version: str,
        backend: str,
        trigger_type: str | None = None,
    ) -> Snapshot:
        """Create a new snapshot record (status defaults to 'building')."""
        return await self._snapshot_dao.create(
            session,
            project_id=project_id,
            repo_url=repo_url,
            repo_name=repo_name,
            version=version,
            backend=backend,
            trigger_type=trigger_type,
        )

    async def get_active(self, session: AsyncSession, project_id: uuid.UUID) -> Snapshot | None:
        """Return the active snapshot for a project, or None."""
        return await self._snapshot_dao.get_active_by_project(session, project_id)

    async def list_building(self, session: AsyncSession) -> list[Snapshot]:
        """Return all snapshots currently being built."""
        return await self._snapshot_dao.list_building(session)

    async def update_status(
        self,
        session: AsyncSession,
        snapshot_id: uuid.UUID,
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
        """Update snapshot build status and optional metadata."""
        await self._snapshot_dao.update_status(
            session,
            snapshot_id,
            status=status,
            error=error,
            node_count=node_count,
            edge_count=edge_count,
            analysis_duration_sec=analysis_duration_sec,
            storage_path=storage_path,
            fuzzer_names=fuzzer_names,
            language=language,
            size_bytes=size_bytes,
        )

    async def activate(self, session: AsyncSession, snapshot_id: uuid.UUID) -> None:
        """Set a snapshot as the active one for its project.

        Deactivates any previously active snapshot for the same project.
        Raises ``ValueError`` (from DAO) if snapshot does not exist.
        """
        await self._snapshot_dao.activate(session, snapshot_id)
