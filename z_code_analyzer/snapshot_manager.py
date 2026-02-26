"""Snapshot lifecycle management — PostgreSQL + concurrency control + eviction."""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from z_code_analyzer.models.snapshot import Snapshot

logger = logging.getLogger(__name__)

# Defaults
MAX_VERSIONS_PER_REPO = 5
SNAPSHOT_TTL_DAYS = 90
BUILDING_TIMEOUT_MINUTES = 30
WAIT_POLL_INTERVAL = 5  # seconds
WAIT_TIMEOUT = 1800  # 30 minutes
DISK_THRESHOLD = 0.80  # Start evicting when disk usage exceeds 80%
DISK_TARGET = 0.70  # Evict until usage drops below 70%


class SnapshotManager:
    """
    Snapshot lifecycle management.
    PostgreSQL stores directory/metadata, Neo4j stores the actual graph.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        graph_store: Any = None,
        log_store: Any = None,
    ) -> None:
        self._session_factory = session_factory
        self._graph_store = graph_store
        self._log_store = log_store

    def close(self) -> None:
        engine = self._session_factory.kw.get("bind")
        if engine is not None:
            engine.dispose()

    def list_snapshots(
        self, repo_url: str | None = None, status: str = "completed"
    ) -> list[Snapshot]:
        """List snapshots, optionally filtered by repo_url."""
        with self._session_factory() as session:
            stmt = select(Snapshot).where(Snapshot.status == status)
            if repo_url:
                stmt = stmt.where(Snapshot.repo_url == repo_url)
            stmt = stmt.order_by(Snapshot.last_accessed_at.desc())
            return list(session.scalars(stmt).all())

    def find_snapshot(
        self,
        repo_url: str,
        version: str,
        preferred_backend: str | None = None,
    ) -> Snapshot | None:
        """Find a reusable snapshot.

        Note: on_snapshot_accessed() opens its own session, so it's safe
        to call within this session's ``with`` block.
        """
        with self._session_factory() as session:
            # Exact match first
            if preferred_backend:
                snap = session.scalars(
                    select(Snapshot).where(
                        Snapshot.repo_url == repo_url,
                        Snapshot.version == version,
                        Snapshot.backend == preferred_backend,
                        Snapshot.status == "completed",
                    )
                ).first()
                if snap:
                    self.on_snapshot_accessed(snap.id)
                    return snap

            # Any backend for same version, prefer higher precision
            for backend in ["svf", "joern", "introspector", "prebuild"]:
                snap = session.scalars(
                    select(Snapshot).where(
                        Snapshot.repo_url == repo_url,
                        Snapshot.version == version,
                        Snapshot.backend == backend,
                        Snapshot.status == "completed",
                    )
                ).first()
                if snap:
                    self.on_snapshot_accessed(snap.id)
                    return snap

        return None

    async def acquire_or_wait(
        self,
        repo_url: str,
        version: str,
        backend: str,
    ) -> Snapshot | None:
        """
        Acquire a snapshot slot or wait for an in-progress one.

        Returns:
            Snapshot with status="completed" if cache hit.
            Snapshot with status="building" if we got the lock (caller should analyze).
            None if a previous attempt failed and we should retry.
        """
        with self._session_factory() as session:
            snap = session.scalars(
                select(Snapshot).where(
                    Snapshot.repo_url == repo_url,
                    Snapshot.version == version,
                    Snapshot.backend == backend,
                )
            ).first()

            if snap:
                if snap.status == "completed":
                    self.on_snapshot_accessed(snap.id)
                    return snap

                if snap.status == "building":
                    created = snap.created_at or datetime.now(timezone.utc)
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    age = datetime.now(timezone.utc) - created

                    if age > timedelta(minutes=BUILDING_TIMEOUT_MINUTES):
                        session.execute(
                            update(Snapshot)
                            .where(Snapshot.id == snap.id)
                            .values(
                                status="failed",
                                error="timeout: analyzer process died",
                            )
                        )
                        session.commit()
                        snap.status = "failed"
                    else:
                        return await self._wait_for_ready(repo_url, version, backend)

                if snap.status == "failed":
                    session.execute(delete(Snapshot).where(Snapshot.id == snap.id))
                    session.commit()

        # Create placeholder
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1] if "/" in repo_url else repo_url
        now = datetime.now(timezone.utc)
        new_snap = Snapshot(
            id=uuid.uuid4(),
            repo_url=repo_url,
            repo_name=repo_name,
            version=version,
            backend=backend,
            status="building",
            created_at=now,
            last_accessed_at=now,
            access_count=0,
            node_count=0,
            edge_count=0,
            fuzzer_names=[],
        )
        try:
            with self._session_factory() as session:
                session.add(new_snap)
                session.commit()
                # Refresh to load all attributes, then expunge
                session.refresh(new_snap)
                session.expunge(new_snap)
                return new_snap
        except IntegrityError:
            return await self._wait_for_ready(repo_url, version, backend)

    async def _wait_for_ready(
        self,
        repo_url: str,
        version: str,
        backend: str,
        timeout: int = WAIT_TIMEOUT,
    ) -> Snapshot | None:
        """Poll until snapshot is ready."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._session_factory() as session:
                snap = session.scalars(
                    select(Snapshot).where(
                        Snapshot.repo_url == repo_url,
                        Snapshot.version == version,
                        Snapshot.backend == backend,
                    )
                ).first()
                if snap and snap.status == "completed":
                    self.on_snapshot_accessed(snap.id)
                    return snap
                if not snap or snap.status == "failed":
                    return None
            await asyncio.sleep(WAIT_POLL_INTERVAL)
        raise TimeoutError("Waiting for snapshot analysis timed out")

    def mark_completed(
        self,
        snapshot_id: str | uuid.UUID,
        node_count: int,
        edge_count: int,
        fuzzer_names: list[str],
        analysis_duration_sec: float = 0.0,
        language: str = "",
        size_bytes: int = 0,
    ) -> None:
        sid = uuid.UUID(str(snapshot_id))

        # Estimate size if not provided (~1200 bytes/node + ~150 bytes/edge)
        if size_bytes <= 0:
            size_bytes = node_count * 1200 + edge_count * 150

        with self._session_factory() as session:
            session.execute(
                update(Snapshot)
                .where(Snapshot.id == sid)
                .values(
                    status="completed",
                    node_count=node_count,
                    edge_count=edge_count,
                    fuzzer_names=fuzzer_names,
                    analysis_duration_sec=analysis_duration_sec,
                    language=language,
                    size_bytes=size_bytes,
                    last_accessed_at=datetime.now(timezone.utc),
                )
            )
            session.commit()

    def mark_failed(self, snapshot_id: str | uuid.UUID, error: str) -> None:
        sid = uuid.UUID(str(snapshot_id))
        with self._session_factory() as session:
            session.execute(
                update(Snapshot).where(Snapshot.id == sid).values(status="failed", error=error)
            )
            session.commit()

    def on_snapshot_accessed(self, snapshot_id: str | uuid.UUID) -> None:
        sid = uuid.UUID(str(snapshot_id))
        with self._session_factory() as session:
            session.execute(
                update(Snapshot)
                .where(Snapshot.id == sid)
                .values(
                    last_accessed_at=datetime.now(timezone.utc),
                    access_count=Snapshot.access_count + 1,
                )
            )
            session.commit()

    # ── Eviction ──

    def evict_by_version_limit(self, repo_url: str) -> int:
        """Evict oldest snapshots if a repo exceeds MAX_VERSIONS_PER_REPO."""
        with self._session_factory() as session:
            snapshots = list(
                session.scalars(
                    select(Snapshot)
                    .where(Snapshot.repo_url == repo_url, Snapshot.status == "completed")
                    .order_by(Snapshot.last_accessed_at.desc())
                ).all()
            )
            to_delete = snapshots[MAX_VERSIONS_PER_REPO:]
            for snap in to_delete:
                self._delete_snapshot(snap)
            return len(to_delete)

    def evict_by_ttl(self) -> int:
        """Evict snapshots not accessed within TTL."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=SNAPSHOT_TTL_DAYS)
        with self._session_factory() as session:
            expired = list(
                session.scalars(
                    select(Snapshot).where(
                        Snapshot.status == "completed",
                        Snapshot.last_accessed_at < cutoff,
                    )
                ).all()
            )
            for snap in expired:
                self._delete_snapshot(snap)
            return len(expired)

    def evict_by_disk_pressure(self, data_dir: str = "/var/lib/neo4j/data") -> int:
        """Evict LRU snapshots when disk usage exceeds DISK_THRESHOLD.

        Keeps evicting until usage drops below DISK_TARGET or no snapshots remain.
        Stops early if Neo4j deletion fails (disk space won't be freed).
        """
        evicted = 0
        while True:
            try:
                usage = shutil.disk_usage(data_dir)
                ratio = usage.used / usage.total
            except OSError:
                logger.warning(
                    "Cannot check disk usage for %s, skipping pressure eviction", data_dir
                )
                break

            if ratio <= DISK_THRESHOLD:
                break

            with self._session_factory() as session:
                oldest = session.scalars(
                    select(Snapshot)
                    .where(Snapshot.status == "completed")
                    .order_by(Snapshot.last_accessed_at.asc())
                    .limit(1)
                ).first()

            if not oldest:
                logger.warning("Disk pressure at %.0f%% but no snapshots to evict", ratio * 100)
                break

            neo4j_ok = self._delete_snapshot(oldest)
            evicted += 1

            if not neo4j_ok:
                logger.error(
                    "Stopping disk pressure eviction: Neo4j delete failed, "
                    "further evictions won't free disk space"
                )
                break

            # Re-check against target
            try:
                usage = shutil.disk_usage(data_dir)
                if usage.used / usage.total <= DISK_TARGET:
                    break
            except OSError:
                break

        if evicted:
            logger.info("Evicted %d snapshot(s) due to disk pressure", evicted)
        return evicted

    def _delete_snapshot(self, snap: Snapshot) -> bool:
        """Delete snapshot from PostgreSQL, Neo4j, and logs.

        PostgreSQL is deleted first to eliminate zombie reference risk — if Neo4j
        cleanup fails later, the orphaned graph data is less harmful than a
        PostgreSQL reference pointing to missing Neo4j data.

        Returns:
            True if Neo4j data was successfully deleted (disk space freed),
            False if Neo4j delete failed (disk pressure may persist).
        """
        sid = str(snap.id)
        logger.info("Evicting snapshot %s (%s %s)", sid, snap.repo_url, snap.version)

        # Delete PostgreSQL reference first
        try:
            with self._session_factory() as session:
                session.execute(delete(Snapshot).where(Snapshot.id == snap.id))
                session.commit()
        except Exception as e:
            logger.error("Failed to delete snapshot %s: %s", sid, e)
            return False  # Don't delete Neo4j/logs if we can't remove the reference

        neo4j_ok = True
        if self._graph_store:
            try:
                self._graph_store.delete_snapshot(sid)
            except Exception as e:
                logger.error("Failed to delete Neo4j snapshot %s: %s", sid, e)
                neo4j_ok = False

        if self._log_store:
            try:
                self._log_store.delete_logs(sid)
            except Exception as e:
                logger.error("Failed to delete logs for snapshot %s: %s", sid, e)

        return neo4j_ok
