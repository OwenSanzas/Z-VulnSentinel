"""Snapshot lifecycle management — MongoDB directory + concurrency control + eviction."""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

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
    MongoDB stores directory/metadata, Neo4j stores the actual graph.
    """

    def __init__(
        self,
        mongo_uri: str = "mongodb://localhost:27017",
        db_name: str = "z_code_analyzer",
        graph_store: Any = None,
        log_store: Any = None,
    ) -> None:
        self._client = MongoClient(mongo_uri)
        self._db = self._client[db_name]
        self._snapshots = self._db["snapshots"]
        self._graph_store = graph_store
        self._log_store = log_store
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        self._snapshots.create_index(
            [("repo_url", 1), ("version", 1), ("backend", 1)],
            unique=True,
        )
        self._snapshots.create_index("last_accessed_at")

    def close(self) -> None:
        self._client.close()

    def list_snapshots(
        self, repo_url: str | None = None, status: str = "completed"
    ) -> list[dict]:
        """List snapshots, optionally filtered by repo_url."""
        query: dict = {"status": status}
        if repo_url:
            query["repo_url"] = repo_url
        return list(self._snapshots.find(query).sort("last_accessed_at", -1))

    def find_snapshot(
        self,
        repo_url: str,
        version: str,
        preferred_backend: str | None = None,
    ) -> dict | None:
        """Find a reusable snapshot."""
        # Exact match first
        if preferred_backend:
            snap = self._snapshots.find_one(
                {
                    "repo_url": repo_url,
                    "version": version,
                    "backend": preferred_backend,
                    "status": "completed",
                }
            )
            if snap:
                self.on_snapshot_accessed(str(snap["_id"]))
                return snap

        # Any backend for same version, prefer higher precision
        for backend in ["svf", "joern", "introspector", "prebuild"]:
            snap = self._snapshots.find_one(
                {
                    "repo_url": repo_url,
                    "version": version,
                    "backend": backend,
                    "status": "completed",
                }
            )
            if snap:
                self.on_snapshot_accessed(str(snap["_id"]))
                return snap

        return None

    async def acquire_or_wait(
        self,
        repo_url: str,
        version: str,
        backend: str,
    ) -> dict | None:
        """
        Acquire a snapshot slot or wait for an in-progress one.

        Returns:
            dict with status="completed" if cache hit.
            dict with status="building" if we got the lock (caller should analyze).
            None if a previous attempt failed and we should retry.
        """
        snap = self._snapshots.find_one(
            {"repo_url": repo_url, "version": version, "backend": backend}
        )

        if snap:
            if snap["status"] == "completed":
                self.on_snapshot_accessed(str(snap["_id"]))
                return snap

            if snap["status"] == "building":
                created = snap.get("created_at", datetime.now(timezone.utc))
                if isinstance(created, datetime):
                    age = datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc)
                else:
                    age = timedelta(0)

                if age > timedelta(minutes=BUILDING_TIMEOUT_MINUTES):
                    self._snapshots.update_one(
                        {"_id": snap["_id"]},
                        {"$set": {"status": "failed", "error": "timeout: analyzer process died"}},
                    )
                    # Update local copy so the failed check below can delete it
                    snap["status"] = "failed"
                else:
                    return await self._wait_for_ready(repo_url, version, backend)

            if snap["status"] == "failed":
                self._snapshots.delete_one({"_id": snap["_id"]})

        # Create placeholder
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1] if "/" in repo_url else repo_url
        try:
            result = self._snapshots.insert_one(
                {
                    "repo_url": repo_url,
                    "repo_name": repo_name,
                    "version": version,
                    "backend": backend,
                    "status": "building",
                    "created_at": datetime.now(timezone.utc),
                    "last_accessed_at": datetime.now(timezone.utc),
                    "access_count": 0,
                    "node_count": 0,
                    "edge_count": 0,
                    "fuzzer_names": [],
                }
            )
            snap = self._snapshots.find_one({"_id": result.inserted_id})
            return snap
        except DuplicateKeyError:
            return await self._wait_for_ready(repo_url, version, backend)

    async def _wait_for_ready(
        self,
        repo_url: str,
        version: str,
        backend: str,
        timeout: int = WAIT_TIMEOUT,
    ) -> dict | None:
        """Poll until snapshot is ready."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            snap = self._snapshots.find_one(
                {"repo_url": repo_url, "version": version, "backend": backend}
            )
            if snap and snap["status"] == "completed":
                self.on_snapshot_accessed(str(snap["_id"]))
                return snap
            if not snap or snap["status"] == "failed":
                return None
            await asyncio.sleep(WAIT_POLL_INTERVAL)
        raise TimeoutError("Waiting for snapshot analysis timed out")

    def mark_completed(
        self,
        snapshot_id: str,
        node_count: int,
        edge_count: int,
        fuzzer_names: list[str],
        analysis_duration_sec: float = 0.0,
        language: str = "",
        size_bytes: int = 0,
    ) -> None:
        from bson import ObjectId

        # Estimate size if not provided (~1200 bytes/node + ~150 bytes/edge)
        if size_bytes <= 0:
            size_bytes = node_count * 1200 + edge_count * 150

        self._snapshots.update_one(
            {"_id": ObjectId(snapshot_id)},
            {
                "$set": {
                    "status": "completed",
                    "node_count": node_count,
                    "edge_count": edge_count,
                    "fuzzer_names": fuzzer_names,
                    "analysis_duration_sec": analysis_duration_sec,
                    "language": language,
                    "size_bytes": size_bytes,
                    "last_accessed_at": datetime.now(timezone.utc),
                }
            },
        )

    def mark_failed(self, snapshot_id: str, error: str) -> None:
        from bson import ObjectId

        self._snapshots.update_one(
            {"_id": ObjectId(snapshot_id)},
            {"$set": {"status": "failed", "error": error}},
        )

    def on_snapshot_accessed(self, snapshot_id: str) -> None:
        from bson import ObjectId

        self._snapshots.update_one(
            {"_id": ObjectId(snapshot_id)},
            {
                "$set": {"last_accessed_at": datetime.now(timezone.utc)},
                "$inc": {"access_count": 1},
            },
        )

    # ── Eviction ──

    def evict_by_version_limit(self, repo_url: str) -> int:
        """Evict oldest snapshots if a repo exceeds MAX_VERSIONS_PER_REPO."""
        snapshots = list(
            self._snapshots.find({"repo_url": repo_url, "status": "completed"}).sort(
                "last_accessed_at", -1
            )
        )
        to_delete = snapshots[MAX_VERSIONS_PER_REPO:]
        for snap in to_delete:
            self._delete_snapshot(snap)
        return len(to_delete)

    def evict_by_ttl(self) -> int:
        """Evict snapshots not accessed within TTL."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=SNAPSHOT_TTL_DAYS)
        expired = list(
            self._snapshots.find(
                {"status": "completed", "last_accessed_at": {"$lt": cutoff}}
            )
        )
        for snap in expired:
            self._delete_snapshot(snap)
        return len(expired)

    def evict_by_disk_pressure(self, data_dir: str = "/var/lib/neo4j/data") -> int:
        """Evict LRU snapshots when disk usage exceeds DISK_THRESHOLD.

        Keeps evicting until usage drops below DISK_TARGET or no snapshots remain.
        """
        evicted = 0
        while True:
            try:
                usage = shutil.disk_usage(data_dir)
                ratio = usage.used / usage.total
            except OSError:
                logger.warning("Cannot check disk usage for %s, skipping pressure eviction", data_dir)
                break

            if ratio <= DISK_THRESHOLD:
                break

            oldest = self._snapshots.find_one(
                {"status": "completed"},
                sort=[("last_accessed_at", 1)],
            )
            if not oldest:
                logger.warning("Disk pressure at %.0f%% but no snapshots to evict", ratio * 100)
                break

            self._delete_snapshot(oldest)
            evicted += 1

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

    def _delete_snapshot(self, snap: dict) -> None:
        """Delete snapshot from MongoDB, Neo4j, and logs.

        MongoDB is deleted first to eliminate zombie reference risk — if Neo4j
        cleanup fails later, the orphaned graph data is less harmful than a
        MongoDB reference pointing to missing Neo4j data.
        """
        sid = str(snap["_id"])
        logger.info("Evicting snapshot %s (%s %s)", sid, snap.get("repo_url"), snap.get("version"))

        # Delete MongoDB reference first
        try:
            self._snapshots.delete_one({"_id": snap["_id"]})
        except Exception as e:
            logger.error("Failed to delete MongoDB snapshot %s: %s", sid, e)
            return  # Don't delete Neo4j/logs if we can't remove the reference

        if self._graph_store:
            try:
                self._graph_store.delete_snapshot(sid)
            except Exception as e:
                logger.error("Failed to delete Neo4j snapshot %s: %s", sid, e)

        if self._log_store:
            try:
                self._log_store.delete_logs(sid)
            except Exception as e:
                logger.error("Failed to delete logs for snapshot %s: %s", sid, e)
