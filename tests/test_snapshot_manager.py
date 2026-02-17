"""Tests for SnapshotManager — requires MongoDB."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

needs_mongo = pytest.mark.skipif(
    os.environ.get("SKIP_MONGO", "0") == "1",
    reason="SKIP_MONGO=1",
)


@pytest.fixture
def sm(mongo_uri):
    """Create a SnapshotManager with a disposable test database."""
    from z_code_analyzer.snapshot_manager import SnapshotManager

    db_name = "z_code_analyzer_test"
    mgr = SnapshotManager(mongo_uri=mongo_uri, db_name=db_name)
    yield mgr
    # Cleanup: drop the entire test database
    mgr._client.drop_database(db_name)
    mgr.close()


# ── list_snapshots / find_snapshot ──


@needs_mongo
class TestListAndFind:
    def test_list_empty(self, sm):
        assert sm.list_snapshots() == []

    def test_list_by_status(self, sm):
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "completed", "last_accessed_at": datetime.now(timezone.utc)}
        )
        sm._snapshots.insert_one(
            {"repo_url": "https://r/b", "version": "v1", "backend": "svf",
             "status": "failed", "last_accessed_at": datetime.now(timezone.utc)}
        )
        assert len(sm.list_snapshots()) == 1
        assert len(sm.list_snapshots(status="failed")) == 1

    def test_list_filter_by_repo(self, sm):
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "completed", "last_accessed_at": datetime.now(timezone.utc)}
        )
        sm._snapshots.insert_one(
            {"repo_url": "https://r/b", "version": "v1", "backend": "svf",
             "status": "completed", "last_accessed_at": datetime.now(timezone.utc)}
        )
        assert len(sm.list_snapshots(repo_url="https://r/a")) == 1

    def test_find_snapshot_exact_backend(self, sm):
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "completed", "last_accessed_at": datetime.now(timezone.utc),
             "access_count": 0}
        )
        snap = sm.find_snapshot("https://r/a", "v1", preferred_backend="svf")
        assert snap is not None
        assert snap["backend"] == "svf"

    def test_find_snapshot_fallback_order(self, sm):
        """When preferred backend not found, falls back in precision order."""
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "joern",
             "status": "completed", "last_accessed_at": datetime.now(timezone.utc),
             "access_count": 0}
        )
        snap = sm.find_snapshot("https://r/a", "v1", preferred_backend="svf")
        assert snap is not None
        assert snap["backend"] == "joern"

    def test_find_snapshot_not_found(self, sm):
        assert sm.find_snapshot("https://r/missing", "v1") is None


# ── acquire_or_wait ──


@needs_mongo
class TestAcquireOrWait:
    def test_new_snapshot_creates_building(self, sm):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        assert snap is not None
        assert snap["status"] == "building"
        assert snap["repo_name"] == "a"

    def test_completed_snapshot_returns_cached(self, sm):
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "completed", "last_accessed_at": datetime.now(timezone.utc),
             "access_count": 0}
        )
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        assert snap["status"] == "completed"

    def test_failed_snapshot_deleted_and_retried(self, sm):
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "failed", "error": "build error",
             "last_accessed_at": datetime.now(timezone.utc)}
        )
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        assert snap is not None
        assert snap["status"] == "building"
        # Old failed one should be gone
        assert sm._snapshots.count_documents({"status": "failed"}) == 0

    def test_building_timeout_marks_failed(self, sm):
        """A building snapshot older than BUILDING_TIMEOUT_MINUTES gets marked failed."""
        old_time = datetime.now(timezone.utc) - timedelta(minutes=60)
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "building", "created_at": old_time,
             "last_accessed_at": old_time}
        )
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        # Should mark the old one as failed, delete it, then create new building
        assert snap is not None
        assert snap["status"] == "building"

    def test_unique_index_prevents_duplicate(self, sm):
        """Two inserts with same (repo_url, version, backend) hit DuplicateKeyError."""
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "completed", "last_accessed_at": datetime.now(timezone.utc),
             "access_count": 0}
        )
        from pymongo.errors import DuplicateKeyError

        with pytest.raises(DuplicateKeyError):
            sm._snapshots.insert_one(
                {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
                 "status": "building", "last_accessed_at": datetime.now(timezone.utc)}
            )

    def test_repo_name_extracted(self, sm):
        snap = asyncio.run(sm.acquire_or_wait(
            "https://github.com/user/curl", "v8.0", "svf"
        ))
        assert snap["repo_name"] == "curl"


# ── mark_completed / mark_failed ──


@needs_mongo
class TestMarkStatus:
    def test_mark_completed(self, sm):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        sid = str(snap["_id"])
        sm.mark_completed(sid, node_count=100, edge_count=200,
                          fuzzer_names=["fuzz1"], analysis_duration_sec=1.5,
                          language="c")
        updated = sm._snapshots.find_one({"_id": snap["_id"]})
        assert updated["status"] == "completed"
        assert updated["node_count"] == 100
        assert updated["edge_count"] == 200
        assert updated["fuzzer_names"] == ["fuzz1"]
        assert updated["analysis_duration_sec"] == 1.5
        assert updated["language"] == "c"

    def test_mark_completed_estimates_size(self, sm):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        sid = str(snap["_id"])
        sm.mark_completed(sid, node_count=100, edge_count=200,
                          fuzzer_names=[])
        updated = sm._snapshots.find_one({"_id": snap["_id"]})
        assert updated["size_bytes"] == 100 * 1200 + 200 * 150

    def test_mark_failed(self, sm):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        sid = str(snap["_id"])
        sm.mark_failed(sid, "compilation error")
        updated = sm._snapshots.find_one({"_id": snap["_id"]})
        assert updated["status"] == "failed"
        assert updated["error"] == "compilation error"


# ── on_snapshot_accessed ──


@needs_mongo
class TestAccess:
    def test_access_increments_count(self, sm):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        sid = str(snap["_id"])
        sm.mark_completed(sid, 10, 20, [])
        sm.on_snapshot_accessed(sid)
        sm.on_snapshot_accessed(sid)
        updated = sm._snapshots.find_one({"_id": snap["_id"]})
        # Initial insert has access_count=0, mark_completed doesn't change it,
        # two on_snapshot_accessed calls → 2
        assert updated["access_count"] == 2


# ── Eviction ──


@needs_mongo
class TestEviction:
    def test_evict_by_version_limit(self, sm):
        from z_code_analyzer import snapshot_manager

        old_limit = snapshot_manager.MAX_VERSIONS_PER_REPO
        snapshot_manager.MAX_VERSIONS_PER_REPO = 2
        try:
            for i in range(4):
                sm._snapshots.insert_one(
                    {"repo_url": "https://r/a", "version": f"v{i}",
                     "backend": "svf", "status": "completed",
                     "last_accessed_at": datetime.now(timezone.utc) - timedelta(hours=4 - i)}
                )
            evicted = sm.evict_by_version_limit("https://r/a")
            assert evicted == 2
            remaining = sm.list_snapshots(repo_url="https://r/a")
            assert len(remaining) == 2
            # Remaining should be the two most recently accessed
            versions = {s["version"] for s in remaining}
            assert "v2" in versions
            assert "v3" in versions
        finally:
            snapshot_manager.MAX_VERSIONS_PER_REPO = old_limit

    def test_evict_by_ttl(self, sm):
        now = datetime.now(timezone.utc)
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "old", "backend": "svf",
             "status": "completed",
             "last_accessed_at": now - timedelta(days=100)}
        )
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "new", "backend": "joern",
             "status": "completed",
             "last_accessed_at": now}
        )
        evicted = sm.evict_by_ttl()
        assert evicted == 1
        remaining = sm.list_snapshots()
        assert len(remaining) == 1
        assert remaining[0]["version"] == "new"

    def test_evict_by_version_limit_no_eviction_needed(self, sm):
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "completed",
             "last_accessed_at": datetime.now(timezone.utc)}
        )
        evicted = sm.evict_by_version_limit("https://r/a")
        assert evicted == 0

    def test_delete_snapshot_calls_graph_store(self, sm):
        mock_gs = MagicMock()
        sm._graph_store = mock_gs
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "completed",
             "last_accessed_at": datetime.now(timezone.utc)}
        )
        snap = sm._snapshots.find_one({"status": "completed"})
        ok = sm._delete_snapshot(snap)
        assert ok is True
        mock_gs.delete_snapshot.assert_called_once_with(str(snap["_id"]))

    def test_delete_snapshot_neo4j_failure(self, sm):
        mock_gs = MagicMock()
        mock_gs.delete_snapshot.side_effect = RuntimeError("neo4j down")
        sm._graph_store = mock_gs
        sm._snapshots.insert_one(
            {"repo_url": "https://r/a", "version": "v1", "backend": "svf",
             "status": "completed",
             "last_accessed_at": datetime.now(timezone.utc)}
        )
        snap = sm._snapshots.find_one({"status": "completed"})
        ok = sm._delete_snapshot(snap)
        assert ok is False
        # MongoDB record should still be deleted (MongoDB first strategy)
        assert sm._snapshots.count_documents({}) == 0
