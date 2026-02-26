"""Tests for SnapshotManager — uses local PostgreSQL."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from z_code_analyzer.models.snapshot import Snapshot, ZCABase
from z_code_analyzer.snapshot_manager import SnapshotManager

_PG_URL = os.environ.get(
    "ZCA_DATABASE_URL",
    "postgresql://vulnsentinel:vulnsentinel@localhost:5432/vulnsentinel_test",
)


@pytest.fixture
def session_factory():
    """Create a PostgreSQL engine with the snapshots table."""
    engine = create_engine(_PG_URL, echo=False)
    ZCABase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    yield factory
    ZCABase.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def sm(session_factory):
    """Create a SnapshotManager backed by PostgreSQL."""
    return SnapshotManager(session_factory=session_factory)


def _insert(session_factory, **kwargs):
    """Helper: insert a snapshot row and return it."""
    import uuid

    defaults = {
        "id": uuid.uuid4(),
        "status": "completed",
        "node_count": 0,
        "edge_count": 0,
        "access_count": 0,
        "analysis_duration_sec": 0.0,
        "language": "",
        "size_bytes": 0,
        "last_accessed_at": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(kwargs)
    snap = Snapshot(**defaults)
    with session_factory() as session:
        session.add(snap)
        session.commit()
        session.refresh(snap)
        session.expunge(snap)
    return snap


def _count(session_factory, **filters):
    """Helper: count snapshot rows matching filters."""
    with session_factory() as session:
        stmt = select(Snapshot)
        for k, v in filters.items():
            stmt = stmt.where(getattr(Snapshot, k) == v)
        return len(list(session.scalars(stmt).all()))


# ── list_snapshots / find_snapshot ──


class TestListAndFind:
    def test_list_empty(self, sm):
        assert sm.list_snapshots() == []

    def test_list_by_status(self, sm, session_factory):
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
            status="completed",
        )
        _insert(
            session_factory,
            repo_url="https://r/b",
            repo_name="b",
            version="v1",
            backend="svf",
            status="failed",
        )
        assert len(sm.list_snapshots()) == 1
        assert len(sm.list_snapshots(status="failed")) == 1

    def test_list_filter_by_repo(self, sm, session_factory):
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
        )
        _insert(
            session_factory,
            repo_url="https://r/b",
            repo_name="b",
            version="v1",
            backend="svf",
        )
        assert len(sm.list_snapshots(repo_url="https://r/a")) == 1

    def test_find_snapshot_exact_backend(self, sm, session_factory):
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
        )
        snap = sm.find_snapshot("https://r/a", "v1", preferred_backend="svf")
        assert snap is not None
        assert snap.backend == "svf"

    def test_find_snapshot_fallback_order(self, sm, session_factory):
        """When preferred backend not found, falls back in precision order."""
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="joern",
        )
        snap = sm.find_snapshot("https://r/a", "v1", preferred_backend="svf")
        assert snap is not None
        assert snap.backend == "joern"

    def test_find_snapshot_not_found(self, sm):
        assert sm.find_snapshot("https://r/missing", "v1") is None


# ── acquire_or_wait ──


class TestAcquireOrWait:
    def test_new_snapshot_creates_building(self, sm):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        assert snap is not None
        assert snap.status == "building"
        assert snap.repo_name == "a"

    def test_completed_snapshot_returns_cached(self, sm, session_factory):
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
            status="completed",
        )
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        assert snap.status == "completed"

    def test_failed_snapshot_deleted_and_retried(self, sm, session_factory):
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
            status="failed",
            error="build error",
        )
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        assert snap is not None
        assert snap.status == "building"
        assert _count(session_factory, status="failed") == 0

    def test_building_timeout_marks_failed(self, sm, session_factory):
        """A building snapshot older than BUILDING_TIMEOUT_MINUTES gets marked failed."""
        old_time = datetime.now(timezone.utc) - timedelta(minutes=60)
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
            status="building",
            created_at=old_time,
            last_accessed_at=old_time,
        )
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        assert snap is not None
        assert snap.status == "building"

    def test_unique_constraint_prevents_duplicate(self, sm, session_factory):
        """Two inserts with same (repo_url, version, backend) hit IntegrityError."""
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
            status="completed",
        )
        from sqlalchemy.exc import IntegrityError

        with pytest.raises(IntegrityError):
            _insert(
                session_factory,
                repo_url="https://r/a",
                repo_name="a",
                version="v1",
                backend="svf",
                status="building",
            )

    def test_repo_name_extracted(self, sm):
        snap = asyncio.run(sm.acquire_or_wait("https://github.com/user/curl", "v8.0", "svf"))
        assert snap.repo_name == "curl"


# ── mark_completed / mark_failed ──


class TestMarkStatus:
    def test_mark_completed(self, sm, session_factory):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        sid = str(snap.id)
        sm.mark_completed(
            sid,
            node_count=100,
            edge_count=200,
            fuzzer_names=["fuzz1"],
            analysis_duration_sec=1.5,
            language="c",
        )
        with session_factory() as session:
            updated = session.scalars(select(Snapshot).where(Snapshot.id == snap.id)).first()
            assert updated.status == "completed"
            assert updated.node_count == 100
            assert updated.edge_count == 200
            assert updated.analysis_duration_sec == 1.5
            assert updated.language == "c"

    def test_mark_completed_estimates_size(self, sm, session_factory):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        sid = str(snap.id)
        sm.mark_completed(sid, node_count=100, edge_count=200, fuzzer_names=[])
        with session_factory() as session:
            updated = session.scalars(select(Snapshot).where(Snapshot.id == snap.id)).first()
            assert updated.size_bytes == 100 * 1200 + 200 * 150

    def test_mark_failed(self, sm, session_factory):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        sid = str(snap.id)
        sm.mark_failed(sid, "compilation error")
        with session_factory() as session:
            updated = session.scalars(select(Snapshot).where(Snapshot.id == snap.id)).first()
            assert updated.status == "failed"
            assert updated.error == "compilation error"


# ── on_snapshot_accessed ──


class TestAccess:
    def test_access_increments_count(self, sm, session_factory):
        snap = asyncio.run(sm.acquire_or_wait("https://r/a", "v1", "svf"))
        sid = str(snap.id)
        sm.mark_completed(sid, 10, 20, [])
        sm.on_snapshot_accessed(sid)
        sm.on_snapshot_accessed(sid)
        with session_factory() as session:
            updated = session.scalars(select(Snapshot).where(Snapshot.id == snap.id)).first()
            assert updated.access_count == 2


# ── Eviction ──


class TestEviction:
    def test_evict_by_version_limit(self, sm, session_factory):
        from z_code_analyzer import snapshot_manager

        old_limit = snapshot_manager.MAX_VERSIONS_PER_REPO
        snapshot_manager.MAX_VERSIONS_PER_REPO = 2
        try:
            for i in range(4):
                _insert(
                    session_factory,
                    repo_url="https://r/a",
                    repo_name="a",
                    version=f"v{i}",
                    backend="svf",
                    status="completed",
                    last_accessed_at=datetime.now(timezone.utc) - timedelta(hours=4 - i),
                )
            evicted = sm.evict_by_version_limit("https://r/a")
            assert evicted == 2
            remaining = sm.list_snapshots(repo_url="https://r/a")
            assert len(remaining) == 2
            versions = {s.version for s in remaining}
            assert "v2" in versions
            assert "v3" in versions
        finally:
            snapshot_manager.MAX_VERSIONS_PER_REPO = old_limit

    def test_evict_by_ttl(self, sm, session_factory):
        now = datetime.now(timezone.utc)
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="old",
            backend="svf",
            status="completed",
            last_accessed_at=now - timedelta(days=100),
        )
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="new",
            backend="joern",
            status="completed",
            last_accessed_at=now,
        )
        evicted = sm.evict_by_ttl()
        assert evicted == 1
        remaining = sm.list_snapshots()
        assert len(remaining) == 1
        assert remaining[0].version == "new"

    def test_evict_by_version_limit_no_eviction_needed(self, sm, session_factory):
        _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
            status="completed",
        )
        evicted = sm.evict_by_version_limit("https://r/a")
        assert evicted == 0

    def test_delete_snapshot_calls_graph_store(self, sm, session_factory):
        mock_gs = MagicMock()
        sm._graph_store = mock_gs
        snap = _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
            status="completed",
        )
        ok = sm._delete_snapshot(snap)
        assert ok is True
        mock_gs.delete_snapshot.assert_called_once_with(str(snap.id))

    def test_delete_snapshot_neo4j_failure(self, sm, session_factory):
        mock_gs = MagicMock()
        mock_gs.delete_snapshot.side_effect = RuntimeError("neo4j down")
        sm._graph_store = mock_gs
        snap = _insert(
            session_factory,
            repo_url="https://r/a",
            repo_name="a",
            version="v1",
            backend="svf",
            status="completed",
        )
        ok = sm._delete_snapshot(snap)
        assert ok is False
        # DB record should still be deleted (DB first strategy)
        assert _count(session_factory) == 0
