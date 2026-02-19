"""Tests for SnapshotDAO."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.snapshot_dao import SnapshotDAO


@pytest.fixture
def dao():
    return SnapshotDAO()


@pytest.fixture
def proj_dao():
    return ProjectDAO()


@pytest.fixture
async def project(proj_dao, session):
    return await proj_dao.create(session, name="my-app", repo_url="https://github.com/org/my-app")


@pytest.fixture
async def project2(proj_dao, session):
    return await proj_dao.create(
        session, name="other-app", repo_url="https://github.com/org/other-app"
    )


def _snap(project_id, version="v1.0.0", **overrides) -> dict:
    """Helper to build snapshot kwargs."""
    defaults = {
        "project_id": project_id,
        "repo_url": "https://github.com/org/my-app",
        "repo_name": "my-app",
        "version": version,
        "backend": "svf",
        "trigger_type": "manual",
    }
    defaults.update(overrides)
    return defaults


# ── create + get_by_id ────────────────────────────────────────────────────


class TestCreate:
    async def test_create_with_defaults(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        assert snap.id is not None
        assert snap.project_id == project.id
        assert snap.status == "building"
        assert snap.is_active is False
        assert snap.node_count == 0
        assert snap.edge_count == 0
        assert snap.fuzzer_names == []
        assert snap.error is None

    async def test_get_by_id(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        found = await dao.get_by_id(session, snap.id)
        assert found is not None
        assert found.version == "v1.0.0"


# ── list_by_project ───────────────────────────────────────────────────────


class TestListByProject:
    async def test_empty(self, dao, session, project):
        page = await dao.list_by_project(session, project.id)
        assert page.data == []
        assert page.has_more is False

    async def test_returns_only_target_project(self, dao, session, project, project2):
        await dao.create(session, **_snap(project.id, "v1.0"))
        await dao.create(
            session,
            **_snap(
                project2.id,
                "v2.0",
                repo_url="https://github.com/org/other-app",
                repo_name="other-app",
            ),
        )
        page = await dao.list_by_project(session, project.id)
        assert len(page.data) == 1
        assert page.data[0].project_id == project.id

    async def test_pagination(self, dao, session, project):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            snap = await dao.create(session, **_snap(project.id, f"v{i}.0", backend="joern"))
            snap.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        page1 = await dao.list_by_project(session, project.id, page_size=3)
        assert len(page1.data) == 3
        assert page1.has_more is True

        page2 = await dao.list_by_project(
            session, project.id, cursor_str=page1.next_cursor, page_size=3
        )
        assert len(page2.data) == 2
        assert page2.has_more is False


# ── get_active_by_project ─────────────────────────────────────────────────


class TestGetActiveByProject:
    async def test_no_active(self, dao, session, project):
        await dao.create(session, **_snap(project.id))
        result = await dao.get_active_by_project(session, project.id)
        assert result is None

    async def test_returns_active(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        await dao.activate(session, snap.id)

        active = await dao.get_active_by_project(session, project.id)
        assert active is not None
        assert active.id == snap.id
        assert active.is_active is True

    async def test_does_not_return_other_projects_active(self, dao, session, project, project2):
        await dao.create(session, **_snap(project.id, "v1.0"))
        snap2 = await dao.create(
            session,
            **_snap(
                project2.id,
                "v2.0",
                repo_url="https://github.com/org/other-app",
                repo_name="other-app",
            ),
        )
        await dao.activate(session, snap2.id)

        result = await dao.get_active_by_project(session, project.id)
        assert result is None


# ── list_building ─────────────────────────────────────────────────────────


class TestListBuilding:
    async def test_empty(self, dao, session):
        result = await dao.list_building(session)
        assert result == []

    async def test_returns_building_only(self, dao, session, project):
        snap1 = await dao.create(session, **_snap(project.id, "v1.0"))
        snap2 = await dao.create(session, **_snap(project.id, "v2.0", backend="joern"))
        # Complete snap2
        await dao.update_status(session, snap2.id, status="completed")

        building = await dao.list_building(session)
        assert len(building) == 1
        assert building[0].id == snap1.id

    async def test_returns_multiple(self, dao, session, project):
        await dao.create(session, **_snap(project.id, "v1.0"))
        await dao.create(session, **_snap(project.id, "v2.0", backend="joern"))

        building = await dao.list_building(session)
        assert len(building) == 2


# ── update_status ─────────────────────────────────────────────────────────


class TestUpdateStatus:
    async def test_update_status_only(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        await dao.update_status(session, snap.id, status="completed")
        await session.refresh(snap)
        assert snap.status == "completed"

    async def test_update_with_metadata(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        await dao.update_status(
            session,
            snap.id,
            status="completed",
            node_count=1500,
            edge_count=8000,
            analysis_duration_sec=12.5,
            storage_path="/data/snapshots/abc",
            fuzzer_names=["fuzz_target_1", "fuzz_target_2"],
            language="c",
            size_bytes=1024000,
        )
        await session.refresh(snap)

        assert snap.status == "completed"
        assert snap.node_count == 1500
        assert snap.edge_count == 8000
        assert snap.analysis_duration_sec == 12.5
        assert snap.storage_path == "/data/snapshots/abc"
        assert snap.fuzzer_names == ["fuzz_target_1", "fuzz_target_2"]
        assert snap.language == "c"
        assert snap.size_bytes == 1024000

    async def test_update_with_error(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        await dao.update_status(
            session,
            snap.id,
            status="completed",
            error="build failed: missing dependency",
        )
        await session.refresh(snap)
        assert snap.error == "build failed: missing dependency"

    async def test_partial_update_preserves_other_fields(self, dao, session, project):
        """Updating only status should not reset node_count etc."""
        snap = await dao.create(session, **_snap(project.id))
        await dao.update_status(session, snap.id, status="completed", node_count=100)
        await dao.update_status(session, snap.id, status="building")
        await session.refresh(snap)
        assert snap.status == "building"
        assert snap.node_count == 100  # preserved

    async def test_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.update_status(session, None, status="completed")


# ── activate ──────────────────────────────────────────────────────────────


class TestActivate:
    async def test_activate_sets_active_and_completed(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        await dao.activate(session, snap.id)
        await session.refresh(snap)

        assert snap.is_active is True
        assert snap.status == "completed"

    async def test_activate_deactivates_previous(self, dao, session, project):
        """Only one snapshot per project should be active."""
        snap1 = await dao.create(session, **_snap(project.id, "v1.0"))
        snap2 = await dao.create(session, **_snap(project.id, "v2.0", backend="joern"))

        await dao.activate(session, snap1.id)
        await dao.activate(session, snap2.id)

        await session.refresh(snap1)
        await session.refresh(snap2)

        assert snap1.is_active is False
        assert snap2.is_active is True

    async def test_activate_does_not_affect_other_projects(self, dao, session, project, project2):
        snap1 = await dao.create(session, **_snap(project.id, "v1.0"))
        snap2 = await dao.create(
            session,
            **_snap(
                project2.id,
                "v2.0",
                repo_url="https://github.com/org/other-app",
                repo_name="other-app",
            ),
        )

        await dao.activate(session, snap1.id)
        await dao.activate(session, snap2.id)

        await session.refresh(snap1)
        await session.refresh(snap2)

        # Both should remain active — different projects
        assert snap1.is_active is True
        assert snap2.is_active is True

    async def test_activate_nonexistent_raises(self, dao, session):
        with pytest.raises(ValueError, match="not found"):
            await dao.activate(session, uuid.uuid4())

    async def test_activate_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.activate(session, None)


# ── inherited methods ─────────────────────────────────────────────────────


class TestInheritedMethods:
    async def test_delete(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        assert await dao.delete(session, snap.id) is True
        assert await dao.get_by_id(session, snap.id) is None

    async def test_exists(self, dao, session, project):
        snap = await dao.create(session, **_snap(project.id))
        assert await dao.exists(session, snap.id) is True

    async def test_count(self, dao, session, project):
        for i in range(3):
            await dao.create(session, **_snap(project.id, f"v{i}.0", backend="joern"))
        assert await dao.count(session) == 3
