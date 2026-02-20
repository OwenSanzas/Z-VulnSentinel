"""Tests for SnapshotService."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from vulnsentinel.dao.base import Page
from vulnsentinel.dao.snapshot_dao import SnapshotDAO
from vulnsentinel.models.snapshot import Snapshot
from vulnsentinel.services import NotFoundError
from vulnsentinel.services.snapshot_service import SnapshotService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_snapshot(**overrides) -> Snapshot:
    defaults = {
        "id": uuid.uuid4(),
        "project_id": uuid.uuid4(),
        "repo_url": "https://github.com/curl/curl",
        "repo_name": "curl",
        "version": "8.5.0",
        "backend": "svf",
        "status": "building",
        "trigger_type": "manual",
        "is_active": False,
        "storage_path": None,
        "node_count": 0,
        "edge_count": 0,
        "fuzzer_names": [],
        "analysis_duration_sec": 0.0,
        "language": "",
        "size_bytes": 0,
        "error": None,
        "last_accessed_at": None,
        "access_count": 0,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return Snapshot(**defaults)


def _make_service() -> tuple[SnapshotService, SnapshotDAO]:
    dao = SnapshotDAO()
    service = SnapshotService(dao)
    return service, dao


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


class TestGet:
    async def test_get_success(self):
        snapshot = _make_snapshot()
        service, dao = _make_service()
        dao.get_by_id = AsyncMock(return_value=snapshot)

        session = AsyncMock()
        result = await service.get(session, snapshot.id)

        assert result is snapshot
        dao.get_by_id.assert_awaited_once_with(session, snapshot.id)

    async def test_get_not_found(self):
        service, dao = _make_service()
        dao.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundError, match="snapshot not found"):
            await service.get(AsyncMock(), uuid.uuid4())


# ---------------------------------------------------------------------------
# list_by_project
# ---------------------------------------------------------------------------


class TestListByProject:
    async def test_list_by_project(self):
        snapshots = [_make_snapshot(), _make_snapshot(version="8.4.0")]
        page = Page(data=snapshots, next_cursor="abc", has_more=True)

        service, dao = _make_service()
        dao.list_by_project = AsyncMock(return_value=page)

        project_id = uuid.uuid4()
        session = AsyncMock()
        result = await service.list_by_project(session, project_id, cursor=None, page_size=10)

        assert result["data"] == snapshots
        assert result["next_cursor"] == "abc"
        assert result["has_more"] is True
        dao.list_by_project.assert_awaited_once_with(session, project_id, None, 10)

    async def test_list_by_project_empty(self):
        page = Page(data=[], next_cursor=None, has_more=False)

        service, dao = _make_service()
        dao.list_by_project = AsyncMock(return_value=page)

        result = await service.list_by_project(AsyncMock(), uuid.uuid4())

        assert result["data"] == []
        assert result["has_more"] is False


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


class TestCreate:
    async def test_create(self):
        snapshot = _make_snapshot()
        service, dao = _make_service()
        dao.create = AsyncMock(return_value=snapshot)

        session = AsyncMock()
        result = await service.create(
            session,
            project_id=snapshot.project_id,
            repo_url="https://github.com/curl/curl",
            repo_name="curl",
            version="8.5.0",
            backend="svf",
            trigger_type="manual",
        )

        assert result is snapshot
        dao.create.assert_awaited_once()
        kwargs = dao.create.call_args.kwargs
        assert kwargs["repo_name"] == "curl"
        assert kwargs["backend"] == "svf"
        assert kwargs["trigger_type"] == "manual"

    async def test_create_without_trigger(self):
        snapshot = _make_snapshot(trigger_type=None)
        service, dao = _make_service()
        dao.create = AsyncMock(return_value=snapshot)

        await service.create(
            AsyncMock(),
            project_id=snapshot.project_id,
            repo_url="https://github.com/curl/curl",
            repo_name="curl",
            version="8.5.0",
            backend="svf",
        )

        kwargs = dao.create.call_args.kwargs
        assert kwargs["trigger_type"] is None


# ---------------------------------------------------------------------------
# get_active
# ---------------------------------------------------------------------------


class TestGetActive:
    async def test_get_active_exists(self):
        snapshot = _make_snapshot(is_active=True, status="completed")
        service, dao = _make_service()
        dao.get_active_by_project = AsyncMock(return_value=snapshot)

        session = AsyncMock()
        project_id = snapshot.project_id
        result = await service.get_active(session, project_id)

        assert result is snapshot
        dao.get_active_by_project.assert_awaited_once_with(session, project_id)

    async def test_get_active_none(self):
        service, dao = _make_service()
        dao.get_active_by_project = AsyncMock(return_value=None)

        result = await service.get_active(AsyncMock(), uuid.uuid4())

        assert result is None


# ---------------------------------------------------------------------------
# list_building
# ---------------------------------------------------------------------------


class TestListBuilding:
    async def test_list_building(self):
        snapshots = [_make_snapshot(), _make_snapshot()]
        service, dao = _make_service()
        dao.list_building = AsyncMock(return_value=snapshots)

        session = AsyncMock()
        result = await service.list_building(session)

        assert result == snapshots
        dao.list_building.assert_awaited_once_with(session)

    async def test_list_building_empty(self):
        service, dao = _make_service()
        dao.list_building = AsyncMock(return_value=[])

        result = await service.list_building(AsyncMock())

        assert result == []


# ---------------------------------------------------------------------------
# update_status
# ---------------------------------------------------------------------------


class TestUpdateStatus:
    async def test_update_status_minimal(self):
        service, dao = _make_service()
        dao.update_status = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.update_status(session, pk, status="completed")

        dao.update_status.assert_awaited_once_with(
            session,
            pk,
            status="completed",
            error=None,
            node_count=None,
            edge_count=None,
            analysis_duration_sec=None,
            storage_path=None,
            fuzzer_names=None,
            language=None,
            size_bytes=None,
        )

    async def test_update_status_with_metadata(self):
        service, dao = _make_service()
        dao.update_status = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.update_status(
            session,
            pk,
            status="completed",
            node_count=500,
            edge_count=2000,
            analysis_duration_sec=12.5,
            storage_path="/data/snapshots/abc",
            fuzzer_names=["fuzz_target_1"],
            language="c",
            size_bytes=1024000,
        )

        kwargs = dao.update_status.call_args.kwargs
        assert kwargs["node_count"] == 500
        assert kwargs["edge_count"] == 2000
        assert kwargs["language"] == "c"

    async def test_update_status_with_error(self):
        service, dao = _make_service()
        dao.update_status = AsyncMock()

        await service.update_status(
            AsyncMock(), uuid.uuid4(), status="building", error="SVF timeout"
        )

        kwargs = dao.update_status.call_args.kwargs
        assert kwargs["error"] == "SVF timeout"
        assert kwargs["status"] == "building"


# ---------------------------------------------------------------------------
# activate
# ---------------------------------------------------------------------------


class TestActivate:
    async def test_activate(self):
        service, dao = _make_service()
        dao.activate = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.activate(session, pk)

        dao.activate.assert_awaited_once_with(session, pk)

    async def test_activate_not_found(self):
        service, dao = _make_service()
        dao.activate = AsyncMock(side_effect=ValueError("Snapshot xxx not found"))

        with pytest.raises(ValueError, match="not found"):
            await service.activate(AsyncMock(), uuid.uuid4())
