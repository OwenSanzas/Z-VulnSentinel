"""Tests for ClientVulnService."""

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from vulnsentinel.dao.base import Page
from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO, ClientVulnFilters
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.models.upstream_vuln import UpstreamVuln
from vulnsentinel.services import NotFoundError, ValidationError
from vulnsentinel.services.client_vuln_service import ClientVulnService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client_vuln(**overrides) -> ClientVuln:
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "upstream_vuln_id": uuid.uuid4(),
        "project_id": uuid.uuid4(),
        "status": "recorded",
        "pipeline_status": "verified",
        "is_affected": True,
        "constraint_expr": None,
        "constraint_source": None,
        "resolved_version": None,
        "fix_version": None,
        "verdict": None,
        "reachable_path": None,
        "poc_results": None,
        "error_message": None,
        "analysis_started_at": None,
        "analysis_completed_at": None,
        "recorded_at": None,
        "reported_at": None,
        "confirmed_at": None,
        "confirmed_msg": None,
        "fixed_at": None,
        "fixed_msg": None,
        "not_affect_at": None,
        "report": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return ClientVuln(**defaults)


def _make_upstream_vuln(**overrides) -> UpstreamVuln:
    defaults = {
        "id": uuid.uuid4(),
        "event_id": uuid.uuid4(),
        "library_id": uuid.uuid4(),
        "commit_sha": "abc123",
        "status": "published",
        "vuln_type": "buffer_overflow",
        "severity": "high",
        "affected_versions": "<8.5.0",
        "summary": "heap overflow",
        "reasoning": "bounds check missing",
        "upstream_poc": None,
        "error_message": None,
        "published_at": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return UpstreamVuln(**defaults)


def _make_service() -> tuple[ClientVulnService, ClientVulnDAO, UpstreamVulnDAO]:
    cv_dao = ClientVulnDAO()
    uv_dao = UpstreamVulnDAO()
    service = ClientVulnService(cv_dao, uv_dao)
    return service, cv_dao, uv_dao


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


class TestGet:
    async def test_get_success(self):
        uv = _make_upstream_vuln()
        cv = _make_client_vuln(upstream_vuln_id=uv.id)
        service, cv_dao, uv_dao = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)
        uv_dao.get_by_id = AsyncMock(return_value=uv)

        session = AsyncMock()
        result = await service.get(session, cv.id)

        assert result["client_vuln"] is cv
        assert result["upstream_vuln"] is uv
        cv_dao.get_by_id.assert_awaited_once_with(session, cv.id)
        uv_dao.get_by_id.assert_awaited_once_with(session, cv.upstream_vuln_id)

    async def test_get_not_found(self):
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundError, match="client vulnerability not found"):
            await service.get(AsyncMock(), uuid.uuid4())


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestList:
    async def test_list_all(self):
        vulns = [_make_client_vuln(), _make_client_vuln()]
        page = Page(data=vulns, next_cursor="abc", has_more=True)
        stats = {
            "total_recorded": 10,
            "total_reported": 5,
            "total_confirmed": 2,
            "total_fixed": 1,
        }

        service, cv_dao, _ = _make_service()
        cv_dao.list_paginated = AsyncMock(return_value=page)
        cv_dao.count = AsyncMock(return_value=50)
        cv_dao.count_by_status = AsyncMock(return_value=stats)

        session = AsyncMock()
        result = await service.list(session, page_size=2)

        assert result["data"] == vulns
        assert result["total"] == 50
        assert result["has_more"] is True
        assert result["stats"] == stats
        cv_dao.list_paginated.assert_awaited_once_with(session, None, 2, filters=None)
        cv_dao.count.assert_awaited_once_with(session, filters=None)
        cv_dao.count_by_status.assert_awaited_once_with(session, project_id=None)

    async def test_list_with_filters(self):
        filters = ClientVulnFilters(status="recorded", project_id=uuid.uuid4())
        page = Page(data=[_make_client_vuln()], next_cursor=None, has_more=False)
        stats = {
            "total_recorded": 1,
            "total_reported": 0,
            "total_confirmed": 0,
            "total_fixed": 0,
        }

        service, cv_dao, _ = _make_service()
        cv_dao.list_paginated = AsyncMock(return_value=page)
        cv_dao.count = AsyncMock(return_value=1)
        cv_dao.count_by_status = AsyncMock(return_value=stats)

        session = AsyncMock()
        result = await service.list(session, filters=filters)

        cv_dao.list_paginated.assert_awaited_once_with(session, None, 20, filters=filters)
        cv_dao.count.assert_awaited_once_with(session, filters=filters)
        cv_dao.count_by_status.assert_awaited_once_with(session, project_id=filters.project_id)
        assert result["stats"] == stats

    async def test_list_empty(self):
        page = Page(data=[], next_cursor=None, has_more=False)
        stats = {
            "total_recorded": 0,
            "total_reported": 0,
            "total_confirmed": 0,
            "total_fixed": 0,
        }

        service, cv_dao, _ = _make_service()
        cv_dao.list_paginated = AsyncMock(return_value=page)
        cv_dao.count = AsyncMock(return_value=0)
        cv_dao.count_by_status = AsyncMock(return_value=stats)

        result = await service.list(AsyncMock())

        assert result["data"] == []
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# list_by_project
# ---------------------------------------------------------------------------


class TestListByProject:
    async def test_list_by_project(self):
        vulns = [_make_client_vuln()]
        page = Page(data=vulns, next_cursor="xyz", has_more=True)

        service, cv_dao, _ = _make_service()
        cv_dao.list_by_project = AsyncMock(return_value=page)

        project_id = uuid.uuid4()
        session = AsyncMock()
        result = await service.list_by_project(session, project_id, page_size=10)

        assert result["data"] == vulns
        assert result["next_cursor"] == "xyz"
        assert result["has_more"] is True
        cv_dao.list_by_project.assert_awaited_once_with(session, project_id, None, 10)

    async def test_list_by_project_empty(self):
        page = Page(data=[], next_cursor=None, has_more=False)

        service, cv_dao, _ = _make_service()
        cv_dao.list_by_project = AsyncMock(return_value=page)

        result = await service.list_by_project(AsyncMock(), uuid.uuid4())

        assert result["data"] == []
        assert result["has_more"] is False


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------


class TestGetStats:
    async def test_get_stats_global(self):
        stats = {
            "total_recorded": 100,
            "total_reported": 60,
            "total_confirmed": 30,
            "total_fixed": 10,
        }
        service, cv_dao, _ = _make_service()
        cv_dao.count_by_status = AsyncMock(return_value=stats)

        result = await service.get_stats(AsyncMock())

        assert result == stats
        cv_dao.count_by_status.assert_awaited_once_with(
            cv_dao.count_by_status.call_args.args[0], project_id=None
        )

    async def test_get_stats_by_project(self):
        project_id = uuid.uuid4()
        stats = {
            "total_recorded": 5,
            "total_reported": 3,
            "total_confirmed": 1,
            "total_fixed": 0,
        }
        service, cv_dao, _ = _make_service()
        cv_dao.count_by_status = AsyncMock(return_value=stats)

        session = AsyncMock()
        result = await service.get_stats(session, project_id=project_id)

        assert result == stats
        cv_dao.count_by_status.assert_awaited_once_with(session, project_id=project_id)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


class TestCreate:
    async def test_create_minimal(self):
        cv = _make_client_vuln()
        service, cv_dao, _ = _make_service()
        cv_dao.create = AsyncMock(return_value=cv)

        session = AsyncMock()
        uv_id = uuid.uuid4()
        proj_id = uuid.uuid4()
        result = await service.create(session, upstream_vuln_id=uv_id, project_id=proj_id)

        assert result is cv
        cv_dao.create.assert_awaited_once_with(
            session,
            upstream_vuln_id=uv_id,
            project_id=proj_id,
            constraint_expr=None,
            constraint_source=None,
            resolved_version=None,
            fix_version=None,
            verdict=None,
        )

    async def test_create_with_version_info(self):
        cv = _make_client_vuln()
        service, cv_dao, _ = _make_service()
        cv_dao.create = AsyncMock(return_value=cv)

        await service.create(
            AsyncMock(),
            upstream_vuln_id=uuid.uuid4(),
            project_id=uuid.uuid4(),
            constraint_expr=">=7.0,<8.5",
            constraint_source="manifest",
            resolved_version="8.4.0",
            fix_version="8.5.0",
            verdict="affected",
        )

        kwargs = cv_dao.create.call_args.kwargs
        assert kwargs["constraint_expr"] == ">=7.0,<8.5"
        assert kwargs["resolved_version"] == "8.4.0"
        assert kwargs["verdict"] == "affected"


# ---------------------------------------------------------------------------
# list_pending_pipeline
# ---------------------------------------------------------------------------


class TestListPendingPipeline:
    async def test_list_pending_pipeline(self):
        vulns = [_make_client_vuln(pipeline_status="pending")]
        service, cv_dao, _ = _make_service()
        cv_dao.list_pending_pipeline = AsyncMock(return_value=vulns)

        session = AsyncMock()
        result = await service.list_pending_pipeline(session, limit=50)

        assert result == vulns
        cv_dao.list_pending_pipeline.assert_awaited_once_with(session, 50)


# ---------------------------------------------------------------------------
# update_pipeline
# ---------------------------------------------------------------------------


class TestUpdatePipeline:
    async def test_advance_to_path_searching(self):
        service, cv_dao, _ = _make_service()
        cv_dao.update_pipeline = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.update_pipeline(session, pk, pipeline_status="path_searching")

        cv_dao.update_pipeline.assert_awaited_once_with(
            session,
            pk,
            pipeline_status="path_searching",
            is_affected=None,
            reachable_path=None,
            poc_results=None,
            error_message=None,
            clear_error=False,
        )

    async def test_advance_with_reachable_path(self):
        service, cv_dao, _ = _make_service()
        cv_dao.update_pipeline = AsyncMock()

        path = {"entry": "main", "chain": ["main", "parse", "vuln_func"]}
        await service.update_pipeline(
            AsyncMock(),
            uuid.uuid4(),
            pipeline_status="poc_generating",
            reachable_path=path,
        )

        kwargs = cv_dao.update_pipeline.call_args.kwargs
        assert kwargs["reachable_path"] == path
        assert kwargs["pipeline_status"] == "poc_generating"

    async def test_set_error(self):
        service, cv_dao, _ = _make_service()
        cv_dao.update_pipeline = AsyncMock()

        await service.update_pipeline(
            AsyncMock(),
            uuid.uuid4(),
            pipeline_status="path_searching",
            error_message="graph store timeout",
        )

        kwargs = cv_dao.update_pipeline.call_args.kwargs
        assert kwargs["error_message"] == "graph store timeout"

    async def test_clear_error_on_retry(self):
        service, cv_dao, _ = _make_service()
        cv_dao.update_pipeline = AsyncMock()

        await service.update_pipeline(
            AsyncMock(),
            uuid.uuid4(),
            pipeline_status="path_searching",
            clear_error=True,
        )

        kwargs = cv_dao.update_pipeline.call_args.kwargs
        assert kwargs["clear_error"] is True
        assert kwargs["error_message"] is None


# ---------------------------------------------------------------------------
# finalize
# ---------------------------------------------------------------------------


class TestFinalize:
    async def test_finalize_affected(self):
        service, cv_dao, _ = _make_service()
        cv_dao.finalize = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.finalize(session, pk, is_affected=True)

        cv_dao.finalize.assert_awaited_once_with(
            session,
            pk,
            pipeline_status="verified",
            status="recorded",
            is_affected=True,
        )

    async def test_finalize_not_affected(self):
        service, cv_dao, _ = _make_service()
        cv_dao.finalize = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.finalize(session, pk, is_affected=False)

        cv_dao.finalize.assert_awaited_once_with(
            session,
            pk,
            pipeline_status="not_affect",
            status="not_affect",
            is_affected=False,
        )


# ---------------------------------------------------------------------------
# update_status (state transition validation)
# ---------------------------------------------------------------------------


class TestUpdateStatus:
    async def test_recorded_to_reported(self):
        cv = _make_client_vuln(status="recorded")
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)
        cv_dao.update_status = AsyncMock()

        session = AsyncMock()
        await service.update_status(session, cv.id, status="reported")

        cv_dao.update_status.assert_awaited_once_with(session, cv.id, status="reported", msg=None)

    async def test_reported_to_confirmed_with_msg(self):
        cv = _make_client_vuln(status="reported")
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)
        cv_dao.update_status = AsyncMock()

        session = AsyncMock()
        await service.update_status(
            session, cv.id, status="confirmed", msg="vendor confirmed via email"
        )

        cv_dao.update_status.assert_awaited_once_with(
            session, cv.id, status="confirmed", msg="vendor confirmed via email"
        )

    async def test_confirmed_to_fixed_with_msg(self):
        cv = _make_client_vuln(status="confirmed")
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)
        cv_dao.update_status = AsyncMock()

        await service.update_status(AsyncMock(), cv.id, status="fixed", msg="patched in v8.5.1")

        kwargs = cv_dao.update_status.call_args.kwargs
        assert kwargs["status"] == "fixed"
        assert kwargs["msg"] == "patched in v8.5.1"

    async def test_not_found(self):
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundError, match="client vulnerability not found"):
            await service.update_status(AsyncMock(), uuid.uuid4(), status="reported")

    async def test_terminal_status_fixed(self):
        """Cannot transition from 'fixed' (terminal)."""
        cv = _make_client_vuln(status="fixed")
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)

        with pytest.raises(ValidationError, match="terminal status"):
            await service.update_status(AsyncMock(), cv.id, status="confirmed")

    async def test_terminal_status_not_affect(self):
        """Cannot transition from 'not_affect' (terminal)."""
        cv = _make_client_vuln(status="not_affect")
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)

        with pytest.raises(ValidationError, match="terminal status"):
            await service.update_status(AsyncMock(), cv.id, status="reported")

    async def test_invalid_transition_recorded_to_confirmed(self):
        """recorded → confirmed is not allowed (must go through reported)."""
        cv = _make_client_vuln(status="recorded")
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)

        with pytest.raises(ValidationError, match="invalid transition"):
            await service.update_status(AsyncMock(), cv.id, status="confirmed")

    async def test_invalid_transition_recorded_to_fixed(self):
        """recorded → fixed is not allowed."""
        cv = _make_client_vuln(status="recorded")
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)

        with pytest.raises(ValidationError, match="invalid transition"):
            await service.update_status(AsyncMock(), cv.id, status="fixed")

    async def test_invalid_transition_reported_to_fixed(self):
        """reported → fixed is not allowed (must go through confirmed)."""
        cv = _make_client_vuln(status="reported")
        service, cv_dao, _ = _make_service()
        cv_dao.get_by_id = AsyncMock(return_value=cv)

        with pytest.raises(ValidationError, match="invalid transition"):
            await service.update_status(AsyncMock(), cv.id, status="fixed")
