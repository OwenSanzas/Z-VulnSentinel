"""Tests for UpstreamVulnService."""

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from vulnsentinel.dao.base import Page
from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.models.upstream_vuln import UpstreamVuln
from vulnsentinel.services import NotFoundError
from vulnsentinel.services.upstream_vuln_service import UpstreamVulnService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_upstream_vuln(**overrides) -> UpstreamVuln:
    defaults = {
        "id": uuid.uuid4(),
        "event_id": uuid.uuid4(),
        "library_id": uuid.uuid4(),
        "commit_sha": "abc123",
        "status": "analyzing",
        "vuln_type": None,
        "severity": None,
        "affected_versions": None,
        "summary": None,
        "reasoning": None,
        "upstream_poc": None,
        "error_message": None,
        "published_at": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return UpstreamVuln(**defaults)


def _make_client_vuln(**overrides) -> ClientVuln:
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "upstream_vuln_id": uuid.uuid4(),
        "project_id": uuid.uuid4(),
        "status": "recorded",
        "pipeline_status": "pending",
        "is_affected": None,
        "constraint_expr": None,
        "constraint_source": None,
        "resolved_version": None,
        "fix_version": None,
        "verdict": None,
        "reachable_path": None,
        "poc_results": None,
        "error_message": None,
        "analysis_completed_at": None,
        "recorded_at": None,
        "reported_at": None,
        "confirmed_at": None,
        "confirmed_msg": None,
        "fixed_at": None,
        "fixed_msg": None,
        "not_affect_at": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return ClientVuln(**defaults)


def _make_service() -> tuple[UpstreamVulnService, UpstreamVulnDAO, ClientVulnDAO]:
    uv_dao = UpstreamVulnDAO()
    cv_dao = ClientVulnDAO()
    service = UpstreamVulnService(uv_dao, cv_dao)
    return service, uv_dao, cv_dao


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


class TestGet:
    async def test_get_with_client_impact(self):
        vuln = _make_upstream_vuln(status="published")
        cv = _make_client_vuln(upstream_vuln_id=vuln.id)
        service, uv_dao, cv_dao = _make_service()
        uv_dao.get_by_id = AsyncMock(return_value=vuln)
        cv_dao.list_by_upstream_vuln = AsyncMock(return_value=[cv])

        session = AsyncMock()
        result = await service.get(session, vuln.id)

        assert result["vuln"] is vuln
        assert result["client_impact"] == [cv]
        uv_dao.get_by_id.assert_awaited_once_with(session, vuln.id)
        cv_dao.list_by_upstream_vuln.assert_awaited_once_with(session, vuln.id)

    async def test_get_no_client_impact(self):
        vuln = _make_upstream_vuln()
        service, uv_dao, cv_dao = _make_service()
        uv_dao.get_by_id = AsyncMock(return_value=vuln)
        cv_dao.list_by_upstream_vuln = AsyncMock(return_value=[])

        result = await service.get(AsyncMock(), vuln.id)

        assert result["vuln"] is vuln
        assert result["client_impact"] == []

    async def test_get_not_found(self):
        service, uv_dao, _ = _make_service()
        uv_dao.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundError, match="upstream vulnerability not found"):
            await service.get(AsyncMock(), uuid.uuid4())


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestList:
    async def test_list_all(self):
        vulns = [_make_upstream_vuln(), _make_upstream_vuln()]
        page = Page(data=vulns, next_cursor="abc", has_more=True)

        service, uv_dao, _ = _make_service()
        uv_dao.list_paginated = AsyncMock(return_value=page)
        uv_dao.count = AsyncMock(return_value=50)

        session = AsyncMock()
        result = await service.list(session, page_size=2)

        assert result["data"] == vulns
        assert result["total"] == 50
        assert result["has_more"] is True
        uv_dao.list_paginated.assert_awaited_once_with(session, None, 2, library_id=None)
        uv_dao.count.assert_awaited_once_with(session, library_id=None)

    async def test_list_by_library(self):
        lib_id = uuid.uuid4()
        page = Page(data=[_make_upstream_vuln()], next_cursor=None, has_more=False)

        service, uv_dao, _ = _make_service()
        uv_dao.list_paginated = AsyncMock(return_value=page)
        uv_dao.count = AsyncMock(return_value=1)

        session = AsyncMock()
        result = await service.list(session, library_id=lib_id)

        uv_dao.list_paginated.assert_awaited_once_with(session, None, 20, library_id=lib_id)
        uv_dao.count.assert_awaited_once_with(session, library_id=lib_id)
        assert result["total"] == 1

    async def test_list_empty(self):
        page = Page(data=[], next_cursor=None, has_more=False)

        service, uv_dao, _ = _make_service()
        uv_dao.list_paginated = AsyncMock(return_value=page)
        uv_dao.count = AsyncMock(return_value=0)

        result = await service.list(AsyncMock())

        assert result["data"] == []
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# count
# ---------------------------------------------------------------------------


class TestCount:
    async def test_count_all(self):
        service, uv_dao, _ = _make_service()
        uv_dao.count = AsyncMock(return_value=100)

        assert await service.count(AsyncMock()) == 100

    async def test_count_by_library(self):
        lib_id = uuid.uuid4()
        service, uv_dao, _ = _make_service()
        uv_dao.count = AsyncMock(return_value=5)

        session = AsyncMock()
        result = await service.count(session, library_id=lib_id)

        assert result == 5
        uv_dao.count.assert_awaited_once_with(session, library_id=lib_id)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


class TestCreate:
    async def test_create(self):
        vuln = _make_upstream_vuln()
        service, uv_dao, _ = _make_service()
        uv_dao.create = AsyncMock(return_value=vuln)

        session = AsyncMock()
        event_id = uuid.uuid4()
        lib_id = uuid.uuid4()
        result = await service.create(
            session, event_id=event_id, library_id=lib_id, commit_sha="deadbeef"
        )

        assert result is vuln
        uv_dao.create.assert_awaited_once_with(
            session, event_id=event_id, library_id=lib_id, commit_sha="deadbeef"
        )


# ---------------------------------------------------------------------------
# update_analysis
# ---------------------------------------------------------------------------


class TestUpdateAnalysis:
    async def test_update_analysis_minimal(self):
        service, uv_dao, _ = _make_service()
        uv_dao.update_analysis = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.update_analysis(
            session,
            pk,
            vuln_type="buffer_overflow",
            severity="high",
            affected_versions="<8.5.0",
            summary="heap buffer overflow in curl_easy_perform",
            reasoning="The commit fixes a bounds check ...",
        )

        uv_dao.update_analysis.assert_awaited_once_with(
            session,
            pk,
            vuln_type="buffer_overflow",
            severity="high",
            affected_versions="<8.5.0",
            summary="heap buffer overflow in curl_easy_perform",
            reasoning="The commit fixes a bounds check ...",
            upstream_poc=None,
        )

    async def test_update_analysis_with_poc(self):
        service, uv_dao, _ = _make_service()
        uv_dao.update_analysis = AsyncMock()

        poc = {"steps": ["compile", "run"], "crash_input": "AAAA"}
        await service.update_analysis(
            AsyncMock(),
            uuid.uuid4(),
            vuln_type="use_after_free",
            severity="critical",
            affected_versions="<2.0",
            summary="UAF in parser",
            reasoning="The free() call ...",
            upstream_poc=poc,
        )

        kwargs = uv_dao.update_analysis.call_args.kwargs
        assert kwargs["upstream_poc"] == poc
        assert kwargs["severity"] == "critical"


# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------


class TestPublish:
    async def test_publish(self):
        service, uv_dao, _ = _make_service()
        uv_dao.publish = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.publish(session, pk)

        uv_dao.publish.assert_awaited_once_with(session, pk)


# ---------------------------------------------------------------------------
# set_error
# ---------------------------------------------------------------------------


class TestSetError:
    async def test_set_error(self):
        service, uv_dao, _ = _make_service()
        uv_dao.set_error = AsyncMock()

        session = AsyncMock()
        pk = uuid.uuid4()
        await service.set_error(session, pk, "LLM timeout after 30s")

        uv_dao.set_error.assert_awaited_once_with(session, pk, "LLM timeout after 30s")
