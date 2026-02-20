"""Tests for EventService."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from vulnsentinel.dao.base import Page
from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.models.event import Event
from vulnsentinel.models.upstream_vuln import UpstreamVuln
from vulnsentinel.services import NotFoundError
from vulnsentinel.services.event_service import EventService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides) -> Event:
    defaults = {
        "id": uuid.uuid4(),
        "library_id": uuid.uuid4(),
        "type": "commit",
        "ref": "abc123",
        "source_url": None,
        "author": "dev",
        "title": "fix buffer overflow",
        "message": None,
        "related_issue_ref": None,
        "related_issue_url": None,
        "related_pr_ref": None,
        "related_pr_url": None,
        "related_commit_sha": None,
        "classification": None,
        "confidence": None,
        "is_bugfix": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return Event(**defaults)


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


def _make_service() -> tuple[EventService, EventDAO, UpstreamVulnDAO]:
    event_dao = EventDAO()
    uv_dao = UpstreamVulnDAO()
    service = EventService(event_dao, uv_dao)
    return service, event_dao, uv_dao


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


class TestGet:
    async def test_get_non_bugfix(self):
        event = _make_event(is_bugfix=False)
        service, event_dao, uv_dao = _make_service()
        event_dao.get_by_id = AsyncMock(return_value=event)
        uv_dao.list_by_event = AsyncMock()

        session = AsyncMock()
        result = await service.get(session, event.id)

        assert result["event"] is event
        assert result["related_vulns"] == []
        uv_dao.list_by_event.assert_not_awaited()

    async def test_get_bugfix_with_vulns(self):
        event = _make_event(is_bugfix=True)
        vuln = _make_upstream_vuln(event_id=event.id)
        service, event_dao, uv_dao = _make_service()
        event_dao.get_by_id = AsyncMock(return_value=event)
        uv_dao.list_by_event = AsyncMock(return_value=[vuln])

        session = AsyncMock()
        result = await service.get(session, event.id)

        assert result["event"] is event
        assert result["related_vulns"] == [vuln]
        uv_dao.list_by_event.assert_awaited_once_with(session, event.id)

    async def test_get_not_found(self):
        service, event_dao, _ = _make_service()
        event_dao.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundError, match="event not found"):
            await service.get(AsyncMock(), uuid.uuid4())


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestList:
    async def test_list_all(self):
        events = [_make_event(), _make_event()]
        page = Page(data=events, next_cursor="abc", has_more=True)

        service, event_dao, _ = _make_service()
        event_dao.list_paginated = AsyncMock(return_value=page)
        event_dao.count = AsyncMock(return_value=50)

        session = AsyncMock()
        result = await service.list(session, page_size=2)

        assert result["data"] == events
        assert result["total"] == 50
        assert result["has_more"] is True
        event_dao.list_paginated.assert_awaited_once_with(session, None, 2, library_id=None)
        event_dao.count.assert_awaited_once_with(session, library_id=None)

    async def test_list_by_library(self):
        lib_id = uuid.uuid4()
        page = Page(data=[_make_event()], next_cursor=None, has_more=False)

        service, event_dao, _ = _make_service()
        event_dao.list_paginated = AsyncMock(return_value=page)
        event_dao.count = AsyncMock(return_value=1)

        session = AsyncMock()
        result = await service.list(session, library_id=lib_id)

        event_dao.list_paginated.assert_awaited_once_with(session, None, 20, library_id=lib_id)
        event_dao.count.assert_awaited_once_with(session, library_id=lib_id)
        assert result["total"] == 1

    async def test_list_empty(self):
        page = Page(data=[], next_cursor=None, has_more=False)

        service, event_dao, _ = _make_service()
        event_dao.list_paginated = AsyncMock(return_value=page)
        event_dao.count = AsyncMock(return_value=0)

        result = await service.list(AsyncMock())

        assert result["data"] == []
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# count
# ---------------------------------------------------------------------------


class TestCount:
    async def test_count_all(self):
        service, event_dao, _ = _make_service()
        event_dao.count = AsyncMock(return_value=100)

        assert await service.count(AsyncMock()) == 100

    async def test_count_by_library(self):
        lib_id = uuid.uuid4()
        service, event_dao, _ = _make_service()
        event_dao.count = AsyncMock(return_value=5)

        session = AsyncMock()
        result = await service.count(session, library_id=lib_id)

        assert result == 5
        event_dao.count.assert_awaited_once_with(session, library_id=lib_id)


# ---------------------------------------------------------------------------
# batch_create
# ---------------------------------------------------------------------------


class TestBatchCreate:
    async def test_batch_create(self):
        service, event_dao, _ = _make_service()
        event_dao.batch_create = AsyncMock(return_value=3)

        events = [
            {"library_id": uuid.uuid4(), "type": "commit", "ref": "abc", "title": "fix 1"},
            {"library_id": uuid.uuid4(), "type": "commit", "ref": "def", "title": "fix 2"},
            {"library_id": uuid.uuid4(), "type": "tag", "ref": "v1.0", "title": "release"},
        ]

        session = AsyncMock()
        result = await service.batch_create(session, events)

        assert result == 3
        event_dao.batch_create.assert_awaited_once_with(session, events)

    async def test_batch_create_empty(self):
        service, event_dao, _ = _make_service()
        event_dao.batch_create = AsyncMock(return_value=0)

        result = await service.batch_create(AsyncMock(), [])

        assert result == 0


# ---------------------------------------------------------------------------
# list_unclassified
# ---------------------------------------------------------------------------


class TestListUnclassified:
    async def test_list_unclassified(self):
        events = [_make_event(), _make_event()]
        service, event_dao, _ = _make_service()
        event_dao.list_unclassified = AsyncMock(return_value=events)

        session = AsyncMock()
        result = await service.list_unclassified(session, limit=50)

        assert result == events
        event_dao.list_unclassified.assert_awaited_once_with(session, 50)


# ---------------------------------------------------------------------------
# list_bugfix_without_vuln
# ---------------------------------------------------------------------------


class TestListBugfixWithoutVuln:
    async def test_list_bugfix_without_vuln(self):
        events = [_make_event(is_bugfix=True)]
        service, event_dao, _ = _make_service()
        event_dao.list_bugfix_without_vuln = AsyncMock(return_value=events)

        session = AsyncMock()
        result = await service.list_bugfix_without_vuln(session, limit=20)

        assert result == events
        event_dao.list_bugfix_without_vuln.assert_awaited_once_with(session, 20)


# ---------------------------------------------------------------------------
# update_classification
# ---------------------------------------------------------------------------


class TestUpdateClassification:
    async def test_security_bugfix(self):
        """security_bugfix classification should set is_bugfix=True."""
        service, event_dao, _ = _make_service()
        event_dao.update_classification = AsyncMock()

        session = AsyncMock()
        event_id = uuid.uuid4()
        await service.update_classification(
            session, event_id, classification="security_bugfix", confidence=0.95
        )

        event_dao.update_classification.assert_awaited_once_with(
            session,
            event_id,
            classification="security_bugfix",
            confidence=0.95,
            is_bugfix=True,
        )

    async def test_normal_bugfix(self):
        """normal_bugfix should NOT set is_bugfix=True."""
        service, event_dao, _ = _make_service()
        event_dao.update_classification = AsyncMock()

        await service.update_classification(
            AsyncMock(), uuid.uuid4(), classification="normal_bugfix", confidence=0.8
        )

        kwargs = event_dao.update_classification.call_args.kwargs
        assert kwargs["is_bugfix"] is False

    async def test_refactor(self):
        service, event_dao, _ = _make_service()
        event_dao.update_classification = AsyncMock()

        await service.update_classification(
            AsyncMock(), uuid.uuid4(), classification="refactor", confidence=0.7
        )

        kwargs = event_dao.update_classification.call_args.kwargs
        assert kwargs["is_bugfix"] is False

    async def test_feature(self):
        service, event_dao, _ = _make_service()
        event_dao.update_classification = AsyncMock()

        await service.update_classification(
            AsyncMock(), uuid.uuid4(), classification="feature", confidence=0.9
        )

        kwargs = event_dao.update_classification.call_args.kwargs
        assert kwargs["is_bugfix"] is False

    async def test_other(self):
        service, event_dao, _ = _make_service()
        event_dao.update_classification = AsyncMock()

        await service.update_classification(
            AsyncMock(), uuid.uuid4(), classification="other", confidence=0.5
        )

        kwargs = event_dao.update_classification.call_args.kwargs
        assert kwargs["is_bugfix"] is False
