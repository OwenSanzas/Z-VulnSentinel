"""Tests for UpstreamVulnDAO."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO


@pytest.fixture
def dao():
    return UpstreamVulnDAO()


@pytest.fixture
def lib_dao():
    return LibraryDAO()


@pytest.fixture
def ev_dao():
    return EventDAO()


@pytest.fixture
async def library(lib_dao, session):
    return await lib_dao.create(session, name="curl", repo_url="https://github.com/curl/curl")


@pytest.fixture
async def library2(lib_dao, session):
    return await lib_dao.create(
        session, name="openssl", repo_url="https://github.com/openssl/openssl"
    )


@pytest.fixture
async def event(ev_dao, session, library):
    return await ev_dao.create(
        session,
        library_id=library.id,
        type="commit",
        ref="abc123",
        title="fix: buffer overflow",
    )


@pytest.fixture
async def event2(ev_dao, session, library):
    return await ev_dao.create(
        session,
        library_id=library.id,
        type="commit",
        ref="def456",
        title="fix: use after free",
    )


@pytest.fixture
async def event_lib2(ev_dao, session, library2):
    return await ev_dao.create(
        session,
        library_id=library2.id,
        type="commit",
        ref="xyz789",
        title="fix: timing attack",
    )


def _vuln(event_id, library_id, commit_sha="abc123", **overrides) -> dict:
    defaults = {
        "event_id": event_id,
        "library_id": library_id,
        "commit_sha": commit_sha,
    }
    defaults.update(overrides)
    return defaults


# ── create + get_by_id ────────────────────────────────────────────────────


class TestCreate:
    async def test_create_with_defaults(self, dao, session, event, library):
        vuln = await dao.create(session, **_vuln(event.id, library.id))
        assert vuln.id is not None
        assert vuln.event_id == event.id
        assert vuln.library_id == library.id
        assert vuln.status == "analyzing"
        assert vuln.vuln_type is None
        assert vuln.severity is None
        assert vuln.error_message is None
        assert vuln.published_at is None
        assert vuln.detected_at is not None

    async def test_get_by_id(self, dao, session, event, library):
        vuln = await dao.create(session, **_vuln(event.id, library.id))
        found = await dao.get_by_id(session, vuln.id)
        assert found is not None
        assert found.commit_sha == "abc123"

    async def test_get_by_id_not_found(self, dao, session):
        assert await dao.get_by_id(session, uuid.uuid4()) is None


# ── list_paginated ────────────────────────────────────────────────────────


class TestListPaginated:
    async def test_empty(self, dao, session):
        page = await dao.list_paginated(session)
        assert page.data == []

    async def test_all_vulns(self, dao, session, event, event2, library):
        await dao.create(session, **_vuln(event.id, library.id, "sha1"))
        await dao.create(session, **_vuln(event2.id, library.id, "sha2"))
        page = await dao.list_paginated(session, page_size=10)
        assert len(page.data) == 2

    async def test_filter_by_library(self, dao, session, event, event_lib2, library, library2):
        await dao.create(session, **_vuln(event.id, library.id))
        await dao.create(session, **_vuln(event_lib2.id, library2.id, "xyz789"))

        page = await dao.list_paginated(session, library_id=library.id)
        assert len(page.data) == 1
        assert page.data[0].library_id == library.id

    async def test_pagination_cursor(self, dao, session, library, ev_dao):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            ev = await ev_dao.create(
                session,
                library_id=library.id,
                type="commit",
                ref=f"pgref_{i}",
                title=f"fix #{i}",
            )
            vuln = await dao.create(session, **_vuln(ev.id, library.id, f"sha_{i}"))
            vuln.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        page1 = await dao.list_paginated(session, page_size=3)
        assert len(page1.data) == 3
        assert page1.has_more is True

        page2 = await dao.list_paginated(session, cursor=page1.next_cursor, page_size=3)
        assert len(page2.data) == 2
        assert page2.has_more is False

        ids1 = {v.id for v in page1.data}
        ids2 = {v.id for v in page2.data}
        assert ids1.isdisjoint(ids2)


# ── count ─────────────────────────────────────────────────────────────────


class TestCount:
    async def test_count_all(self, dao, session, event, event2, library):
        await dao.create(session, **_vuln(event.id, library.id, "s1"))
        await dao.create(session, **_vuln(event2.id, library.id, "s2"))
        assert await dao.count(session) == 2

    async def test_count_by_library(self, dao, session, event, event_lib2, library, library2):
        await dao.create(session, **_vuln(event.id, library.id))
        await dao.create(session, **_vuln(event_lib2.id, library2.id, "x"))
        assert await dao.count(session, library_id=library.id) == 1
        assert await dao.count(session, library_id=library2.id) == 1

    async def test_count_empty(self, dao, session):
        assert await dao.count(session) == 0


# ── list_by_event ─────────────────────────────────────────────────────────


class TestListByEvent:
    async def test_returns_vulns_for_event(self, dao, session, event, library):
        await dao.create(session, **_vuln(event.id, library.id))
        result = await dao.list_by_event(session, event.id)
        assert len(result) == 1
        assert result[0].event_id == event.id

    async def test_empty(self, dao, session, event):
        result = await dao.list_by_event(session, event.id)
        assert result == []

    async def test_does_not_return_other_events(self, dao, session, event, event2, library):
        await dao.create(session, **_vuln(event.id, library.id, "s1"))
        await dao.create(session, **_vuln(event2.id, library.id, "s2"))
        result = await dao.list_by_event(session, event.id)
        assert len(result) == 1
        assert result[0].event_id == event.id


# ── update_analysis ───────────────────────────────────────────────────────


class TestUpdateAnalysis:
    async def test_update_all_fields(self, dao, session, event, library):
        vuln = await dao.create(session, **_vuln(event.id, library.id))
        await dao.update_analysis(
            session,
            vuln.id,
            vuln_type="buffer_overflow",
            severity="high",
            affected_versions="<7.89.0",
            summary="Heap buffer overflow in URL parser",
            reasoning="The commit fixes an unchecked memcpy in parse_url()",
            upstream_poc={"type": "curl_command", "value": "curl -x ..."},
        )
        await session.refresh(vuln)

        assert vuln.vuln_type == "buffer_overflow"
        assert vuln.severity == "high"
        assert vuln.affected_versions == "<7.89.0"
        assert vuln.summary == "Heap buffer overflow in URL parser"
        assert vuln.reasoning == "The commit fixes an unchecked memcpy in parse_url()"
        assert vuln.upstream_poc == {"type": "curl_command", "value": "curl -x ..."}

    async def test_update_without_poc(self, dao, session, event, library):
        """upstream_poc is optional — omitting it should not set it."""
        vuln = await dao.create(session, **_vuln(event.id, library.id))
        await dao.update_analysis(
            session,
            vuln.id,
            vuln_type="use_after_free",
            severity="critical",
            affected_versions="<3.0",
            summary="UAF in TLS handshake",
            reasoning="Double free in ssl_connect()",
        )
        await session.refresh(vuln)
        assert vuln.upstream_poc is None
        assert vuln.vuln_type == "use_after_free"

    async def test_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.update_analysis(
                session,
                None,
                vuln_type="x",
                severity="low",
                affected_versions="x",
                summary="x",
                reasoning="x",
            )


# ── publish ───────────────────────────────────────────────────────────────


class TestPublish:
    async def test_publish_sets_status_and_timestamp(self, dao, session, event, library):
        vuln = await dao.create(session, **_vuln(event.id, library.id))
        assert vuln.status == "analyzing"
        assert vuln.published_at is None

        await dao.publish(session, vuln.id)
        await session.refresh(vuln)

        assert vuln.status == "published"
        assert vuln.published_at is not None

    async def test_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.publish(session, None)


# ── set_error ─────────────────────────────────────────────────────────────


class TestSetError:
    async def test_set_error(self, dao, session, event, library):
        vuln = await dao.create(session, **_vuln(event.id, library.id))
        await dao.set_error(session, vuln.id, "LLM timeout after 30s")
        await session.refresh(vuln)
        assert vuln.error_message == "LLM timeout after 30s"

    async def test_overwrite_error(self, dao, session, event, library):
        vuln = await dao.create(session, **_vuln(event.id, library.id))
        await dao.set_error(session, vuln.id, "first error")
        await dao.set_error(session, vuln.id, "second error")
        await session.refresh(vuln)
        assert vuln.error_message == "second error"

    async def test_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.set_error(session, None, "err")
