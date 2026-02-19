"""Tests for EventDAO."""

from datetime import datetime, timedelta, timezone

import pytest

from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.models.upstream_vuln import UpstreamVuln


@pytest.fixture
def dao():
    return EventDAO()


@pytest.fixture
def lib_dao():
    return LibraryDAO()


@pytest.fixture
async def library(lib_dao, session):
    return await lib_dao.create(session, name="curl", repo_url="https://github.com/curl/curl")


@pytest.fixture
async def library2(lib_dao, session):
    return await lib_dao.create(
        session, name="openssl", repo_url="https://github.com/openssl/openssl"
    )


def _event(library_id, ref="abc123", **overrides) -> dict:
    defaults = {
        "library_id": library_id,
        "type": "commit",
        "ref": ref,
        "title": f"fix: some bug ({ref})",
    }
    defaults.update(overrides)
    return defaults


# ── create + get_by_id ────────────────────────────────────────────────────


class TestCreate:
    async def test_create_minimal(self, dao, session, library):
        ev = await dao.create(session, **_event(library.id))
        assert ev.id is not None
        assert ev.library_id == library.id
        assert ev.type == "commit"
        assert ev.classification is None
        assert ev.is_bugfix is False

    async def test_create_with_all_fields(self, dao, session, library):
        ev = await dao.create(
            session,
            library_id=library.id,
            type="pr_merge",
            ref="PR#42",
            title="fix: memory leak",
            message="Fixed a buffer overflow in parse_url",
            source_url="https://github.com/curl/curl/pull/42",
            author="dev@example.com",
            related_issue_ref="#100",
            related_issue_url="https://github.com/curl/curl/issues/100",
            related_pr_ref="PR#42",
            related_pr_url="https://github.com/curl/curl/pull/42",
            related_commit_sha="deadbeef",
        )
        assert ev.type == "pr_merge"
        assert ev.message == "Fixed a buffer overflow in parse_url"
        assert ev.related_issue_ref == "#100"

    async def test_get_by_id(self, dao, session, library):
        ev = await dao.create(session, **_event(library.id))
        found = await dao.get_by_id(session, ev.id)
        assert found is not None
        assert found.ref == "abc123"


# ── batch_create ──────────────────────────────────────────────────────────


class TestBatchCreate:
    async def test_insert_multiple(self, dao, session, library):
        events = [_event(library.id, f"ref_{i}") for i in range(3)]
        inserted = await dao.batch_create(session, events)
        assert inserted == 3

    async def test_empty_list(self, dao, session):
        assert await dao.batch_create(session, []) == 0

    async def test_skip_duplicates(self, dao, session, library):
        """ON CONFLICT DO NOTHING: duplicates should be silently skipped."""
        events = [_event(library.id, "dup_ref")]
        await dao.batch_create(session, events)

        # Same (library_id, type, ref) again
        inserted = await dao.batch_create(session, events)
        assert inserted == 0

    async def test_partial_insert(self, dao, session, library):
        """Mix of new and duplicate — only new rows inserted."""
        await dao.batch_create(session, [_event(library.id, "existing")])

        mixed = [
            _event(library.id, "existing"),  # dup
            _event(library.id, "new_one"),  # new
        ]
        inserted = await dao.batch_create(session, mixed)
        assert inserted == 1

    async def test_different_libraries_same_ref_ok(self, dao, session, library, library2):
        """Same ref but different library_id should both insert."""
        events = [
            _event(library.id, "same_ref"),
            _event(library2.id, "same_ref"),
        ]
        inserted = await dao.batch_create(session, events)
        assert inserted == 2

    async def test_different_types_same_ref_ok(self, dao, session, library):
        """Same (library_id, ref) but different type should both insert."""
        events = [
            _event(library.id, "ref1", type="commit"),
            _event(library.id, "ref1", type="tag", title="tag v1.0"),
        ]
        inserted = await dao.batch_create(session, events)
        assert inserted == 2


# ── list_paginated ────────────────────────────────────────────────────────


class TestListPaginated:
    async def test_empty(self, dao, session):
        page = await dao.list_paginated(session)
        assert page.data == []

    async def test_all_events(self, dao, session, library):
        for i in range(3):
            await dao.create(session, **_event(library.id, f"ref_{i}"))
        page = await dao.list_paginated(session, page_size=10)
        assert len(page.data) == 3

    async def test_filter_by_library(self, dao, session, library, library2):
        await dao.create(session, **_event(library.id, "ref_a"))
        await dao.create(session, **_event(library2.id, "ref_b"))

        page = await dao.list_paginated(session, library_id=library.id)
        assert len(page.data) == 1
        assert page.data[0].library_id == library.id

    async def test_pagination_cursor(self, dao, session, library):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            ev = await dao.create(session, **_event(library.id, f"pg_{i}"))
            ev.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        page1 = await dao.list_paginated(session, page_size=3)
        assert len(page1.data) == 3
        assert page1.has_more is True

        page2 = await dao.list_paginated(session, cursor_str=page1.next_cursor, page_size=3)
        assert len(page2.data) == 2
        assert page2.has_more is False

        ids1 = {e.id for e in page1.data}
        ids2 = {e.id for e in page2.data}
        assert ids1.isdisjoint(ids2)


# ── count ─────────────────────────────────────────────────────────────────


class TestCount:
    async def test_count_all(self, dao, session, library):
        for i in range(3):
            await dao.create(session, **_event(library.id, f"cnt_{i}"))
        assert await dao.count(session) == 3

    async def test_count_by_library(self, dao, session, library, library2):
        await dao.create(session, **_event(library.id, "a"))
        await dao.create(session, **_event(library.id, "b"))
        await dao.create(session, **_event(library2.id, "c"))

        assert await dao.count(session, library_id=library.id) == 2
        assert await dao.count(session, library_id=library2.id) == 1

    async def test_count_empty(self, dao, session):
        assert await dao.count(session) == 0


# ── list_unclassified ─────────────────────────────────────────────────────


class TestListUnclassified:
    async def test_returns_unclassified_only(self, dao, session, library):
        ev1 = await dao.create(session, **_event(library.id, "unclass"))
        ev2 = await dao.create(session, **_event(library.id, "classified"))
        await dao.update_classification(
            session,
            ev2.id,
            classification="feature",
            confidence=0.9,
            is_bugfix=False,
        )

        result = await dao.list_unclassified(session, limit=10)
        assert len(result) == 1
        assert result[0].id == ev1.id

    async def test_respects_limit(self, dao, session, library):
        for i in range(5):
            await dao.create(session, **_event(library.id, f"ul_{i}"))
        result = await dao.list_unclassified(session, limit=2)
        assert len(result) == 2

    async def test_ordered_by_created_at_desc(self, dao, session, library):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(3):
            ev = await dao.create(session, **_event(library.id, f"ord_{i}"))
            ev.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        result = await dao.list_unclassified(session, limit=10)
        timestamps = [e.created_at for e in result]
        assert timestamps == sorted(timestamps, reverse=True)

    async def test_empty(self, dao, session):
        result = await dao.list_unclassified(session, limit=10)
        assert result == []


# ── list_bugfix_without_vuln ──────────────────────────────────────────────


class TestListBugfixWithoutVuln:
    async def _make_bugfix(self, dao, session, library, ref):
        """Create a classified bugfix event."""
        ev = await dao.create(session, **_event(library.id, ref))
        await dao.update_classification(
            session,
            ev.id,
            classification="security_bugfix",
            confidence=0.95,
            is_bugfix=True,
        )
        await session.refresh(ev)
        return ev

    async def test_returns_bugfix_without_vuln(self, dao, session, library):
        ev = await self._make_bugfix(dao, session, library, "bf1")
        result = await dao.list_bugfix_without_vuln(session, limit=10)
        assert len(result) == 1
        assert result[0].id == ev.id

    async def test_excludes_bugfix_with_vuln(self, dao, session, library):
        """Bugfix that already has an upstream_vuln should be excluded."""
        ev = await self._make_bugfix(dao, session, library, "bf_with_vuln")

        # Create an upstream_vuln linked to this event
        vuln = UpstreamVuln(
            event_id=ev.id,
            library_id=library.id,
            commit_sha="abc123",
        )
        session.add(vuln)
        await session.flush()

        result = await dao.list_bugfix_without_vuln(session, limit=10)
        assert len(result) == 0

    async def test_excludes_non_bugfix(self, dao, session, library):
        """is_bugfix=False events should not appear."""
        await dao.create(session, **_event(library.id, "not_bugfix"))
        result = await dao.list_bugfix_without_vuln(session, limit=10)
        assert len(result) == 0

    async def test_mixed_scenario(self, dao, session, library):
        """Only bugfix events WITHOUT vuln should appear."""
        # bugfix without vuln → should appear
        ev1 = await self._make_bugfix(dao, session, library, "bf_no_vuln")

        # bugfix with vuln → should NOT appear
        ev2 = await self._make_bugfix(dao, session, library, "bf_has_vuln")
        vuln = UpstreamVuln(event_id=ev2.id, library_id=library.id, commit_sha="xyz")
        session.add(vuln)
        await session.flush()

        # non-bugfix → should NOT appear
        await dao.create(session, **_event(library.id, "feature_ev"))

        result = await dao.list_bugfix_without_vuln(session, limit=10)
        assert len(result) == 1
        assert result[0].id == ev1.id

    async def test_respects_limit(self, dao, session, library):
        for i in range(5):
            await self._make_bugfix(dao, session, library, f"bfl_{i}")
        result = await dao.list_bugfix_without_vuln(session, limit=2)
        assert len(result) == 2

    async def test_empty(self, dao, session):
        result = await dao.list_bugfix_without_vuln(session, limit=10)
        assert result == []


# ── update_classification ─────────────────────────────────────────────────


class TestUpdateClassification:
    async def test_update(self, dao, session, library):
        ev = await dao.create(session, **_event(library.id))
        await dao.update_classification(
            session,
            ev.id,
            classification="security_bugfix",
            confidence=0.92,
            is_bugfix=True,
        )
        await session.refresh(ev)
        assert ev.classification == "security_bugfix"
        assert ev.confidence == pytest.approx(0.92)
        assert ev.is_bugfix is True

    async def test_overwrite_classification(self, dao, session, library):
        """Re-classification should overwrite previous values."""
        ev = await dao.create(session, **_event(library.id))
        await dao.update_classification(
            session,
            ev.id,
            classification="feature",
            confidence=0.5,
            is_bugfix=False,
        )
        await dao.update_classification(
            session,
            ev.id,
            classification="normal_bugfix",
            confidence=0.85,
            is_bugfix=True,
        )
        await session.refresh(ev)
        assert ev.classification == "normal_bugfix"
        assert ev.confidence == pytest.approx(0.85)
        assert ev.is_bugfix is True

    async def test_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.update_classification(
                session,
                None,
                classification="other",
                confidence=0.1,
                is_bugfix=False,
            )
