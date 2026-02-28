"""Tests for LibraryDAO."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from vulnsentinel.dao.library_dao import LibraryConflictError, LibraryDAO
from vulnsentinel.models.library import Library


@pytest.fixture
def dao():
    return LibraryDAO()


def _lib(name: str, **overrides) -> dict:
    """Helper to build library kwargs with sensible defaults."""
    defaults = {
        "name": name,
        "repo_url": f"https://github.com/org/{name}",
        "platform": "github",
        "default_branch": "main",
    }
    defaults.update(overrides)
    return defaults


# ── list_paginated ────────────────────────────────────────────────────────


class TestListPaginated:
    async def test_empty(self, dao, session):
        page = await dao.list_paginated(session)
        assert page.data == []
        assert page.has_more is False
        assert page.next_cursor is None

    async def test_returns_all_within_page(self, dao, session):
        for i in range(3):
            await dao.create(session, **_lib(f"lib_{i}"))
        page = await dao.list_paginated(session, page_size=10)
        assert len(page.data) == 3
        assert page.has_more is False

    async def test_pagination_cursor(self, dao, session):
        """Two pages should cover all rows with no overlap."""
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            lib = await dao.create(session, **_lib(f"pg_{i}"))
            lib.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        page1 = await dao.list_paginated(session, page_size=3)
        assert len(page1.data) == 3
        assert page1.has_more is True

        page2 = await dao.list_paginated(session, cursor=page1.next_cursor, page_size=3)
        assert len(page2.data) == 2
        assert page2.has_more is False

        ids1 = {lib.id for lib in page1.data}
        ids2 = {lib.id for lib in page2.data}
        assert ids1.isdisjoint(ids2)
        assert len(ids1 | ids2) == 5

    async def test_desc_ordering(self, dao, session):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(3):
            lib = await dao.create(session, **_lib(f"ord_{i}"))
            lib.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        page = await dao.list_paginated(session, page_size=10)
        timestamps = [lib.created_at for lib in page.data]
        assert timestamps == sorted(timestamps, reverse=True)


# ── get_all_monitored ─────────────────────────────────────────────────────


class TestGetAllMonitored:
    async def test_empty(self, dao, session):
        result = await dao.get_all_monitored(session)
        assert result == []

    async def test_returns_all_ordered_by_name(self, dao, session):
        for name in ["curl", "libpng", "abseil"]:
            await dao.create(session, **_lib(name))

        result = await dao.get_all_monitored(session)
        assert len(result) == 3
        names = [lib.name for lib in result]
        assert names == ["abseil", "curl", "libpng"]

    async def test_returns_library_objects(self, dao, session):
        await dao.create(session, **_lib("mylib"))
        result = await dao.get_all_monitored(session)
        assert isinstance(result[0], Library)
        assert result[0].name == "mylib"


# ── upsert_by_name ───────────────────────────────────────────────────────


class TestUpsertByName:
    async def test_insert_new(self, dao, session):
        lib = await dao.upsert_by_name(
            session,
            name="newlib",
            repo_url="https://github.com/org/newlib",
        )
        assert lib.name == "newlib"
        assert lib.repo_url == "https://github.com/org/newlib"
        assert lib.platform == "github"
        assert lib.default_branch == "main"
        assert lib.id is not None

    async def test_upsert_same_name_same_repo_returns_original(self, dao, session):
        """Idempotent: same name + same repo_url returns existing row."""
        lib1 = await dao.upsert_by_name(
            session,
            name="mylib",
            repo_url="https://github.com/org/mylib",
        )
        lib2 = await dao.upsert_by_name(
            session,
            name="mylib",
            repo_url="https://github.com/org/mylib",
        )
        assert lib2.id == lib1.id
        assert lib2.repo_url == "https://github.com/org/mylib"

    async def test_upsert_same_name_different_repo_raises(self, dao, session):
        """Same name but different repo_url must raise LibraryConflictError."""
        await dao.upsert_by_name(
            session, name="conflict", repo_url="https://github.com/org/conflict"
        )
        with pytest.raises(LibraryConflictError, match="already exists"):
            await dao.upsert_by_name(
                session, name="conflict", repo_url="https://github.com/org/other"
            )

    async def test_upsert_conflict_does_not_create_duplicate(self, dao, session):
        """After a conflict error, only one row should exist."""
        await dao.upsert_by_name(session, name="dup", repo_url="https://github.com/org/dup")
        with pytest.raises(LibraryConflictError):
            await dao.upsert_by_name(session, name="dup", repo_url="https://github.com/org/dup-v2")
        total = await dao.count(session)
        assert total == 1

    async def test_upsert_idempotent_does_not_create_duplicate(self, dao, session):
        """Repeated upsert with identical data should still be one row."""
        await dao.upsert_by_name(session, name="idem", repo_url="https://github.com/org/idem")
        await dao.upsert_by_name(session, name="idem", repo_url="https://github.com/org/idem")
        total = await dao.count(session)
        assert total == 1

    async def test_upsert_different_names_both_created(self, dao, session):
        l1 = await dao.upsert_by_name(session, name="lib_a", repo_url="https://github.com/org/a")
        l2 = await dao.upsert_by_name(session, name="lib_b", repo_url="https://github.com/org/b")
        assert l1.id != l2.id
        assert await dao.count(session) == 2

    async def test_upsert_default_platform_and_branch(self, dao, session):
        lib = await dao.upsert_by_name(
            session, name="defaults", repo_url="https://github.com/org/defaults"
        )
        assert lib.platform == "github"
        assert lib.default_branch == "main"


# ── update_pointers ───────────────────────────────────────────────────────


class TestUpdatePointers:
    async def test_update_all_pointers(self, dao, session):
        lib = await dao.create(session, **_lib("ptr_all"))
        now = datetime.now(timezone.utc)

        await dao.update_pointers(
            session,
            lib.id,
            latest_commit_sha="abc123",
            latest_tag_version="v1.0.0",
            last_scanned_at=now,
        )
        await session.refresh(lib)

        assert lib.latest_commit_sha == "abc123"
        assert lib.latest_tag_version == "v1.0.0"
        assert lib.last_scanned_at == now

    async def test_update_partial_pointers(self, dao, session):
        """Only the provided pointers should change; others stay None."""
        lib = await dao.create(session, **_lib("ptr_partial"))

        await dao.update_pointers(session, lib.id, latest_commit_sha="def456")
        await session.refresh(lib)

        assert lib.latest_commit_sha == "def456"
        assert lib.latest_tag_version is None
        assert lib.last_scanned_at is None

    async def test_update_preserves_existing_values(self, dao, session):
        """COALESCE: None param should not overwrite existing value."""
        lib = await dao.create(session, **_lib("ptr_preserve"))
        now = datetime.now(timezone.utc)

        # First update: set all
        await dao.update_pointers(
            session,
            lib.id,
            latest_commit_sha="first",
            latest_tag_version="v1.0",
            last_scanned_at=now,
        )
        # Second update: only commit_sha, others None
        await dao.update_pointers(session, lib.id, latest_commit_sha="second")
        await session.refresh(lib)

        assert lib.latest_commit_sha == "second"
        assert lib.latest_tag_version == "v1.0"  # preserved
        assert lib.last_scanned_at == now  # preserved

    async def test_update_pointers_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.update_pointers(session, None, latest_commit_sha="x")

    async def test_update_pointers_nonexistent_pk_is_noop(self, dao, session):
        """Updating a non-existent library should silently do nothing."""
        fake_id = uuid.uuid4()
        await dao.update_pointers(session, fake_id, latest_commit_sha="ghost")
        # No row exists — just verify no exception
        result = await dao.get_by_id(session, fake_id)
        assert result is None


# ── inherited BaseDAO methods ─────────────────────────────────────────────


class TestInheritedMethods:
    async def test_get_by_id(self, dao, session):
        lib = await dao.create(session, **_lib("inherit"))
        found = await dao.get_by_id(session, lib.id)
        assert found is not None
        assert found.name == "inherit"

    async def test_delete(self, dao, session):
        lib = await dao.create(session, **_lib("to_delete"))
        assert await dao.delete(session, lib.id) is True
        assert await dao.get_by_id(session, lib.id) is None

    async def test_count(self, dao, session):
        for i in range(3):
            await dao.create(session, **_lib(f"cnt_{i}"))
        assert await dao.count(session) == 3

    async def test_exists(self, dao, session):
        lib = await dao.create(session, **_lib("exist_test"))
        assert await dao.exists(session, lib.id) is True
        await dao.delete(session, lib.id)
        assert await dao.exists(session, lib.id) is False

    async def test_get_by_field(self, dao, session):
        await dao.create(session, **_lib("findme"))
        found = await dao.get_by_field(session, name="findme")
        assert found is not None
        assert found.repo_url == "https://github.com/org/findme"

    async def test_server_defaults(self, dao, session):
        """platform, default_branch, monitoring_since should have defaults."""
        lib = await dao.create(
            session,
            name="defaults_test",
            repo_url="https://github.com/org/defaults_test",
        )
        assert lib.platform == "github"
        assert lib.default_branch == "main"
        assert lib.monitoring_since is not None
