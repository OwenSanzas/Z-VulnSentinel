"""Tests for ProjectDAO."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from vulnsentinel.dao.project_dao import ProjectDAO


@pytest.fixture
def dao():
    return ProjectDAO()


def _proj(name: str, **overrides) -> dict:
    """Helper to build project kwargs with sensible defaults."""
    defaults = {
        "name": name,
        "repo_url": f"https://github.com/org/{name}",
    }
    defaults.update(overrides)
    return defaults


# ── create ────────────────────────────────────────────────────────────────


class TestCreate:
    async def test_create_minimal(self, dao, session):
        """Create with only required fields; server defaults should fill the rest."""
        proj = await dao.create(session, **_proj("my-app"))
        assert proj.name == "my-app"
        assert proj.repo_url == "https://github.com/org/my-app"
        assert proj.platform == "github"
        assert proj.default_branch == "main"
        assert proj.id is not None
        assert proj.created_at is not None
        assert proj.monitoring_since is not None
        # optional fields default to None
        assert proj.organization is None
        assert proj.contact is None
        assert proj.current_version is None
        assert proj.last_update_at is None

    async def test_create_with_all_fields(self, dao, session):
        proj = await dao.create(
            session,
            name="full-app",
            repo_url="https://gitlab.com/org/full-app",
            platform="gitlab",
            default_branch="develop",
            organization="Acme Corp",
            contact="admin@acme.com",
            current_version="2.1.0",
        )
        assert proj.organization == "Acme Corp"
        assert proj.contact == "admin@acme.com"
        assert proj.current_version == "2.1.0"
        assert proj.platform == "gitlab"
        assert proj.default_branch == "develop"

    async def test_create_duplicate_repo_url_raises(self, dao, session):
        """repo_url is unique — duplicate must raise IntegrityError."""
        await dao.create(session, **_proj("app1"))
        with pytest.raises(IntegrityError):
            await dao.create(
                session,
                name="app2",
                repo_url="https://github.com/org/app1",  # same repo_url
            )

    async def test_create_same_name_different_repo_ok(self, dao, session):
        """name is NOT unique — two projects can share a name."""
        p1 = await dao.create(session, **_proj("shared-name", repo_url="https://github.com/a/r1"))
        p2 = await dao.create(session, **_proj("shared-name", repo_url="https://github.com/b/r2"))
        assert p1.id != p2.id
        assert p1.name == p2.name


# ── get_by_id ─────────────────────────────────────────────────────────────


class TestGetById:
    async def test_found(self, dao, session):
        proj = await dao.create(session, **_proj("find-me"))
        found = await dao.get_by_id(session, proj.id)
        assert found is not None
        assert found.name == "find-me"

    async def test_not_found(self, dao, session):
        assert await dao.get_by_id(session, uuid.uuid4()) is None


# ── list_paginated ────────────────────────────────────────────────────────


class TestListPaginated:
    async def test_empty(self, dao, session):
        page = await dao.list_paginated(session)
        assert page.data == []
        assert page.has_more is False

    async def test_returns_all_within_page(self, dao, session):
        for i in range(3):
            await dao.create(session, **_proj(f"proj_{i}"))
        page = await dao.list_paginated(session, page_size=10)
        assert len(page.data) == 3
        assert page.has_more is False

    async def test_pagination_cursor(self, dao, session):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            proj = await dao.create(session, **_proj(f"pg_{i}"))
            proj.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        page1 = await dao.list_paginated(session, page_size=3)
        assert len(page1.data) == 3
        assert page1.has_more is True

        page2 = await dao.list_paginated(session, cursor=page1.next_cursor, page_size=3)
        assert len(page2.data) == 2
        assert page2.has_more is False

        ids1 = {p.id for p in page1.data}
        ids2 = {p.id for p in page2.data}
        assert ids1.isdisjoint(ids2)
        assert len(ids1 | ids2) == 5

    async def test_desc_ordering(self, dao, session):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(3):
            proj = await dao.create(session, **_proj(f"ord_{i}"))
            proj.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        page = await dao.list_paginated(session, page_size=10)
        timestamps = [p.created_at for p in page.data]
        assert timestamps == sorted(timestamps, reverse=True)


# ── count ─────────────────────────────────────────────────────────────────


class TestCount:
    async def test_count_empty(self, dao, session):
        assert await dao.count(session) == 0

    async def test_count(self, dao, session):
        for i in range(4):
            await dao.create(session, **_proj(f"cnt_{i}"))
        assert await dao.count(session) == 4


# ── inherited methods ─────────────────────────────────────────────────────


class TestInheritedMethods:
    async def test_update(self, dao, session):
        proj = await dao.create(session, **_proj("upd"))
        updated = await dao.update(session, proj.id, contact="new@acme.com")
        assert updated.contact == "new@acme.com"
        assert updated.name == "upd"  # unchanged

    async def test_delete(self, dao, session):
        proj = await dao.create(session, **_proj("del"))
        assert await dao.delete(session, proj.id) is True
        assert await dao.get_by_id(session, proj.id) is None

    async def test_exists(self, dao, session):
        proj = await dao.create(session, **_proj("exist"))
        assert await dao.exists(session, proj.id) is True
        await dao.delete(session, proj.id)
        assert await dao.exists(session, proj.id) is False

    async def test_get_by_field(self, dao, session):
        await dao.create(session, **_proj("field-test"))
        found = await dao.get_by_field(session, repo_url="https://github.com/org/field-test")
        assert found is not None
        assert found.name == "field-test"
