"""Tests for LibraryService."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from vulnsentinel.dao.base import Page
from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.library_dao import LibraryConflictError, LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.models.library import Library
from vulnsentinel.models.project import Project
from vulnsentinel.models.project_dependency import ProjectDependency
from vulnsentinel.services import ConflictError, NotFoundError
from vulnsentinel.services.library_service import LibraryService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_library(**overrides) -> Library:
    defaults = {
        "id": uuid.uuid4(),
        "name": "curl",
        "repo_url": "https://github.com/curl/curl",
        "platform": "github",
        "ecosystem": "c_cpp",
        "default_branch": "master",
        "latest_tag_version": None,
        "latest_commit_sha": None,
        "monitoring_since": datetime.now(timezone.utc),
        "last_scanned_at": None,
        "collect_status": "healthy",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return Library(**defaults)


def _make_project(**overrides) -> Project:
    defaults = {
        "id": uuid.uuid4(),
        "name": "my-project",
        "organization": None,
        "repo_url": "https://github.com/org/my-project",
        "platform": "github",
        "default_branch": "main",
        "contact": None,
        "current_version": None,
        "monitoring_since": datetime.now(timezone.utc),
        "last_update_at": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return Project(**defaults)


def _make_dep(**overrides) -> ProjectDependency:
    defaults = {
        "id": uuid.uuid4(),
        "project_id": uuid.uuid4(),
        "library_id": uuid.uuid4(),
        "constraint_expr": ">=7.80",
        "resolved_version": "8.5.0",
        "constraint_source": "manifest",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return ProjectDependency(**defaults)


def _make_service() -> tuple[
    LibraryService, LibraryDAO, ProjectDAO, ProjectDependencyDAO, EventDAO
]:
    lib_dao = LibraryDAO()
    proj_dao = ProjectDAO()
    dep_dao = ProjectDependencyDAO()
    event_dao = EventDAO()
    service = LibraryService(lib_dao, proj_dao, dep_dao, event_dao)
    return service, lib_dao, proj_dao, dep_dao, event_dao


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


class TestGet:
    async def test_get_success(self):
        lib = _make_library()
        project = _make_project(name="my-app")
        dep = _make_dep(library_id=lib.id, project_id=project.id)
        service, lib_dao, proj_dao, dep_dao, event_dao = _make_service()

        lib_dao.get_by_id = AsyncMock(return_value=lib)
        dep_dao.list_by_library = AsyncMock(return_value=[dep])
        proj_dao.get_by_id = AsyncMock(return_value=project)
        event_dao.count = AsyncMock(return_value=42)

        session = AsyncMock()
        result = await service.get(session, lib.id)

        assert result["library"] is lib
        assert len(result["used_by"]) == 1
        assert result["used_by"][0]["project_id"] == project.id
        assert result["used_by"][0]["project_name"] == "my-app"
        assert result["used_by"][0]["constraint_expr"] == ">=7.80"
        assert result["used_by"][0]["resolved_version"] == "8.5.0"
        assert result["used_by"][0]["constraint_source"] == "manifest"
        assert result["events_tracked"] == 42

    async def test_get_not_found(self):
        service, lib_dao, _, _, _ = _make_service()
        lib_dao.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundError, match="library not found"):
            await service.get(AsyncMock(), uuid.uuid4())

    async def test_get_no_deps_no_events(self):
        lib = _make_library()
        service, lib_dao, _, dep_dao, event_dao = _make_service()

        lib_dao.get_by_id = AsyncMock(return_value=lib)
        dep_dao.list_by_library = AsyncMock(return_value=[])
        event_dao.count = AsyncMock(return_value=0)

        result = await service.get(AsyncMock(), lib.id)

        assert result["used_by"] == []
        assert result["events_tracked"] == 0

    async def test_get_multiple_deps(self):
        lib = _make_library()
        proj_a = _make_project(name="app-a")
        proj_b = _make_project(name="app-b")
        dep_a = _make_dep(library_id=lib.id, project_id=proj_a.id)
        dep_b = _make_dep(library_id=lib.id, project_id=proj_b.id)
        service, lib_dao, proj_dao, dep_dao, event_dao = _make_service()

        lib_dao.get_by_id = AsyncMock(return_value=lib)
        dep_dao.list_by_library = AsyncMock(return_value=[dep_a, dep_b])
        proj_dao.get_by_id = AsyncMock(
            side_effect=lambda _s, pk: {
                proj_a.id: proj_a,
                proj_b.id: proj_b,
            }[pk]
        )
        event_dao.count = AsyncMock(return_value=5)

        result = await service.get(AsyncMock(), lib.id)

        assert len(result["used_by"]) == 2
        names = [u["project_name"] for u in result["used_by"]]
        assert "app-a" in names
        assert "app-b" in names

    async def test_get_dep_with_deleted_project(self):
        """If a project was deleted, project_name should be None."""
        lib = _make_library()
        dep = _make_dep(library_id=lib.id)
        service, lib_dao, proj_dao, dep_dao, event_dao = _make_service()

        lib_dao.get_by_id = AsyncMock(return_value=lib)
        dep_dao.list_by_library = AsyncMock(return_value=[dep])
        proj_dao.get_by_id = AsyncMock(return_value=None)
        event_dao.count = AsyncMock(return_value=0)

        result = await service.get(AsyncMock(), lib.id)

        assert result["used_by"][0]["project_name"] is None


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestList:
    async def test_list_first_page(self):
        libs = [_make_library(name=f"lib-{i}") for i in range(3)]
        used_by = {libs[0].id: 2}

        service, lib_dao, _, _, _ = _make_service()
        lib_dao.list_offset = AsyncMock(return_value=(libs, used_by, 10))

        session = AsyncMock()
        result = await service.list(session, page=0, page_size=3)

        assert result["data"] == libs
        assert result["used_by_counts"] == used_by
        assert result["page"] == 0
        assert result["total"] == 10

        lib_dao.list_offset.assert_awaited_once_with(
            session, page=0, page_size=3, sort_by="name", sort_dir="asc", status=None, ecosystem=None
        )

    async def test_list_empty(self):
        service, lib_dao, _, _, _ = _make_service()
        lib_dao.list_offset = AsyncMock(return_value=([], {}, 0))

        result = await service.list(AsyncMock())

        assert result["data"] == []
        assert result["total"] == 0

    async def test_list_with_sort_and_filter(self):
        libs = [_make_library()]
        service, lib_dao, _, _, _ = _make_service()
        lib_dao.list_offset = AsyncMock(return_value=(libs, {}, 1))

        session = AsyncMock()
        await service.list(session, sort_by="platform", sort_dir="desc", status="unhealthy")

        lib_dao.list_offset.assert_awaited_once_with(
            session, page=0, page_size=20, sort_by="platform", sort_dir="desc", status="unhealthy", ecosystem=None
        )


# ---------------------------------------------------------------------------
# count
# ---------------------------------------------------------------------------


class TestCount:
    async def test_count(self):
        service, lib_dao, _, _, _ = _make_service()
        lib_dao.count = AsyncMock(return_value=7)

        session = AsyncMock()
        result = await service.count(session)

        assert result == 7
        lib_dao.count.assert_awaited_once_with(session)


# ---------------------------------------------------------------------------
# upsert
# ---------------------------------------------------------------------------


class TestUpsert:
    async def test_upsert_new_library(self):
        lib = _make_library()
        service, lib_dao, _, _, _ = _make_service()
        lib_dao.upsert_by_name = AsyncMock(return_value=lib)

        session = AsyncMock()
        result = await service.upsert(session, name="curl", repo_url="https://github.com/curl/curl")

        assert result is lib
        lib_dao.upsert_by_name.assert_awaited_once_with(
            session,
            name="curl",
            repo_url="https://github.com/curl/curl",
            platform="github",
            default_branch="main",
            ecosystem="c_cpp",
        )

    async def test_upsert_existing_same_repo(self):
        """Upserting with same name and same repo_url returns existing."""
        lib = _make_library()
        service, lib_dao, _, _, _ = _make_service()
        lib_dao.upsert_by_name = AsyncMock(return_value=lib)

        result = await service.upsert(
            AsyncMock(), name="curl", repo_url="https://github.com/curl/curl"
        )

        assert result is lib

    async def test_upsert_conflict_different_repo(self):
        """Upserting same name but different repo_url raises ConflictError."""
        service, lib_dao, _, _, _ = _make_service()
        lib_dao.upsert_by_name = AsyncMock(
            side_effect=LibraryConflictError("Library 'curl' already exists with repo_url...")
        )

        with pytest.raises(ConflictError, match="curl"):
            await service.upsert(AsyncMock(), name="curl", repo_url="https://github.com/fork/curl")

    async def test_upsert_custom_platform_and_branch(self):
        lib = _make_library(platform="gitlab", default_branch="develop")
        service, lib_dao, _, _, _ = _make_service()
        lib_dao.upsert_by_name = AsyncMock(return_value=lib)

        session = AsyncMock()
        await service.upsert(
            session,
            name="curl",
            repo_url="https://gitlab.com/curl/curl",
            platform="gitlab",
            default_branch="develop",
        )

        lib_dao.upsert_by_name.assert_awaited_once_with(
            session,
            name="curl",
            repo_url="https://gitlab.com/curl/curl",
            platform="gitlab",
            default_branch="develop",
            ecosystem="c_cpp",
        )
