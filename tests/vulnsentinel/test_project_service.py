"""Tests for ProjectService."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from vulnsentinel.dao.base import Page
from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.models.library import Library
from vulnsentinel.models.project import Project
from vulnsentinel.services import NotFoundError
from vulnsentinel.services.library_service import LibraryService
from vulnsentinel.services.project_service import DependencyInput, ProjectService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_project(**overrides) -> Project:
    defaults = {
        "id": uuid.uuid4(),
        "name": "my-project",
        "organization": "acme",
        "repo_url": "https://github.com/acme/my-project",
        "platform": "github",
        "default_branch": "main",
        "contact": "dev@acme.com",
        "current_version": None,
        "monitoring_since": datetime.now(timezone.utc),
        "last_update_at": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return Project(**defaults)


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


def _make_service() -> tuple[
    ProjectService, ProjectDAO, ProjectDependencyDAO, ClientVulnDAO, LibraryService
]:
    proj_dao = ProjectDAO()
    dep_dao = ProjectDependencyDAO()
    cv_dao = ClientVulnDAO()
    lib_service = LibraryService.__new__(LibraryService)
    service = ProjectService(proj_dao, dep_dao, cv_dao, lib_service)
    return service, proj_dao, dep_dao, cv_dao, lib_service


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


class TestGet:
    async def test_get_success(self):
        project = _make_project()
        service, proj_dao, dep_dao, cv_dao, _ = _make_service()

        proj_dao.get_by_id = AsyncMock(return_value=project)
        dep_dao.count_by_project = AsyncMock(return_value=3)
        cv_dao.active_count_by_project = AsyncMock(return_value=2)

        session = AsyncMock()
        result = await service.get(session, project.id)

        assert result["project"] is project
        assert result["deps_count"] == 3
        assert result["vuln_count"] == 2
        proj_dao.get_by_id.assert_awaited_once_with(session, project.id)
        dep_dao.count_by_project.assert_awaited_once_with(session, project.id)
        cv_dao.active_count_by_project.assert_awaited_once_with(session, project.id)

    async def test_get_not_found(self):
        service, proj_dao, _, _, _ = _make_service()
        proj_dao.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(NotFoundError, match="project not found"):
            await service.get(AsyncMock(), uuid.uuid4())

    async def test_get_zero_counts(self):
        project = _make_project()
        service, proj_dao, dep_dao, cv_dao, _ = _make_service()

        proj_dao.get_by_id = AsyncMock(return_value=project)
        dep_dao.count_by_project = AsyncMock(return_value=0)
        cv_dao.active_count_by_project = AsyncMock(return_value=0)

        result = await service.get(AsyncMock(), project.id)

        assert result["deps_count"] == 0
        assert result["vuln_count"] == 0


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestList:
    async def test_list_with_counts(self):
        projects = [_make_project(name=f"proj-{i}") for i in range(2)]
        page = Page(data=projects, next_cursor="abc", has_more=True)

        service, proj_dao, dep_dao, cv_dao, _ = _make_service()
        proj_dao.list_paginated = AsyncMock(return_value=page)
        proj_dao.count = AsyncMock(return_value=5)
        proj_dao.batch_counts = AsyncMock(
            return_value={p.id: {"deps_count": 3, "vuln_count": 1} for p in projects}
        )

        session = AsyncMock()
        result = await service.list(session, cursor=None, page_size=2)

        assert len(result["data"]) == 2
        assert result["data"][0]["deps_count"] == 3
        assert result["data"][0]["vuln_count"] == 1
        assert result["next_cursor"] == "abc"
        assert result["has_more"] is True
        assert result["total"] == 5

    async def test_list_empty(self):
        page = Page(data=[], next_cursor=None, has_more=False)

        service, proj_dao, _, _, _ = _make_service()
        proj_dao.list_paginated = AsyncMock(return_value=page)
        proj_dao.count = AsyncMock(return_value=0)
        proj_dao.batch_counts = AsyncMock(return_value={})

        result = await service.list(AsyncMock())

        assert result["data"] == []
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# count
# ---------------------------------------------------------------------------


class TestCount:
    async def test_count(self):
        service, proj_dao, _, _, _ = _make_service()
        proj_dao.count = AsyncMock(return_value=42)

        session = AsyncMock()
        result = await service.count(session)

        assert result == 42


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


class TestCreate:
    async def test_create_with_dependencies(self):
        project = _make_project()
        lib_curl = _make_library(name="curl")
        lib_zlib = _make_library(name="zlib", repo_url="https://github.com/madler/zlib")

        service, proj_dao, dep_dao, _, lib_service = _make_service()
        proj_dao.get_by_field = AsyncMock(return_value=None)
        proj_dao.create = AsyncMock(return_value=project)
        dep_dao.batch_upsert = AsyncMock(return_value=[])

        # LibraryService.upsert returns different libraries per call
        lib_service.upsert = AsyncMock(side_effect=[lib_curl, lib_zlib])

        session = AsyncMock()
        deps = [
            DependencyInput(
                library_name="curl",
                library_repo_url="https://github.com/curl/curl",
                constraint_expr=">=7.80",
                resolved_version="8.5.0",
            ),
            DependencyInput(
                library_name="zlib",
                library_repo_url="https://github.com/madler/zlib",
                constraint_expr=">=1.2",
                resolved_version="1.3.1",
            ),
        ]

        result = await service.create(
            session,
            name="my-project",
            repo_url="https://github.com/acme/my-project",
            organization="acme",
            dependencies=deps,
        )

        assert result is project

        # Verify project created
        proj_dao.create.assert_awaited_once()
        create_kwargs = proj_dao.create.call_args.kwargs
        assert create_kwargs["name"] == "my-project"
        assert create_kwargs["organization"] == "acme"

        # Verify library upserts
        assert lib_service.upsert.await_count == 2

        # Verify batch_upsert called with correct dep rows
        dep_dao.batch_upsert.assert_awaited_once()
        dep_rows = dep_dao.batch_upsert.call_args.args[1]
        assert len(dep_rows) == 2
        assert dep_rows[0]["project_id"] == project.id
        assert dep_rows[0]["library_id"] == lib_curl.id
        assert dep_rows[0]["constraint_expr"] == ">=7.80"
        assert dep_rows[1]["library_id"] == lib_zlib.id
        assert dep_rows[1]["constraint_expr"] == ">=1.2"

    async def test_create_without_dependencies(self):
        project = _make_project()
        service, proj_dao, dep_dao, _, _ = _make_service()
        proj_dao.get_by_field = AsyncMock(return_value=None)
        proj_dao.create = AsyncMock(return_value=project)
        dep_dao.batch_upsert = AsyncMock()

        result = await service.create(
            AsyncMock(),
            name="my-project",
            repo_url="https://github.com/acme/my-project",
        )

        assert result is project
        dep_dao.batch_upsert.assert_not_awaited()

    async def test_create_empty_dependencies_list(self):
        project = _make_project()
        service, proj_dao, dep_dao, _, _ = _make_service()
        proj_dao.get_by_field = AsyncMock(return_value=None)
        proj_dao.create = AsyncMock(return_value=project)
        dep_dao.batch_upsert = AsyncMock()

        result = await service.create(
            AsyncMock(),
            name="my-project",
            repo_url="https://github.com/acme/my-project",
            dependencies=[],
        )

        assert result is project
        dep_dao.batch_upsert.assert_not_awaited()

    async def test_create_passes_all_project_fields(self):
        project = _make_project()
        service, proj_dao, _, _, _ = _make_service()
        proj_dao.get_by_field = AsyncMock(return_value=None)
        proj_dao.create = AsyncMock(return_value=project)

        await service.create(
            AsyncMock(),
            name="my-project",
            repo_url="https://github.com/acme/my-project",
            organization="acme",
            contact="dev@acme.com",
            platform="gitlab",
            default_branch="develop",
        )

        kwargs = proj_dao.create.call_args.kwargs
        assert kwargs["name"] == "my-project"
        assert kwargs["repo_url"] == "https://github.com/acme/my-project"
        assert kwargs["organization"] == "acme"
        assert kwargs["contact"] == "dev@acme.com"
        assert kwargs["platform"] == "gitlab"
        assert kwargs["default_branch"] == "develop"

    async def test_create_dependency_input_defaults(self):
        """DependencyInput should have sensible defaults."""
        dep = DependencyInput(
            library_name="curl",
            library_repo_url="https://github.com/curl/curl",
        )
        assert dep.constraint_expr is None
        assert dep.resolved_version is None
        assert dep.platform == "github"
        assert dep.default_branch == "main"
