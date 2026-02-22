"""Tests for ProjectDependencyDAO."""

from datetime import datetime, timedelta, timezone

import pytest

from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO


@pytest.fixture
def dao():
    return ProjectDependencyDAO()


@pytest.fixture
def lib_dao():
    return LibraryDAO()


@pytest.fixture
def proj_dao():
    return ProjectDAO()


@pytest.fixture
async def library(lib_dao, session):
    """Create a library for FK references."""
    return await lib_dao.create(session, name="curl", repo_url="https://github.com/curl/curl")


@pytest.fixture
async def library2(lib_dao, session):
    return await lib_dao.create(
        session, name="openssl", repo_url="https://github.com/openssl/openssl"
    )


@pytest.fixture
async def library3(lib_dao, session):
    return await lib_dao.create(
        session, name="libpng", repo_url="https://github.com/pnggroup/libpng"
    )


@pytest.fixture
async def project(proj_dao, session):
    """Create a project for FK references."""
    return await proj_dao.create(session, name="my-app", repo_url="https://github.com/org/my-app")


@pytest.fixture
async def project2(proj_dao, session):
    return await proj_dao.create(
        session, name="other-app", repo_url="https://github.com/org/other-app"
    )


# ── batch_upsert ─────────────────────────────────────────────────────────


class TestBatchUpsert:
    async def test_insert_single(self, dao, session, project, library):
        deps = [
            {
                "project_id": project.id,
                "library_id": library.id,
                "constraint_expr": ">=7.0",
                "resolved_version": "7.88.1",
                "constraint_source": "requirements.txt",
            }
        ]
        result = await dao.batch_upsert(session, deps)
        assert len(result) == 1
        assert result[0].project_id == project.id
        assert result[0].library_id == library.id
        assert result[0].constraint_expr == ">=7.0"
        assert result[0].resolved_version == "7.88.1"

    async def test_insert_multiple(self, dao, session, project, library, library2):
        deps = [
            {
                "project_id": project.id,
                "library_id": library.id,
                "constraint_expr": ">=7.0",
                "resolved_version": "7.88.1",
            },
            {
                "project_id": project.id,
                "library_id": library2.id,
                "constraint_expr": ">=3.0",
                "resolved_version": "3.1.0",
            },
        ]
        result = await dao.batch_upsert(session, deps)
        assert len(result) == 2

    async def test_empty_list(self, dao, session):
        result = await dao.batch_upsert(session, [])
        assert result == []

    async def test_upsert_updates_on_conflict(self, dao, session, project, library):
        """Same (project, library) should update constraint/version."""
        dep_v1 = {
            "project_id": project.id,
            "library_id": library.id,
            "constraint_expr": ">=7.0",
            "resolved_version": "7.88.1",
            "constraint_source": "requirements.txt",
        }
        await dao.batch_upsert(session, [dep_v1])

        dep_v2 = {
            "project_id": project.id,
            "library_id": library.id,
            "constraint_expr": ">=8.0",
            "resolved_version": "8.0.0",
            "constraint_source": "requirements.txt",
        }
        result = await dao.batch_upsert(session, [dep_v2])
        assert len(result) == 1
        assert result[0].constraint_expr == ">=8.0"
        assert result[0].resolved_version == "8.0.0"

    async def test_upsert_no_duplicate_rows(self, dao, session, project, library):
        """After upsert, still only one row for the same unique key."""
        dep = {
            "project_id": project.id,
            "library_id": library.id,
            "constraint_source": "go.mod",
        }
        await dao.batch_upsert(session, [dep])
        await dao.batch_upsert(session, [dep])

        count = await dao.count_by_project(session, project.id)
        assert count == 1

    async def test_upsert_preserves_manual_source(self, dao, session, project, library):
        """Existing manual record must keep constraint_source='manual' after scanner upsert."""
        manual_dep = {
            "project_id": project.id,
            "library_id": library.id,
            "constraint_expr": ">=7.0",
            "resolved_version": "7.88.1",
            "constraint_source": "manual",
        }
        await dao.batch_upsert(session, [manual_dep])

        scanner_dep = {
            "project_id": project.id,
            "library_id": library.id,
            "constraint_expr": ">=8.0",
            "resolved_version": "8.0.0",
            "constraint_source": "conanfile.txt",
        }
        result = await dao.batch_upsert(session, [scanner_dep])
        assert len(result) == 1
        assert result[0].constraint_source == "manual"
        # constraint_expr and resolved_version should still be updated
        assert result[0].constraint_expr == ">=8.0"
        assert result[0].resolved_version == "8.0.0"

    async def test_upsert_overwrites_scanner_source(self, dao, session, project, library):
        """Existing scanner record should have constraint_source updated."""
        scanner_dep_v1 = {
            "project_id": project.id,
            "library_id": library.id,
            "constraint_expr": ">=7.0",
            "resolved_version": "7.88.1",
            "constraint_source": "conanfile.txt",
        }
        await dao.batch_upsert(session, [scanner_dep_v1])

        scanner_dep_v2 = {
            "project_id": project.id,
            "library_id": library.id,
            "constraint_expr": ">=8.0",
            "resolved_version": "8.0.0",
            "constraint_source": "CMakeLists.txt",
        }
        result = await dao.batch_upsert(session, [scanner_dep_v2])
        assert len(result) == 1
        assert result[0].constraint_source == "CMakeLists.txt"
        assert result[0].constraint_expr == ">=8.0"


# ── delete_stale_scanner_deps ────────────────────────────────────────────


class TestDeleteStaleScannerDeps:
    async def test_deletes_non_manual_not_in_keep(
        self, dao, session, project, library, library2, library3
    ):
        """Should delete scanner deps not in keep list, preserve manual and kept."""
        deps = [
            {
                "project_id": project.id,
                "library_id": library.id,
                "constraint_source": "conanfile.txt",
            },
            {
                "project_id": project.id,
                "library_id": library2.id,
                "constraint_source": "manual",
            },
            {
                "project_id": project.id,
                "library_id": library3.id,
                "constraint_source": "CMakeLists.txt",
            },
        ]
        await dao.batch_upsert(session, deps)

        # Keep library (curl), stale: library3 (libpng), manual: library2 (openssl)
        deleted = await dao.delete_stale_scanner_deps(
            session, project.id, keep_library_ids={library.id}
        )
        assert deleted == 1  # only library3's scanner dep

        remaining = await dao.list_by_library(session, library.id)
        assert len(remaining) == 1  # curl kept

        manual_remaining = await dao.list_by_library(session, library2.id)
        assert len(manual_remaining) == 1  # openssl manual preserved

        stale_remaining = await dao.list_by_library(session, library3.id)
        assert len(stale_remaining) == 0  # libpng deleted

    async def test_empty_keep_deletes_all_scanner(self, dao, session, project, library, library2):
        """Empty keep set should delete all non-manual deps."""
        deps = [
            {
                "project_id": project.id,
                "library_id": library.id,
                "constraint_source": "conanfile.txt",
            },
            {
                "project_id": project.id,
                "library_id": library2.id,
                "constraint_source": "manual",
            },
        ]
        await dao.batch_upsert(session, deps)

        deleted = await dao.delete_stale_scanner_deps(session, project.id, keep_library_ids=set())
        assert deleted == 1  # only scanner dep deleted
        assert await dao.count_by_project(session, project.id) == 1  # manual remains

    async def test_does_not_affect_other_projects(self, dao, session, project, project2, library):
        """Deletion must be scoped to the given project_id."""
        deps = [
            {
                "project_id": project.id,
                "library_id": library.id,
                "constraint_source": "conanfile.txt",
            },
            {
                "project_id": project2.id,
                "library_id": library.id,
                "constraint_source": "conanfile.txt",
            },
        ]
        await dao.batch_upsert(session, deps)

        deleted = await dao.delete_stale_scanner_deps(session, project.id, keep_library_ids=set())
        assert deleted == 1
        # project2's dep untouched
        assert await dao.count_by_project(session, project2.id) == 1


# ── list_by_project ───────────────────────────────────────────────────────


class TestListByProject:
    async def test_empty(self, dao, session, project):
        page = await dao.list_by_project(session, project.id)
        assert page.data == []
        assert page.has_more is False

    async def test_returns_only_target_project(self, dao, session, project, project2, library):
        """Must not leak dependencies from another project."""
        await dao.batch_upsert(
            session,
            [
                {"project_id": project.id, "library_id": library.id},
                {"project_id": project2.id, "library_id": library.id},
            ],
        )
        page = await dao.list_by_project(session, project.id)
        assert len(page.data) == 1
        assert page.data[0].project_id == project.id

    async def test_pagination(self, dao, session, project, lib_dao):
        """Pagination should work with cursor."""
        libs = []
        for i in range(5):
            lib = await lib_dao.create(
                session, name=f"lib_{i}", repo_url=f"https://github.com/org/lib_{i}"
            )
            libs.append(lib)

        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        deps = []
        for i, lib in enumerate(libs):
            deps.append(
                {
                    "project_id": project.id,
                    "library_id": lib.id,
                }
            )
        created = await dao.batch_upsert(session, deps)
        # Set staggered created_at for deterministic ordering
        for i, dep in enumerate(created):
            dep.created_at = base_time + timedelta(minutes=i)
        await session.flush()

        page1 = await dao.list_by_project(session, project.id, page_size=3)
        assert len(page1.data) == 3
        assert page1.has_more is True

        page2 = await dao.list_by_project(
            session, project.id, cursor=page1.next_cursor, page_size=3
        )
        assert len(page2.data) == 2
        assert page2.has_more is False

        ids1 = {d.id for d in page1.data}
        ids2 = {d.id for d in page2.data}
        assert ids1.isdisjoint(ids2)


# ── list_by_library ───────────────────────────────────────────────────────


class TestListByLibrary:
    async def test_empty(self, dao, session, library):
        result = await dao.list_by_library(session, library.id)
        assert result == []

    async def test_returns_all_projects_using_library(
        self, dao, session, project, project2, library
    ):
        await dao.batch_upsert(
            session,
            [
                {"project_id": project.id, "library_id": library.id},
                {"project_id": project2.id, "library_id": library.id},
            ],
        )
        result = await dao.list_by_library(session, library.id)
        assert len(result) == 2
        project_ids = {r.project_id for r in result}
        assert project_ids == {project.id, project2.id}

    async def test_does_not_include_other_libraries(self, dao, session, project, library, library2):
        await dao.batch_upsert(
            session,
            [
                {"project_id": project.id, "library_id": library.id},
                {"project_id": project.id, "library_id": library2.id},
            ],
        )
        result = await dao.list_by_library(session, library.id)
        assert len(result) == 1
        assert result[0].library_id == library.id


# ── count_by_project ─────────────────────────────────────────────────────


class TestCountByProject:
    async def test_zero(self, dao, session, project):
        assert await dao.count_by_project(session, project.id) == 0

    async def test_counts_only_target_project(
        self, dao, session, project, project2, library, library2
    ):
        await dao.batch_upsert(
            session,
            [
                {"project_id": project.id, "library_id": library.id},
                {"project_id": project.id, "library_id": library2.id},
                {"project_id": project2.id, "library_id": library.id},
            ],
        )
        assert await dao.count_by_project(session, project.id) == 2
        assert await dao.count_by_project(session, project2.id) == 1
