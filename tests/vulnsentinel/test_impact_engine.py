"""Tests for the Impact Engine: assessor pure function, DAO polling, and runner."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO
from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.engines.impact_engine.assessor import ImpactResult, assess_impact
from vulnsentinel.engines.impact_engine.runner import ImpactRunner
from vulnsentinel.services.client_vuln_service import ClientVulnService
from vulnsentinel.services.upstream_vuln_service import UpstreamVulnService


# ── Helpers ──────────────────────────────────────────────────────────────────


def _mock_dep(project_id=None, constraint_expr="^1.0.0", resolved_version="1.2.3", constraint_source="scan"):
    """Create a mock ProjectDependency."""
    dep = MagicMock()
    dep.project_id = project_id or uuid.uuid4()
    dep.constraint_expr = constraint_expr
    dep.resolved_version = resolved_version
    dep.constraint_source = constraint_source
    return dep


# ── TestAssessImpact (pure function, no DB) ──────────────────────────────────


class TestAssessImpact:
    def test_returns_result_per_dependency(self):
        vuln_id = uuid.uuid4()
        deps = [_mock_dep(), _mock_dep(), _mock_dep()]

        results = assess_impact(vuln_id, deps)

        assert len(results) == 3
        assert all(isinstance(r, ImpactResult) for r in results)

    def test_copies_fields_from_dependency(self):
        vuln_id = uuid.uuid4()
        proj_id = uuid.uuid4()
        dep = _mock_dep(
            project_id=proj_id,
            constraint_expr=">=2.0",
            resolved_version="2.5.1",
            constraint_source="manifest",
        )

        results = assess_impact(vuln_id, [dep])

        assert len(results) == 1
        r = results[0]
        assert r.upstream_vuln_id == vuln_id
        assert r.project_id == proj_id
        assert r.constraint_expr == ">=2.0"
        assert r.resolved_version == "2.5.1"
        assert r.constraint_source == "manifest"

    def test_empty_dependencies_returns_empty(self):
        results = assess_impact(uuid.uuid4(), [])
        assert results == []

    def test_none_fields_preserved(self):
        dep = _mock_dep(constraint_expr=None, resolved_version=None, constraint_source=None)
        results = assess_impact(uuid.uuid4(), [dep])
        assert results[0].constraint_expr is None
        assert results[0].resolved_version is None
        assert results[0].constraint_source is None


# ── TestImpactResult ─────────────────────────────────────────────────────────


class TestImpactResult:
    def test_dataclass_fields(self):
        r = ImpactResult(
            upstream_vuln_id=uuid.uuid4(),
            project_id=uuid.uuid4(),
            constraint_expr="^1.0",
            resolved_version="1.5.0",
            constraint_source="scan",
        )
        assert r.upstream_vuln_id is not None
        assert r.project_id is not None


# ── DB integration fixtures ──────────────────────────────────────────────────


@pytest.fixture
def uv_dao():
    return UpstreamVulnDAO()


@pytest.fixture
def cv_dao():
    return ClientVulnDAO()


@pytest.fixture
def dep_dao():
    return ProjectDependencyDAO()


@pytest.fixture
def lib_dao():
    return LibraryDAO()


@pytest.fixture
def ev_dao():
    return EventDAO()


@pytest.fixture
def proj_dao():
    return ProjectDAO()


@pytest.fixture
async def library(lib_dao, session):
    return await lib_dao.create(session, name="curl", repo_url="https://github.com/curl/curl")


@pytest.fixture
async def library_no_deps(lib_dao, session):
    return await lib_dao.create(session, name="lonely", repo_url="https://github.com/x/lonely")


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
async def event_no_deps(ev_dao, session, library_no_deps):
    return await ev_dao.create(
        session,
        library_id=library_no_deps.id,
        type="commit",
        ref="nnn111",
        title="fix: lonely vuln",
    )


@pytest.fixture
async def project_a(proj_dao, session):
    return await proj_dao.create(session, name="project-a", repo_url="https://github.com/x/a")


@pytest.fixture
async def project_b(proj_dao, session):
    return await proj_dao.create(session, name="project-b", repo_url="https://github.com/x/b")


@pytest.fixture
async def dep_a(dep_dao, session, project_a, library):
    return await dep_dao.create(
        session,
        project_id=project_a.id,
        library_id=library.id,
        constraint_expr="^7.0",
        resolved_version="7.88.1",
        constraint_source="scan",
    )


@pytest.fixture
async def dep_b(dep_dao, session, project_b, library):
    return await dep_dao.create(
        session,
        project_id=project_b.id,
        library_id=library.id,
        constraint_expr=">=8.0",
        resolved_version="8.5.0",
        constraint_source="manifest",
    )


@pytest.fixture
async def published_vuln(uv_dao, session, event, library):
    vuln = await uv_dao.create(
        session,
        event_id=event.id,
        library_id=library.id,
        commit_sha="abc123",
    )
    await uv_dao.publish(session, vuln.id)
    return vuln


@pytest.fixture
async def published_vuln_no_deps(uv_dao, session, event_no_deps, library_no_deps):
    vuln = await uv_dao.create(
        session,
        event_id=event_no_deps.id,
        library_id=library_no_deps.id,
        commit_sha="nnn111",
    )
    await uv_dao.publish(session, vuln.id)
    return vuln


# ── TestListPublishedWithoutImpact (DB) ──────────────────────────────────────


class TestListPublishedWithoutImpact:
    @pytest.mark.anyio()
    async def test_returns_published_with_dependents(
        self, uv_dao, session, published_vuln, dep_a
    ):
        results = await uv_dao.list_published_without_impact(session)
        assert len(results) == 1
        assert results[0].id == published_vuln.id

    @pytest.mark.anyio()
    async def test_excludes_analyzing_status(
        self, uv_dao, session, event, library, dep_a
    ):
        # Create vuln but don't publish it
        await uv_dao.create(
            session,
            event_id=event.id,
            library_id=library.id,
            commit_sha="abc123",
        )
        results = await uv_dao.list_published_without_impact(session)
        assert len(results) == 0

    @pytest.mark.anyio()
    async def test_excludes_vuln_with_existing_client_vulns(
        self, uv_dao, cv_dao, session, published_vuln, dep_a, project_a
    ):
        # Create a client_vuln for this upstream_vuln
        await cv_dao.create(
            session,
            upstream_vuln_id=published_vuln.id,
            project_id=project_a.id,
        )
        results = await uv_dao.list_published_without_impact(session)
        assert len(results) == 0

    @pytest.mark.anyio()
    async def test_excludes_vuln_without_dependents(
        self, uv_dao, session, published_vuln_no_deps
    ):
        """Library with no project_dependencies should be excluded (方案 C)."""
        results = await uv_dao.list_published_without_impact(session)
        assert len(results) == 0

    @pytest.mark.anyio()
    async def test_respects_limit(
        self, uv_dao, session, published_vuln, event2, library, dep_a
    ):
        # Create a second published vuln
        vuln2 = await uv_dao.create(
            session,
            event_id=event2.id,
            library_id=library.id,
            commit_sha="def456",
        )
        await uv_dao.publish(session, vuln2.id)

        results = await uv_dao.list_published_without_impact(session, limit=1)
        assert len(results) == 1


# ── TestImpactRunner (mock-based, no DB) ─────────────────────────────────────


class TestImpactRunner:
    def _make_runner(self):
        vuln_service = AsyncMock(spec=UpstreamVulnService)
        cv_service = AsyncMock(spec=ClientVulnService)
        dep_dao = AsyncMock(spec=ProjectDependencyDAO)
        runner = ImpactRunner(vuln_service, cv_service, dep_dao)
        return runner, vuln_service, cv_service, dep_dao

    def _make_vuln(self, library_id=None):
        vuln = MagicMock()
        vuln.id = uuid.uuid4()
        vuln.library_id = library_id or uuid.uuid4()
        return vuln

    @pytest.mark.anyio()
    async def test_process_one_creates_client_vulns(self):
        runner, vuln_service, cv_service, dep_dao = self._make_runner()
        vuln = self._make_vuln()
        session = AsyncMock(spec=AsyncSession)

        deps = [_mock_dep(), _mock_dep()]
        dep_dao.list_by_library.return_value = deps

        created = await runner.process_one(session, vuln)

        assert created == 2
        assert cv_service.create.call_count == 2

    @pytest.mark.anyio()
    async def test_process_one_no_deps_returns_zero(self):
        runner, vuln_service, cv_service, dep_dao = self._make_runner()
        vuln = self._make_vuln()
        session = AsyncMock(spec=AsyncSession)

        dep_dao.list_by_library.return_value = []

        created = await runner.process_one(session, vuln)

        assert created == 0
        cv_service.create.assert_not_called()

    @pytest.mark.anyio()
    async def test_process_one_skips_duplicates(self):
        from sqlalchemy.exc import IntegrityError

        runner, vuln_service, cv_service, dep_dao = self._make_runner()
        vuln = self._make_vuln()
        session = AsyncMock(spec=AsyncSession)

        deps = [_mock_dep(), _mock_dep()]
        dep_dao.list_by_library.return_value = deps

        # First call succeeds, second raises IntegrityError
        cv_service.create.side_effect = [
            MagicMock(),
            IntegrityError("dup", params=None, orig=Exception()),
        ]

        created = await runner.process_one(session, vuln)

        assert created == 1
        assert cv_service.create.call_count == 2

    @pytest.mark.anyio()
    async def test_process_one_passes_version_fields(self):
        runner, vuln_service, cv_service, dep_dao = self._make_runner()
        vuln = self._make_vuln()
        session = AsyncMock(spec=AsyncSession)

        proj_id = uuid.uuid4()
        dep = _mock_dep(
            project_id=proj_id,
            constraint_expr=">=2.0",
            resolved_version="2.5.1",
            constraint_source="manifest",
        )
        dep_dao.list_by_library.return_value = [dep]

        await runner.process_one(session, vuln)

        cv_service.create.assert_called_once_with(
            session,
            upstream_vuln_id=vuln.id,
            project_id=proj_id,
            constraint_expr=">=2.0",
            constraint_source="manifest",
            resolved_version="2.5.1",
        )
