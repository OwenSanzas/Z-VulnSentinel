"""Tests for the API layer — all 21 endpoints.

Uses httpx.AsyncClient with FastAPI TestClient pattern.
Services are mocked to isolate the API layer from the database.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.models.event import Event
from vulnsentinel.models.library import Library
from vulnsentinel.models.project import Project
from vulnsentinel.models.snapshot import Snapshot
from vulnsentinel.models.upstream_vuln import UpstreamVuln
from vulnsentinel.models.user import User
from vulnsentinel.services import AuthenticationError, ConflictError, NotFoundError, ValidationError
from vulnsentinel.services.auth_service import AccessToken, TokenPair

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
USER_ID = uuid.uuid4()
TEST_SECRET = "test-jwt-secret-for-unit-tests"


def _user() -> User:
    return User(
        id=USER_ID,
        username="alice",
        email="alice@example.com",
        password_hash="xxx",
        role="admin",
        created_at=NOW,
        updated_at=NOW,
    )


def _library(lib_id: uuid.UUID | None = None) -> Library:
    return Library(
        id=lib_id or uuid.uuid4(),
        name="curl",
        repo_url="https://github.com/curl/curl",
        platform="github",
        default_branch="main",
        latest_tag_version="8.5.0",
        latest_commit_sha="abc123",
        monitoring_since=NOW,
        last_activity_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )


def _project(proj_id: uuid.UUID | None = None) -> Project:
    return Project(
        id=proj_id or uuid.uuid4(),
        name="myapp",
        organization="acme",
        repo_url="https://github.com/acme/myapp",
        platform="github",
        default_branch="main",
        contact="team@acme.com",
        current_version="1.0.0",
        monitoring_since=NOW,
        last_update_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )


def _snapshot(snap_id: uuid.UUID | None = None, project_id: uuid.UUID | None = None) -> Snapshot:
    return Snapshot(
        id=snap_id or uuid.uuid4(),
        project_id=project_id or uuid.uuid4(),
        repo_url="https://github.com/acme/myapp",
        repo_name="myapp",
        version="1.0.0",
        backend="svf",
        status="building",
        trigger_type="manual",
        is_active=False,
        storage_path=None,
        node_count=0,
        edge_count=0,
        fuzzer_names=[],
        analysis_duration_sec=0.0,
        language="c",
        size_bytes=0,
        error=None,
        created_at=NOW,
        updated_at=NOW,
    )


def _event(event_id: uuid.UUID | None = None) -> Event:
    return Event(
        id=event_id or uuid.uuid4(),
        library_id=uuid.uuid4(),
        type="commit",
        ref="abc123",
        source_url="https://github.com/curl/curl/commit/abc123",
        author="dev",
        title="fix buffer overflow",
        message="details here",
        related_issue_ref=None,
        related_issue_url=None,
        related_pr_ref=None,
        related_pr_url=None,
        related_commit_sha=None,
        classification="security_bugfix",
        confidence=0.95,
        is_bugfix=True,
        created_at=NOW,
        updated_at=NOW,
    )


def _upstream_vuln(vuln_id: uuid.UUID | None = None) -> UpstreamVuln:
    return UpstreamVuln(
        id=vuln_id or uuid.uuid4(),
        event_id=uuid.uuid4(),
        library_id=uuid.uuid4(),
        commit_sha="abc123",
        vuln_type="buffer_overflow",
        severity="high",
        status="published",
        summary="Buffer overflow in libcurl",
        affected_versions="<8.5.0",
        reasoning="analysis reasoning",
        error_message=None,
        upstream_poc=None,
        detected_at=NOW,
        published_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )


def _client_vuln(cv_id: uuid.UUID | None = None) -> ClientVuln:
    return ClientVuln(
        id=cv_id or uuid.uuid4(),
        upstream_vuln_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        pipeline_status="verified",
        status="recorded",
        is_affected=True,
        constraint_expr=">=7.0",
        constraint_source="manifest",
        resolved_version="8.4.0",
        fix_version="8.5.0",
        verdict="affected",
        reachable_path={"path": ["main", "do_curl"]},
        poc_results={"success": True},
        report=None,
        error_message=None,
        recorded_at=NOW,
        reported_at=None,
        confirmed_at=None,
        confirmed_msg=None,
        fixed_at=None,
        fixed_msg=None,
        created_at=NOW,
        updated_at=NOW,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app():
    """Create a test app with mocked lifespan (no real DB)."""
    # Bypass lifespan entirely by creating app then overriding deps
    from vulnsentinel.api import deps

    # Create a mock session factory
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.begin = MagicMock(return_value=mock_session)

    from fastapi import FastAPI

    from vulnsentinel.api.errors import register_error_handlers
    from vulnsentinel.api.routers import (
        auth,
        client_vulns,
        events,
        libraries,
        projects,
        snapshots,
        stats,
        upstream_vulns,
    )

    application = FastAPI()
    register_error_handlers(application)
    application.include_router(auth.router, prefix="/api/v1/auth")
    application.include_router(libraries.router, prefix="/api/v1/libraries")
    application.include_router(projects.router, prefix="/api/v1/projects")
    application.include_router(snapshots.router, prefix="/api/v1/snapshots")
    application.include_router(events.router, prefix="/api/v1/events")
    application.include_router(upstream_vulns.router, prefix="/api/v1/upstream-vulns")
    application.include_router(client_vulns.router, prefix="/api/v1/client-vulns")
    application.include_router(stats.router, prefix="/api/v1/stats")

    # Override session dependency
    async def _mock_session():
        yield mock_session

    application.dependency_overrides[deps.get_session] = _mock_session

    # Override auth dependency — return a fake user by default
    async def _mock_user():
        return _user()

    application.dependency_overrides[deps.get_current_user] = _mock_user

    return application


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------


class TestAuthRouter:
    @pytest.mark.asyncio
    async def test_login_success(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.login = AsyncMock(return_value=TokenPair("access_tok", "refresh_tok"))
        app.dependency_overrides[deps.get_auth_service] = lambda: mock_svc

        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "secret"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "access_tok"
        assert data["refresh_token"] == "refresh_tok"
        assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.login = AsyncMock(side_effect=AuthenticationError("invalid credentials"))
        app.dependency_overrides[deps.get_auth_service] = lambda: mock_svc

        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "invalid credentials"

    @pytest.mark.asyncio
    async def test_refresh_success(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = MagicMock()
        mock_svc.refresh = MagicMock(return_value=AccessToken("new_access"))
        app.dependency_overrides[deps.get_auth_service] = lambda: mock_svc

        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "some_refresh_token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "new_access"

    @pytest.mark.asyncio
    async def test_refresh_invalid_token(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = MagicMock()
        mock_svc.refresh = MagicMock(side_effect=AuthenticationError("invalid refresh token"))
        app.dependency_overrides[deps.get_auth_service] = lambda: mock_svc

        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "bad"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_me(self, client):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "alice"
        assert data["email"] == "alice@example.com"


# ---------------------------------------------------------------------------
# Libraries tests
# ---------------------------------------------------------------------------


class TestLibrariesRouter:
    @pytest.mark.asyncio
    async def test_list_libraries(self, app, client):
        from vulnsentinel.api import deps

        lib = _library()
        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(
            return_value={
                "data": [lib],
                "next_cursor": None,
                "has_more": False,
                "total": 1,
            }
        )
        app.dependency_overrides[deps.get_library_service] = lambda: mock_svc

        resp = await client.get("/api/v1/libraries/")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["data"]) == 1
        assert data["data"][0]["name"] == "curl"
        assert data["meta"]["total"] == 1
        assert data["meta"]["has_more"] is False

    @pytest.mark.asyncio
    async def test_list_libraries_with_pagination(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(
            return_value={
                "data": [_library()],
                "next_cursor": "abc",
                "has_more": True,
                "total": 5,
            }
        )
        app.dependency_overrides[deps.get_library_service] = lambda: mock_svc

        resp = await client.get("/api/v1/libraries/?page_size=1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["has_more"] is True
        assert data["meta"]["next_cursor"] == "abc"

    @pytest.mark.asyncio
    async def test_list_libraries_invalid_cursor(self, app, client):
        from vulnsentinel.api import deps
        from vulnsentinel.dao.base import InvalidCursorError

        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(side_effect=InvalidCursorError("invalid cursor: 'bad'"))
        app.dependency_overrides[deps.get_library_service] = lambda: mock_svc

        resp = await client.get("/api/v1/libraries/?cursor=bad")
        assert resp.status_code == 422
        assert "invalid cursor" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_get_library(self, app, client):
        from vulnsentinel.api import deps

        lib_id = uuid.uuid4()
        lib = _library(lib_id)
        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(
            return_value={
                "library": lib,
                "used_by": [
                    {
                        "project_id": uuid.uuid4(),
                        "project_name": "myapp",
                        "constraint_expr": ">=7.0",
                        "resolved_version": "8.4.0",
                        "constraint_source": "manifest",
                    }
                ],
                "events_tracked": 42,
            }
        )
        app.dependency_overrides[deps.get_library_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/libraries/{lib_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "curl"
        assert len(data["used_by"]) == 1
        assert data["events_tracked"] == 42

    @pytest.mark.asyncio
    async def test_get_library_not_found(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(side_effect=NotFoundError("library not found"))
        app.dependency_overrides[deps.get_library_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/libraries/{uuid.uuid4()}")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "library not found"


# ---------------------------------------------------------------------------
# Projects tests
# ---------------------------------------------------------------------------


class TestProjectsRouter:
    @pytest.mark.asyncio
    async def test_list_projects(self, app, client):
        from vulnsentinel.api import deps

        proj = _project()
        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(
            return_value={
                "data": [
                    {
                        "project": proj,
                        "deps_count": 3,
                        "vuln_count": 1,
                        **{
                            k: getattr(proj, k)
                            for k in [
                                "id",
                                "name",
                                "organization",
                                "repo_url",
                                "platform",
                                "default_branch",
                                "contact",
                                "current_version",
                                "monitoring_since",
                                "last_update_at",
                                "created_at",
                            ]
                        },
                    }
                ],
                "next_cursor": None,
                "has_more": False,
                "total": 1,
            }
        )
        app.dependency_overrides[deps.get_project_service] = lambda: mock_svc

        resp = await client.get("/api/v1/projects/")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["data"]) == 1

    @pytest.mark.asyncio
    async def test_get_project(self, app, client):
        from vulnsentinel.api import deps

        proj_id = uuid.uuid4()
        proj = _project(proj_id)
        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(
            return_value={
                "project": proj,
                "deps_count": 5,
                "vuln_count": 2,
            }
        )
        app.dependency_overrides[deps.get_project_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/projects/{proj_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "myapp"
        assert data["deps_count"] == 5
        assert data["vuln_count"] == 2

    @pytest.mark.asyncio
    async def test_create_project(self, app, client):
        from vulnsentinel.api import deps

        proj = _project()
        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(return_value=proj)
        app.dependency_overrides[deps.get_project_service] = lambda: mock_svc

        resp = await client.post(
            "/api/v1/projects/",
            json={
                "name": "myapp",
                "repo_url": "https://github.com/acme/myapp",
                "organization": "acme",
                "dependencies": [
                    {
                        "library_name": "curl",
                        "library_repo_url": "https://github.com/curl/curl",
                        "constraint_expr": ">=7.0",
                    }
                ],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "myapp"

    @pytest.mark.asyncio
    async def test_create_project_without_deps(self, app, client):
        from vulnsentinel.api import deps

        proj = _project()
        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(return_value=proj)
        app.dependency_overrides[deps.get_project_service] = lambda: mock_svc

        resp = await client.post(
            "/api/v1/projects/",
            json={"name": "myapp", "repo_url": "https://github.com/acme/myapp"},
        )
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_create_project_duplicate_repo_url(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        msg = "project with repo_url 'https://github.com/acme/myapp' already exists"
        mock_svc.create = AsyncMock(side_effect=ConflictError(msg))
        app.dependency_overrides[deps.get_project_service] = lambda: mock_svc

        resp = await client.post(
            "/api/v1/projects/",
            json={"name": "myapp", "repo_url": "https://github.com/acme/myapp"},
        )
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_project_snapshots(self, app, client):
        from vulnsentinel.api import deps

        proj_id = uuid.uuid4()
        proj = _project(proj_id)
        snap = _snapshot(project_id=proj_id)

        mock_proj_svc = AsyncMock()
        mock_proj_svc.get = AsyncMock(
            return_value={
                "project": proj,
                "deps_count": 0,
                "vuln_count": 0,
            }
        )
        app.dependency_overrides[deps.get_project_service] = lambda: mock_proj_svc

        mock_svc = AsyncMock()
        mock_svc.list_by_project = AsyncMock(
            return_value={
                "data": [snap],
                "next_cursor": None,
                "has_more": False,
            }
        )
        app.dependency_overrides[deps.get_snapshot_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/projects/{proj_id}/snapshots")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["data"]) == 1

    @pytest.mark.asyncio
    async def test_create_project_snapshot(self, app, client):
        from vulnsentinel.api import deps

        proj_id = uuid.uuid4()
        proj = _project(proj_id)
        snap = _snapshot(project_id=proj_id)

        mock_proj_svc = AsyncMock()
        mock_proj_svc.get = AsyncMock(
            return_value={
                "project": proj,
                "deps_count": 0,
                "vuln_count": 0,
            }
        )
        app.dependency_overrides[deps.get_project_service] = lambda: mock_proj_svc

        mock_svc = AsyncMock()
        mock_svc.create = AsyncMock(return_value=snap)
        app.dependency_overrides[deps.get_snapshot_service] = lambda: mock_svc

        resp = await client.post(
            f"/api/v1/projects/{proj_id}/snapshots",
            json={
                "repo_url": "https://github.com/acme/myapp",
                "repo_name": "myapp",
                "version": "1.0.0",
                "backend": "svf",
                "trigger_type": "manual",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["backend"] == "svf"

    @pytest.mark.asyncio
    async def test_list_project_vulnerabilities(self, app, client):
        from vulnsentinel.api import deps

        proj_id = uuid.uuid4()
        proj = _project(proj_id)
        cv = _client_vuln()

        mock_proj_svc = AsyncMock()
        mock_proj_svc.get = AsyncMock(
            return_value={
                "project": proj,
                "deps_count": 0,
                "vuln_count": 0,
            }
        )
        app.dependency_overrides[deps.get_project_service] = lambda: mock_proj_svc

        mock_svc = AsyncMock()
        mock_svc.list_by_project = AsyncMock(
            return_value={
                "data": [cv],
                "next_cursor": None,
                "has_more": False,
            }
        )
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/projects/{proj_id}/vulnerabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["data"]) == 1


# ---------------------------------------------------------------------------
# Snapshots tests
# ---------------------------------------------------------------------------


class TestSnapshotsRouter:
    @pytest.mark.asyncio
    async def test_get_snapshot(self, app, client):
        from vulnsentinel.api import deps

        snap_id = uuid.uuid4()
        snap = _snapshot(snap_id)
        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(return_value=snap)
        app.dependency_overrides[deps.get_snapshot_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/snapshots/{snap_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_get_snapshot_not_found(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(side_effect=NotFoundError("snapshot not found"))
        app.dependency_overrides[deps.get_snapshot_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/snapshots/{uuid.uuid4()}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Events tests
# ---------------------------------------------------------------------------


class TestEventsRouter:
    @pytest.mark.asyncio
    async def test_list_events(self, app, client):
        from vulnsentinel.api import deps

        ev = _event()
        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(
            return_value={
                "data": [ev],
                "next_cursor": None,
                "has_more": False,
                "total": 1,
            }
        )
        app.dependency_overrides[deps.get_event_service] = lambda: mock_svc

        resp = await client.get("/api/v1/events/")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["data"]) == 1
        assert data["data"][0]["title"] == "fix buffer overflow"

    @pytest.mark.asyncio
    async def test_list_events_with_library_filter(self, app, client):
        from vulnsentinel.api import deps

        lib_id = uuid.uuid4()
        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(
            return_value={
                "data": [],
                "next_cursor": None,
                "has_more": False,
                "total": 0,
            }
        )
        app.dependency_overrides[deps.get_event_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/events/?library_id={lib_id}")
        assert resp.status_code == 200
        mock_svc.list.assert_called_once()
        call_kwargs = mock_svc.list.call_args
        assert call_kwargs.kwargs.get("library_id") == lib_id

    @pytest.mark.asyncio
    async def test_get_event(self, app, client):
        from vulnsentinel.api import deps

        ev_id = uuid.uuid4()
        ev = _event(ev_id)
        vuln = _upstream_vuln()
        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(
            return_value={
                "event": ev,
                "related_vulns": [vuln],
            }
        )
        app.dependency_overrides[deps.get_event_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/events/{ev_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "fix buffer overflow"
        assert len(data["related_vulns"]) == 1

    @pytest.mark.asyncio
    async def test_get_event_not_found(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(side_effect=NotFoundError("event not found"))
        app.dependency_overrides[deps.get_event_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/events/{uuid.uuid4()}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Upstream Vulns tests
# ---------------------------------------------------------------------------


class TestUpstreamVulnsRouter:
    @pytest.mark.asyncio
    async def test_list_upstream_vulns(self, app, client):
        from vulnsentinel.api import deps

        vuln = _upstream_vuln()
        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(
            return_value={
                "data": [vuln],
                "next_cursor": None,
                "has_more": False,
                "total": 1,
            }
        )
        app.dependency_overrides[deps.get_upstream_vuln_service] = lambda: mock_svc

        resp = await client.get("/api/v1/upstream-vulns/")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["data"]) == 1
        assert data["data"][0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_get_upstream_vuln(self, app, client):
        from vulnsentinel.api import deps

        vuln_id = uuid.uuid4()
        vuln = _upstream_vuln(vuln_id)
        cv = _client_vuln()
        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(
            return_value={
                "vuln": vuln,
                "client_impact": [cv],
            }
        )
        app.dependency_overrides[deps.get_upstream_vuln_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/upstream-vulns/{vuln_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"] == "Buffer overflow in libcurl"
        assert data["affected_versions"] == "<8.5.0"
        assert len(data["client_impact"]) == 1

    @pytest.mark.asyncio
    async def test_get_upstream_vuln_not_found(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(side_effect=NotFoundError("not found"))
        app.dependency_overrides[deps.get_upstream_vuln_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/upstream-vulns/{uuid.uuid4()}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Client Vulns tests
# ---------------------------------------------------------------------------


class TestClientVulnsRouter:
    @pytest.mark.asyncio
    async def test_get_stats(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.get_stats = AsyncMock(
            return_value={
                "total_recorded": 10,
                "total_reported": 8,
                "total_confirmed": 5,
                "total_fixed": 2,
            }
        )
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.get("/api/v1/client-vulns/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_recorded"] == 10
        assert data["total_fixed"] == 2

    @pytest.mark.asyncio
    async def test_get_stats_with_project_filter(self, app, client):
        from vulnsentinel.api import deps

        proj_id = uuid.uuid4()
        mock_svc = AsyncMock()
        mock_svc.get_stats = AsyncMock(
            return_value={
                "total_recorded": 3,
                "total_reported": 2,
                "total_confirmed": 1,
                "total_fixed": 0,
            }
        )
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/client-vulns/stats?project_id={proj_id}")
        assert resp.status_code == 200
        mock_svc.get_stats.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_client_vulns(self, app, client):
        from vulnsentinel.api import deps

        cv = _client_vuln()
        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(
            return_value={
                "data": [cv],
                "next_cursor": None,
                "has_more": False,
                "total": 1,
                "stats": {
                    "total_recorded": 1,
                    "total_reported": 0,
                    "total_confirmed": 0,
                    "total_fixed": 0,
                },
            }
        )
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.get("/api/v1/client-vulns/")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["data"]) == 1
        assert data["stats"]["total_recorded"] == 1

    @pytest.mark.asyncio
    async def test_list_client_vulns_with_filters(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.list = AsyncMock(
            return_value={
                "data": [],
                "next_cursor": None,
                "has_more": False,
                "total": 0,
                "stats": {
                    "total_recorded": 0,
                    "total_reported": 0,
                    "total_confirmed": 0,
                    "total_fixed": 0,
                },
            }
        )
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.get("/api/v1/client-vulns/?status=recorded&severity=high")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_client_vuln(self, app, client):
        from vulnsentinel.api import deps

        cv_id = uuid.uuid4()
        cv = _client_vuln(cv_id)
        uv = _upstream_vuln()
        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(
            return_value={
                "client_vuln": cv,
                "upstream_vuln": uv,
            }
        )
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/client-vulns/{cv_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["pipeline_status"] == "verified"
        assert data["upstream_vuln"]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_get_client_vuln_not_found(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(side_effect=NotFoundError("not found"))
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/client-vulns/{uuid.uuid4()}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_status(self, app, client):
        from vulnsentinel.api import deps

        cv_id = uuid.uuid4()
        mock_svc = AsyncMock()
        mock_svc.update_status = AsyncMock(return_value=None)
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.patch(
            f"/api/v1/client-vulns/{cv_id}/status",
            json={"status": "reported"},
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_update_status_with_msg(self, app, client):
        from vulnsentinel.api import deps

        cv_id = uuid.uuid4()
        mock_svc = AsyncMock()
        mock_svc.update_status = AsyncMock(return_value=None)
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.patch(
            f"/api/v1/client-vulns/{cv_id}/status",
            json={"status": "confirmed", "msg": "verified by team"},
        )
        assert resp.status_code == 204
        mock_svc.update_status.assert_called_once_with(
            mock_svc.update_status.call_args.args[0],  # session
            cv_id,
            status="confirmed",
            msg="verified by team",
        )

    @pytest.mark.asyncio
    async def test_update_status_validation_error(self, app, client):
        from vulnsentinel.api import deps

        cv_id = uuid.uuid4()
        mock_svc = AsyncMock()
        mock_svc.update_status = AsyncMock(side_effect=ValidationError("invalid transition"))
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.patch(
            f"/api/v1/client-vulns/{cv_id}/status",
            json={"status": "fixed"},
        )
        assert resp.status_code == 422
        assert resp.json()["detail"] == "invalid transition"


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------


class TestStatsRouter:
    @pytest.mark.asyncio
    async def test_get_dashboard(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.get_dashboard = AsyncMock(
            return_value={
                "projects_count": 5,
                "libraries_count": 12,
                "vuln_recorded": 20,
                "vuln_reported": 15,
                "vuln_confirmed": 8,
                "vuln_fixed": 3,
            }
        )
        app.dependency_overrides[deps.get_stats_service] = lambda: mock_svc

        resp = await client.get("/api/v1/stats/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["projects_count"] == 5
        assert data["libraries_count"] == 12
        assert data["vuln_recorded"] == 20
        assert data["vuln_fixed"] == 3


# ---------------------------------------------------------------------------
# Error handler tests
# ---------------------------------------------------------------------------


class TestErrorHandlers:
    @pytest.mark.asyncio
    async def test_not_found_returns_404(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.get = AsyncMock(side_effect=NotFoundError("resource not found"))
        app.dependency_overrides[deps.get_library_service] = lambda: mock_svc

        resp = await client.get(f"/api/v1/libraries/{uuid.uuid4()}")
        assert resp.status_code == 404
        assert resp.json() == {"detail": "resource not found"}

    @pytest.mark.asyncio
    async def test_validation_returns_422(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.update_status = AsyncMock(side_effect=ValidationError("bad transition"))
        app.dependency_overrides[deps.get_client_vuln_service] = lambda: mock_svc

        resp = await client.patch(
            f"/api/v1/client-vulns/{uuid.uuid4()}/status",
            json={"status": "invalid"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_auth_error_returns_401(self, app, client):
        from vulnsentinel.api import deps

        mock_svc = AsyncMock()
        mock_svc.login = AsyncMock(side_effect=AuthenticationError("invalid credentials"))
        app.dependency_overrides[deps.get_auth_service] = lambda: mock_svc

        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "x", "password": "y"},
        )
        assert resp.status_code == 401
