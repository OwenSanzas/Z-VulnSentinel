"""Dependency injection — session, auth, and service singletons."""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO
from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.project_dependency_dao import ProjectDependencyDAO
from vulnsentinel.dao.snapshot_dao import SnapshotDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.dao.user_dao import UserDAO
from vulnsentinel.engines.dependency_scanner.scanner import DependencyScanner
from vulnsentinel.engines.event_collector.runner import EventCollectorRunner
from vulnsentinel.models.user import User
from vulnsentinel.services import AuthenticationError
from vulnsentinel.services.auth_service import AuthService
from vulnsentinel.services.client_vuln_service import ClientVulnService
from vulnsentinel.services.event_service import EventService
from vulnsentinel.services.library_service import LibraryService
from vulnsentinel.services.project_service import ProjectService
from vulnsentinel.services.snapshot_service import SnapshotService
from vulnsentinel.services.stats_service import StatsService
from vulnsentinel.services.upstream_vuln_service import UpstreamVulnService

# ---------------------------------------------------------------------------
# DAO singletons
# ---------------------------------------------------------------------------
_user_dao = UserDAO()
_library_dao = LibraryDAO()
_project_dao = ProjectDAO()
_project_dependency_dao = ProjectDependencyDAO()
_snapshot_dao = SnapshotDAO()
_event_dao = EventDAO()
_upstream_vuln_dao = UpstreamVulnDAO()
_client_vuln_dao = ClientVulnDAO()

# ---------------------------------------------------------------------------
# Service singletons
# ---------------------------------------------------------------------------
_auth_service = AuthService(_user_dao)
_library_service = LibraryService(_library_dao, _project_dao, _project_dependency_dao, _event_dao)
_project_service = ProjectService(
    _project_dao, _project_dependency_dao, _client_vuln_dao, _library_service
)
_snapshot_service = SnapshotService(_snapshot_dao)
_event_service = EventService(_event_dao, _upstream_vuln_dao)
_upstream_vuln_service = UpstreamVulnService(_upstream_vuln_dao, _client_vuln_dao)
_client_vuln_service = ClientVulnService(_client_vuln_dao, _upstream_vuln_dao)
_stats_service = StatsService(_project_dao, _library_dao, _client_vuln_service)
_dependency_scanner = DependencyScanner(_project_service, _library_service)
_event_collector_runner = EventCollectorRunner(_library_service, _event_service)

# ---------------------------------------------------------------------------
# Engine / session factory (initialised by app lifespan)
# ---------------------------------------------------------------------------
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_session_factory(database_url: str | None = None) -> async_sessionmaker[AsyncSession]:
    """Create the async engine and session factory. Called once at startup."""
    global _engine, _session_factory  # noqa: PLW0603
    url = database_url or os.environ.get(
        "VULNSENTINEL_DATABASE_URL", "postgresql+asyncpg://localhost/vulnsentinel"
    )
    _engine = create_async_engine(
        url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_recycle=1800,
    )
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _session_factory


async def dispose_engine() -> None:
    """Dispose the async engine, closing all pooled connections."""
    global _engine  # noqa: PLW0603
    if _engine is not None:
        await _engine.dispose()
        _engine = None


def set_session_factory(factory: async_sessionmaker[AsyncSession]) -> None:
    """Override session factory (for testing)."""
    global _session_factory  # noqa: PLW0603
    _session_factory = factory


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a per-request session with automatic commit/rollback."""
    if _session_factory is None:
        raise RuntimeError("call init_session_factory() before handling requests")
    async with _session_factory() as session:
        async with session.begin():
            yield session


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    session: AsyncSession = Depends(get_session),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> User:
    """Extract and validate Bearer token, return the authenticated User."""
    if credentials is None:
        raise AuthenticationError("missing authorization header")
    return await _auth_service.get_current_user(session, credentials.credentials)


# ---------------------------------------------------------------------------
# Service getters (for Depends())
# ---------------------------------------------------------------------------


def get_auth_service() -> AuthService:
    return _auth_service


def get_library_service() -> LibraryService:
    return _library_service


def get_project_service() -> ProjectService:
    return _project_service


def get_snapshot_service() -> SnapshotService:
    return _snapshot_service


def get_event_service() -> EventService:
    return _event_service


def get_upstream_vuln_service() -> UpstreamVulnService:
    return _upstream_vuln_service


def get_client_vuln_service() -> ClientVulnService:
    return _client_vuln_service


def get_stats_service() -> StatsService:
    return _stats_service


def get_dependency_scanner() -> DependencyScanner:
    return _dependency_scanner


def get_event_collector_runner() -> EventCollectorRunner:
    return _event_collector_runner
