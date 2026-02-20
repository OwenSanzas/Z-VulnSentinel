"""VulnSentinel REST API — FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vulnsentinel.api.deps import dispose_engine, get_auth_service, init_session_factory
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


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup: init DB, ensure admin. Shutdown: dispose engine."""
    factory = init_session_factory()
    auth_svc = get_auth_service()
    async with factory() as session:
        async with session.begin():
            await auth_svc.ensure_admin_exists(session)
    yield
    await dispose_engine()


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    app = FastAPI(
        title="VulnSentinel",
        docs_url="/api/v1/docs",
        openapi_url="/api/v1/openapi.json",
        lifespan=_lifespan,
    )

    register_error_handlers(app)

    app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(libraries.router, prefix="/api/v1/libraries", tags=["libraries"])
    app.include_router(projects.router, prefix="/api/v1/projects", tags=["projects"])
    app.include_router(snapshots.router, prefix="/api/v1/snapshots", tags=["snapshots"])
    app.include_router(events.router, prefix="/api/v1/events", tags=["events"])
    app.include_router(
        upstream_vulns.router, prefix="/api/v1/upstream-vulns", tags=["upstream-vulns"]
    )
    app.include_router(
        client_vulns.router, prefix="/api/v1/client-vulns", tags=["client-vulns"]
    )
    app.include_router(stats.router, prefix="/api/v1/stats", tags=["stats"])

    return app
