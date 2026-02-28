"""VulnSentinel REST API — FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from vulnsentinel.api.deps import (
    dispose_engine,
    get_auth_service,
    get_dependency_scanner,
    get_event_classifier_runner,
    get_event_collector_runner,
    get_github_client,
    get_impact_runner,
    get_notification_runner,
    get_project_service,
    get_reachability_runner,
    get_vuln_analyzer_runner,
    init_session_factory,
)
from vulnsentinel.api.errors import register_error_handlers
from vulnsentinel.api.middleware.request_id import RequestIDMiddleware
from vulnsentinel.api.routers import (
    auth,
    client_vulns,
    events,
    libraries,
    projects,
    stats,
    upstream_vulns,
)
from vulnsentinel.core.logging import setup_logging
from vulnsentinel.scheduler import create_scheduler

BANNER = """
\033[38;5;208m\
    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
    ██║   ██║██║   ██║██║     ████╗  ██║
    ██║   ██║██║   ██║██║     ██╔██╗ ██║
    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝

    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

      Vulnerability Early Warning Platform v1.0
      Developed by O2Lab @ Texas A&M University
\033[0m"""


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup: init DB, ensure admin. Shutdown: dispose engine."""
    factory = init_session_factory()
    auth_svc = get_auth_service()
    async with factory() as session:
        async with session.begin():
            await auth_svc.ensure_admin_exists(session)

    scheduler = create_scheduler(
        factory,
        scanner=get_dependency_scanner(),
        project_service=get_project_service(),
        event_collector_runner=get_event_collector_runner(),
        github_client=get_github_client(),
        event_classifier_runner=get_event_classifier_runner(),
        vuln_analyzer_runner=get_vuln_analyzer_runner(),
        impact_runner=get_impact_runner(),
        notification_runner=get_notification_runner(),
        reachability_runner=get_reachability_runner(),
    )
    await scheduler.start()
    yield
    await scheduler.stop()
    await dispose_engine()


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    setup_logging()
    print(BANNER)

    app = FastAPI(
        title="VulnSentinel",
        docs_url="/api/v1/docs",
        openapi_url="/api/v1/openapi.json",
        lifespan=_lifespan,
    )

    register_error_handlers(app)

    cors_origins = os.environ.get("VULNSENTINEL_CORS_ORIGINS", "http://localhost:3000")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in cors_origins.split(",")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestIDMiddleware)

    @app.get("/health", tags=["ops"])
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(libraries.router, prefix="/api/v1/libraries", tags=["libraries"])
    app.include_router(projects.router, prefix="/api/v1/projects", tags=["projects"])
    app.include_router(events.router, prefix="/api/v1/events", tags=["events"])
    app.include_router(
        upstream_vulns.router, prefix="/api/v1/upstream-vulns", tags=["upstream-vulns"]
    )
    app.include_router(client_vulns.router, prefix="/api/v1/client-vulns", tags=["client-vulns"])
    app.include_router(stats.router, prefix="/api/v1/stats", tags=["stats"])

    return app
