"""Projects router."""

from __future__ import annotations

import asyncio
import uuid

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import (
    get_client_vuln_service,
    get_current_user,
    get_dependency_scanner,
    get_github_client,
    get_project_service,
    get_session,
    get_session_factory,
)
from vulnsentinel.core.github import parse_repo_url
from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.api.routers.client_vulns import _enrich_client_vulns
from vulnsentinel.api.schemas.client_vuln import ClientVulnListItem
from vulnsentinel.api.schemas.common import PageMeta, PaginatedResponse
from vulnsentinel.api.schemas.project import (
    CreateProjectRequest,
    DependencyInputSchema,
    DependencyResponse,
    ProjectDetail,
    ProjectListItem,
    ProjectResponse,
    UpdateDependencyRequest,
    UpdateProjectRequest,
)
from vulnsentinel.models.user import User
from vulnsentinel.services.client_vuln_service import ClientVulnService
from vulnsentinel.services.project_service import DependencyInput, ProjectService

router = APIRouter()


@router.get("/", response_model=PaginatedResponse[ProjectListItem])
async def list_projects(
    cursor: str | None = Query(None),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ProjectService = Depends(get_project_service),
) -> PaginatedResponse[ProjectListItem]:
    result = await svc.list(session, cursor=cursor, page_size=page_size)
    return PaginatedResponse(
        data=[
            ProjectListItem(
                **{k: getattr(item["project"], k) for k in ProjectResponse.model_fields},
                deps_count=item["deps_count"],
                vuln_count=item["vuln_count"],
            )
            for item in result["data"]
        ],
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
            total=result["total"],
        ),
    )


@router.get("/{project_id}", response_model=ProjectDetail)
async def get_project(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ProjectService = Depends(get_project_service),
) -> ProjectDetail:
    result = await svc.get(session, project_id)
    proj = result["project"]
    return ProjectDetail(
        **{k: getattr(proj, k) for k in ProjectResponse.model_fields},
        deps_count=result["deps_count"],
        vuln_count=result["vuln_count"],
    )


_log = structlog.get_logger(__name__)


@router.post("/", response_model=ProjectResponse, status_code=201)
async def create_project(
    body: CreateProjectRequest,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ProjectService = Depends(get_project_service),
) -> ProjectResponse:
    deps = None
    if body.dependencies:
        deps = [
            DependencyInput(
                library_name=d.library_name,
                library_repo_url=d.library_repo_url,
                constraint_expr=d.constraint_expr,
                resolved_version=d.resolved_version,
                platform=d.platform,
                default_branch=d.default_branch,
            )
            for d in body.dependencies
        ]
    project = await svc.create(
        session,
        name=body.name,
        repo_url=body.repo_url,
        organization=body.organization,
        contact=body.contact,
        platform=body.platform,
        default_branch=body.default_branch,
        auto_sync_deps=body.auto_sync_deps,
        pinned_ref=body.pinned_ref,
        dependencies=deps,
    )

    # Trigger immediate dependency scan in the background
    if body.auto_sync_deps:
        scanner = get_dependency_scanner()
        factory = get_session_factory()
        project_id = project.id

        async def _background_scan() -> None:
            # Wait for the request transaction to commit — the get_session
            # dependency commits on cleanup, which happens after the response.
            await asyncio.sleep(1)
            try:
                async with factory() as bg_session:
                    async with bg_session.begin():
                        await scanner.run(bg_session, project_id)
                _log.info("scan.on_create_done", project_id=str(project_id))
            except Exception:
                _log.exception("scan.on_create_failed", project_id=str(project_id))

        asyncio.create_task(_background_scan())

    return ProjectResponse.model_validate(project)


@router.patch("/{project_id}", response_model=ProjectDetail)
async def update_project(
    project_id: uuid.UUID,
    body: UpdateProjectRequest,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ProjectService = Depends(get_project_service),
) -> ProjectDetail:
    result = await svc.update(
        session,
        project_id,
        fields_set=body.model_fields_set,
        name=body.name,
        organization=body.organization,
        contact=body.contact,
        auto_sync_deps=body.auto_sync_deps,
        pinned_ref=body.pinned_ref,
    )
    proj = result["project"]
    return ProjectDetail(
        **{k: getattr(proj, k) for k in ProjectResponse.model_fields},
        deps_count=result["deps_count"],
        vuln_count=result["vuln_count"],
    )


@router.get(
    "/{project_id}/vulnerabilities",
    response_model=PaginatedResponse[ClientVulnListItem],
)
async def list_project_vulns(
    project_id: uuid.UUID,
    cursor: str | None = Query(None),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    project_svc: ProjectService = Depends(get_project_service),
    svc: ClientVulnService = Depends(get_client_vuln_service),
) -> PaginatedResponse[ClientVulnListItem]:
    await project_svc.get(session, project_id)  # 404 if not exists
    result = await svc.list_by_project(session, project_id, cursor=cursor, page_size=page_size)
    enriched = await _enrich_client_vulns(session, result["data"])
    return PaginatedResponse(
        data=enriched,
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
        ),
    )


# ── GitHub helpers ───────────────────────────────────────────────────


@router.get("/github/branches")
async def list_repo_branches(
    repo_url: str = Query(...),
    _user: User = Depends(get_current_user),
    client: GitHubClient = Depends(get_github_client),
) -> list[str]:
    """Fetch branch names from a GitHub repo URL."""
    owner, repo = parse_repo_url(repo_url.strip())
    branches: list[str] = []
    async for item in client.get_paginated(
        f"/repos/{owner}/{repo}/branches", max_pages=3
    ):
        branches.append(item["name"])
    return branches


# ── Dependencies sub-resource ────────────────────────────────────────


def _dep_response(item: dict) -> DependencyResponse:
    dep = item["dep"]
    return DependencyResponse(
        id=dep.id,
        library_id=dep.library_id,
        library_name=item["library_name"],
        constraint_expr=dep.constraint_expr,
        resolved_version=dep.resolved_version,
        constraint_source=dep.constraint_source,
        notify_enabled=dep.notify_enabled,
        created_at=dep.created_at,
    )


@router.get(
    "/{project_id}/dependencies",
    response_model=PaginatedResponse[DependencyResponse],
)
async def list_project_dependencies(
    project_id: uuid.UUID,
    cursor: str | None = Query(None),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ProjectService = Depends(get_project_service),
) -> PaginatedResponse[DependencyResponse]:
    result = await svc.list_dependencies(session, project_id, cursor=cursor, page_size=page_size)
    return PaginatedResponse(
        data=[_dep_response(item) for item in result["data"]],
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
        ),
    )


@router.post(
    "/{project_id}/dependencies",
    response_model=DependencyResponse,
    status_code=201,
)
async def add_project_dependency(
    project_id: uuid.UUID,
    body: DependencyInputSchema,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ProjectService = Depends(get_project_service),
) -> DependencyResponse:
    result = await svc.add_dependency(
        session,
        project_id,
        DependencyInput(
            library_name=body.library_name,
            library_repo_url=body.library_repo_url,
            constraint_expr=body.constraint_expr,
            resolved_version=body.resolved_version,
            platform=body.platform,
            default_branch=body.default_branch,
        ),
    )
    return _dep_response(result)


@router.delete(
    "/{project_id}/dependencies/{dep_id}",
    status_code=204,
)
async def remove_project_dependency(
    project_id: uuid.UUID,
    dep_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ProjectService = Depends(get_project_service),
) -> None:
    await svc.remove_dependency(session, project_id, dep_id)


@router.patch(
    "/{project_id}/dependencies/{dep_id}",
    response_model=DependencyResponse,
)
async def update_project_dependency(
    project_id: uuid.UUID,
    dep_id: uuid.UUID,
    body: UpdateDependencyRequest,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ProjectService = Depends(get_project_service),
) -> DependencyResponse:
    result = await svc.update_dependency_notify(session, project_id, dep_id, body.notify_enabled)
    return _dep_response(result)
