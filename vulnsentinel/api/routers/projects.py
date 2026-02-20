"""Projects router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import (
    get_client_vuln_service,
    get_current_user,
    get_project_service,
    get_session,
    get_snapshot_service,
)
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
from vulnsentinel.api.schemas.snapshot import CreateSnapshotRequest, SnapshotResponse
from vulnsentinel.models.user import User
from vulnsentinel.services.client_vuln_service import ClientVulnService
from vulnsentinel.services.project_service import DependencyInput, ProjectService
from vulnsentinel.services.snapshot_service import SnapshotService

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
                constraint_source=d.constraint_source,
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
    "/{project_id}/snapshots",
    response_model=PaginatedResponse[SnapshotResponse],
)
async def list_project_snapshots(
    project_id: uuid.UUID,
    cursor: str | None = Query(None),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    project_svc: ProjectService = Depends(get_project_service),
    svc: SnapshotService = Depends(get_snapshot_service),
) -> PaginatedResponse[SnapshotResponse]:
    await project_svc.get(session, project_id)  # 404 if not exists
    result = await svc.list_by_project(session, project_id, cursor=cursor, page_size=page_size)
    return PaginatedResponse(
        data=[SnapshotResponse.model_validate(s) for s in result["data"]],
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
        ),
    )


@router.post(
    "/{project_id}/snapshots",
    response_model=SnapshotResponse,
    status_code=201,
)
async def create_project_snapshot(
    project_id: uuid.UUID,
    body: CreateSnapshotRequest,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    project_svc: ProjectService = Depends(get_project_service),
    svc: SnapshotService = Depends(get_snapshot_service),
) -> SnapshotResponse:
    await project_svc.get(session, project_id)  # 404 if not exists
    snapshot = await svc.create(
        session,
        project_id=project_id,
        repo_url=body.repo_url,
        repo_name=body.repo_name,
        version=body.version,
        backend=body.backend,
        trigger_type=body.trigger_type,
    )
    return SnapshotResponse.model_validate(snapshot)


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
    return PaginatedResponse(
        data=[ClientVulnListItem.model_validate(cv) for cv in result["data"]],
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
        ),
    )


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
            constraint_source=body.constraint_source,
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
