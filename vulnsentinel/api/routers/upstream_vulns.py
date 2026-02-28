"""Upstream vulnerabilities router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_current_user, get_session, get_upstream_vuln_service
from vulnsentinel.api.schemas.common import PageMeta, PaginatedResponse
from vulnsentinel.api.schemas.upstream_vuln import (
    ClientImpactItem,
    UpstreamVulnDetail,
    UpstreamVulnListItem,
)
from vulnsentinel.models.library import Library
from vulnsentinel.models.project import Project
from vulnsentinel.models.project_dependency import ProjectDependency
from vulnsentinel.models.user import User
from vulnsentinel.services.upstream_vuln_service import UpstreamVulnService

router = APIRouter()


@router.get("/", response_model=PaginatedResponse[UpstreamVulnListItem])
async def list_upstream_vulns(
    cursor: str | None = Query(None),
    page_size: int = Query(20, ge=1, le=100),
    library_id: uuid.UUID | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: UpstreamVulnService = Depends(get_upstream_vuln_service),
) -> PaginatedResponse[UpstreamVulnListItem]:
    result = await svc.list(session, cursor=cursor, page_size=page_size, library_id=library_id)
    return PaginatedResponse(
        data=[UpstreamVulnListItem.model_validate(v) for v in result["data"]],
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
            total=result["total"],
        ),
    )


@router.get("/{vuln_id}", response_model=UpstreamVulnDetail)
async def get_upstream_vuln(
    vuln_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: UpstreamVulnService = Depends(get_upstream_vuln_service),
) -> UpstreamVulnDetail:
    result = await svc.get(session, vuln_id)
    vuln = result["vuln"]
    client_impact_rows = result["client_impact"]

    # Fetch library_name
    lib_stmt = select(Library.name).where(Library.id == vuln.library_id)
    lib_name = (await session.execute(lib_stmt)).scalar_one_or_none() or ""

    # Batch fetch project names and resolved versions for client impact
    proj_ids = {ci.project_id for ci in client_impact_rows}
    proj_names: dict[uuid.UUID, str] = {}
    version_map: dict[uuid.UUID, str | None] = {}
    if proj_ids:
        proj_stmt = select(Project.id, Project.name).where(Project.id.in_(proj_ids))
        proj_rows = await session.execute(proj_stmt)
        proj_names = {row.id: row.name for row in proj_rows}

        # Get resolved_version from project_dependencies for this library
        dep_stmt = select(ProjectDependency.project_id, ProjectDependency.resolved_version).where(
            ProjectDependency.library_id == vuln.library_id,
            ProjectDependency.project_id.in_(proj_ids),
        )
        dep_rows = await session.execute(dep_stmt)
        version_map = {row.project_id: row.resolved_version for row in dep_rows}

    client_impact = [
        ClientImpactItem(
            id=ci.id,
            project_id=ci.project_id,
            project_name=proj_names.get(ci.project_id, ""),
            version_used=version_map.get(ci.project_id),
            status=ci.status,
            pipeline_status=ci.pipeline_status,
            is_affected=ci.is_affected,
        )
        for ci in client_impact_rows
    ]

    return UpstreamVulnDetail(
        **{k: getattr(vuln, k) for k in UpstreamVulnListItem.model_fields},
        library_name=lib_name,
        affected_versions=vuln.affected_versions,
        reasoning=vuln.reasoning,
        error_message=vuln.error_message,
        upstream_poc=vuln.upstream_poc,
        affected_functions=vuln.affected_functions,
        client_impact=client_impact,
    )
