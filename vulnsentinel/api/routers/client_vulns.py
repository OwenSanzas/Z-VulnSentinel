"""Client vulnerabilities router."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_client_vuln_service, get_current_user, get_session
from vulnsentinel.api.schemas.client_vuln import (
    ClientVulnDetail,
    ClientVulnListItem,
    ClientVulnListResponse,
    UpdateStatusRequest,
    VulnStatsResponse,
)
from vulnsentinel.api.schemas.common import PageMeta
from vulnsentinel.api.schemas.upstream_vuln import UpstreamVulnListItem
from vulnsentinel.models.library import Library
from vulnsentinel.models.project import Project
from vulnsentinel.models.upstream_vuln import UpstreamVuln
from vulnsentinel.models.user import User
from vulnsentinel.services.client_vuln_service import ClientVulnFilters, ClientVulnService

router = APIRouter()


async def _enrich_client_vulns(
    session: AsyncSession,
    client_vulns: list,
) -> list[ClientVulnListItem]:
    """Batch-enrich client vuln ORM objects with denormalized fields."""
    if not client_vulns:
        return []

    uv_ids = {cv.upstream_vuln_id for cv in client_vulns}
    proj_ids = {cv.project_id for cv in client_vulns}

    # Batch fetch upstream vulns (summary, severity, library_id)
    uv_stmt = select(
        UpstreamVuln.id, UpstreamVuln.summary, UpstreamVuln.severity, UpstreamVuln.library_id
    ).where(UpstreamVuln.id.in_(uv_ids))
    uv_rows = await session.execute(uv_stmt)
    uv_map = {row.id: row for row in uv_rows}

    # Batch fetch project names
    proj_stmt = select(Project.id, Project.name).where(Project.id.in_(proj_ids))
    proj_rows = await session.execute(proj_stmt)
    proj_names = {row.id: row.name for row in proj_rows}

    # Batch fetch library names
    lib_ids = {uv.library_id for uv in uv_map.values()}
    lib_stmt = select(Library.id, Library.name).where(Library.id.in_(lib_ids))
    lib_rows = await session.execute(lib_stmt)
    lib_names = {row.id: row.name for row in lib_rows}

    items = []
    for cv in client_vulns:
        uv = uv_map.get(cv.upstream_vuln_id)
        items.append(
            ClientVulnListItem(
                id=cv.id,
                upstream_vuln_id=cv.upstream_vuln_id,
                project_id=cv.project_id,
                library_name=lib_names.get(uv.library_id, "") if uv else "",
                project_name=proj_names.get(cv.project_id, ""),
                summary=uv.summary if uv else None,
                severity=uv.severity if uv else None,
                pipeline_status=cv.pipeline_status,
                status=cv.status,
                is_affected=cv.is_affected,
                recorded_at=cv.recorded_at,
                created_at=cv.created_at,
            )
        )
    return items


@router.get("/stats", response_model=VulnStatsResponse)
async def get_client_vuln_stats(
    project_id: uuid.UUID | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ClientVulnService = Depends(get_client_vuln_service),
) -> VulnStatsResponse:
    stats = await svc.get_stats(session, project_id=project_id)
    return VulnStatsResponse(**stats)


@router.get("/", response_model=ClientVulnListResponse)
async def list_client_vulns(
    cursor: str | None = Query(None),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    library_id: uuid.UUID | None = Query(None),
    project_id: uuid.UUID | None = Query(None),
    date_from: datetime | None = Query(None),
    date_to: datetime | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ClientVulnService = Depends(get_client_vuln_service),
) -> ClientVulnListResponse:
    filters = ClientVulnFilters(
        status=status,
        severity=severity,
        library_id=library_id,
        project_id=project_id,
        date_from=date_from,
        date_to=date_to,
    )
    result = await svc.list(session, cursor=cursor, page_size=page_size, filters=filters)
    enriched = await _enrich_client_vulns(session, result["data"])
    return ClientVulnListResponse(
        data=enriched,
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
            total=result["total"],
        ),
        stats=VulnStatsResponse(**result["stats"]),
    )


@router.get("/{vuln_id}", response_model=ClientVulnDetail)
async def get_client_vuln(
    vuln_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ClientVulnService = Depends(get_client_vuln_service),
) -> ClientVulnDetail:
    result = await svc.get(session, vuln_id)
    cv = result["client_vuln"]
    uv = result["upstream_vuln"]

    # Fetch library_name and project_name
    lib_stmt = select(Library.name).where(Library.id == uv.library_id)
    lib_name = (await session.execute(lib_stmt)).scalar_one_or_none() or ""

    proj_stmt = select(Project.name).where(Project.id == cv.project_id)
    proj_name = (await session.execute(proj_stmt)).scalar_one_or_none() or ""

    return ClientVulnDetail(
        id=cv.id,
        upstream_vuln_id=cv.upstream_vuln_id,
        project_id=cv.project_id,
        library_id=uv.library_id,
        library_name=lib_name,
        project_name=proj_name,
        summary=uv.summary,
        severity=uv.severity,
        pipeline_status=cv.pipeline_status,
        status=cv.status,
        is_affected=cv.is_affected,
        recorded_at=cv.recorded_at,
        created_at=cv.created_at,
        constraint_expr=cv.constraint_expr,
        constraint_source=cv.constraint_source,
        resolved_version=cv.resolved_version,
        fix_version=cv.fix_version,
        verdict=cv.verdict,
        reachable_path=cv.reachable_path,
        poc_results=cv.poc_results,
        report=cv.report,
        error_message=cv.error_message,
        reported_at=cv.reported_at,
        confirmed_at=cv.confirmed_at,
        confirmed_msg=cv.confirmed_msg,
        fixed_at=cv.fixed_at,
        fixed_msg=cv.fixed_msg,
        upstream_vuln=UpstreamVulnListItem.model_validate(uv),
    )


@router.patch("/{vuln_id}/status", status_code=204)
async def update_client_vuln_status(
    vuln_id: uuid.UUID,
    body: UpdateStatusRequest,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: ClientVulnService = Depends(get_client_vuln_service),
) -> None:
    await svc.update_status(session, vuln_id, status=body.status, msg=body.msg)
