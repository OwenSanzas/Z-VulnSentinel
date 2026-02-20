"""Client vulnerabilities router."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
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
from vulnsentinel.models.user import User
from vulnsentinel.services.client_vuln_service import ClientVulnFilters, ClientVulnService

router = APIRouter()


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
    return ClientVulnListResponse(
        data=[ClientVulnListItem.model_validate(cv) for cv in result["data"]],
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
    return ClientVulnDetail(
        **{k: getattr(cv, k) for k in ClientVulnDetail.model_fields if k != "upstream_vuln"},
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
