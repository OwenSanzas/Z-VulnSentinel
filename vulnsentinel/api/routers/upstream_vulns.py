"""Upstream vulnerabilities router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_current_user, get_session, get_upstream_vuln_service
from vulnsentinel.api.schemas.common import PageMeta, PaginatedResponse
from vulnsentinel.api.schemas.upstream_vuln import (
    ClientImpactItem,
    UpstreamVulnDetail,
    UpstreamVulnListItem,
)
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
    result = await svc.list(
        session, cursor=cursor, page_size=page_size, library_id=library_id
    )
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
    return UpstreamVulnDetail(
        **{k: getattr(vuln, k) for k in UpstreamVulnListItem.model_fields},
        affected_versions=vuln.affected_versions,
        reasoning=vuln.reasoning,
        error_message=vuln.error_message,
        upstream_poc=vuln.upstream_poc,
        client_impact=[ClientImpactItem.model_validate(ci) for ci in result["client_impact"]],
    )
