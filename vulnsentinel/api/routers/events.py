"""Events router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_current_user, get_event_service, get_session
from vulnsentinel.api.schemas.common import PageMeta, PaginatedResponse
from vulnsentinel.api.schemas.event import EventDetail, EventListItem
from vulnsentinel.api.schemas.upstream_vuln import UpstreamVulnListItem
from vulnsentinel.models.user import User
from vulnsentinel.services.event_service import EventService

router = APIRouter()


@router.get("/", response_model=PaginatedResponse[EventListItem])
async def list_events(
    cursor: str | None = Query(None),
    page_size: int = Query(20, ge=1, le=100),
    library_id: uuid.UUID | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: EventService = Depends(get_event_service),
) -> PaginatedResponse[EventListItem]:
    result = await svc.list(session, cursor=cursor, page_size=page_size, library_id=library_id)
    return PaginatedResponse(
        data=[EventListItem.model_validate(e) for e in result["data"]],
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
            total=result["total"],
        ),
    )


@router.get("/{event_id}", response_model=EventDetail)
async def get_event(
    event_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: EventService = Depends(get_event_service),
) -> EventDetail:
    result = await svc.get(session, event_id)
    event = result["event"]
    related_vulns = result.get("related_vulns", [])
    return EventDetail(
        **{k: getattr(event, k) for k in EventListItem.model_fields},
        related_issue_ref=event.related_issue_ref,
        related_issue_url=event.related_issue_url,
        related_pr_ref=event.related_pr_ref,
        related_pr_url=event.related_pr_url,
        related_commit_sha=event.related_commit_sha,
        related_vulns=[UpstreamVulnListItem.model_validate(v) for v in related_vulns],
    )
