"""Events router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_current_user, get_event_service, get_session
from vulnsentinel.api.schemas.common import PageMeta, PaginatedResponse
from vulnsentinel.api.schemas.event import EventDetail, EventListItem
from vulnsentinel.api.schemas.upstream_vuln import UpstreamVulnListItem
from vulnsentinel.models.library import Library
from vulnsentinel.models.user import User
from vulnsentinel.services.event_service import EventService

router = APIRouter()


async def _library_names(
    session: AsyncSession, library_ids: set[uuid.UUID]
) -> dict[uuid.UUID, str]:
    """Batch-fetch library names by IDs."""
    if not library_ids:
        return {}
    stmt = select(Library.id, Library.name).where(Library.id.in_(library_ids))
    rows = await session.execute(stmt)
    return {row.id: row.name for row in rows}


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
    lib_names = await _library_names(session, {e.library_id for e in result["data"]})
    return PaginatedResponse(
        data=[
            EventListItem(
                **{k: getattr(e, k) for k in EventListItem.model_fields if k != "library_name"},
                library_name=lib_names.get(e.library_id, ""),
            )
            for e in result["data"]
        ],
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
    lib_names = await _library_names(session, {event.library_id})
    return EventDetail(
        **{k: getattr(event, k) for k in EventListItem.model_fields if k != "library_name"},
        library_name=lib_names.get(event.library_id, ""),
        related_issue_ref=event.related_issue_ref,
        related_issue_url=event.related_issue_url,
        related_pr_ref=event.related_pr_ref,
        related_pr_url=event.related_pr_url,
        related_commit_sha=event.related_commit_sha,
        related_vulns=[UpstreamVulnListItem.model_validate(v) for v in related_vulns],
    )
