"""Libraries router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_current_user, get_library_service, get_session
from vulnsentinel.api.schemas.common import PageMeta, PaginatedResponse
from vulnsentinel.api.schemas.library import LibraryDetail, LibraryListItem, LibraryUsedBy
from vulnsentinel.models.user import User
from vulnsentinel.services.library_service import LibraryService

router = APIRouter()


@router.get("/", response_model=PaginatedResponse[LibraryListItem])
async def list_libraries(
    cursor: str | None = Query(None),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: LibraryService = Depends(get_library_service),
) -> PaginatedResponse[LibraryListItem]:
    result = await svc.list(session, cursor=cursor, page_size=page_size)
    return PaginatedResponse(
        data=[LibraryListItem.model_validate(lib) for lib in result["data"]],
        meta=PageMeta(
            next_cursor=result["next_cursor"],
            has_more=result["has_more"],
            total=result["total"],
        ),
    )


@router.get("/{library_id}", response_model=LibraryDetail)
async def get_library(
    library_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: LibraryService = Depends(get_library_service),
) -> LibraryDetail:
    result = await svc.get(session, library_id)
    lib = result["library"]
    detail = LibraryDetail(
        **{k: getattr(lib, k) for k in LibraryListItem.model_fields},
        used_by=[LibraryUsedBy(**u) for u in result["used_by"]],
        events_tracked=result["events_tracked"],
    )
    return detail
