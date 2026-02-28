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
    page: int = Query(0, ge=0),
    page_size: int = Query(20, ge=1, le=100),
    sort_by: str = Query("name"),
    sort_dir: str = Query("asc"),
    status: str | None = Query(None),
    ecosystem: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: LibraryService = Depends(get_library_service),
) -> PaginatedResponse[LibraryListItem]:
    result = await svc.list(
        session,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_dir=sort_dir,
        status=status,
        ecosystem=ecosystem,
    )
    used_by = result["used_by_counts"]
    total = result["total"]
    total_pages = (total + page_size - 1) // page_size if total else 0
    return PaginatedResponse(
        data=[
            LibraryListItem(
                **{k: getattr(lib, k) for k in LibraryListItem.model_fields if k != "used_by_count"},
                used_by_count=used_by.get(lib.id, 0),
            )
            for lib in result["data"]
        ],
        meta=PageMeta(
            next_cursor=None,
            has_more=page < total_pages - 1,
            total=total,
            page=result["page"],
            total_pages=total_pages,
        ),
    )


@router.get("/health-summary")
async def health_summary(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: LibraryService = Depends(get_library_service),
) -> dict:
    return await svc.health_summary(session)


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
        **{k: getattr(lib, k) for k in LibraryListItem.model_fields if k != "used_by_count"},
        collect_error=lib.collect_error,
        collect_detail=lib.collect_detail,
        used_by=[LibraryUsedBy(**u) for u in result["used_by"]],
        used_by_count=len(result["used_by"]),
        events_tracked=result["events_tracked"],
    )
    return detail
