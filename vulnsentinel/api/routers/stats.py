"""Stats router — dashboard aggregates."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_current_user, get_session, get_stats_service
from vulnsentinel.api.schemas.stats import DashboardResponse
from vulnsentinel.models.user import User
from vulnsentinel.services.stats_service import StatsService

router = APIRouter()


@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: StatsService = Depends(get_stats_service),
) -> DashboardResponse:
    result = await svc.get_dashboard(session)
    return DashboardResponse(**result)
