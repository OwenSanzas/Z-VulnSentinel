"""Snapshots router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_current_user, get_session, get_snapshot_service
from vulnsentinel.api.schemas.snapshot import SnapshotResponse
from vulnsentinel.models.user import User
from vulnsentinel.services.snapshot_service import SnapshotService

router = APIRouter()


@router.get("/{snapshot_id}", response_model=SnapshotResponse)
async def get_snapshot(
    snapshot_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
    svc: SnapshotService = Depends(get_snapshot_service),
) -> SnapshotResponse:
    snapshot = await svc.get(session, snapshot_id)
    return SnapshotResponse.model_validate(snapshot)
