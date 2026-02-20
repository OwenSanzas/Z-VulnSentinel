"""Auth router — login, refresh, me."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.api.deps import get_auth_service, get_current_user, get_session
from vulnsentinel.api.schemas.auth import (
    AccessTokenResponse,
    LoginRequest,
    RefreshRequest,
    TokenPairResponse,
    UserResponse,
)
from vulnsentinel.models.user import User
from vulnsentinel.services.auth_service import AuthService

router = APIRouter()


@router.post("/login", response_model=TokenPairResponse)
async def login(
    body: LoginRequest,
    session: AsyncSession = Depends(get_session),
    auth: AuthService = Depends(get_auth_service),
) -> TokenPairResponse:
    pair = await auth.login(session, body.username, body.password)
    return TokenPairResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type=pair.token_type,
    )


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh(
    body: RefreshRequest,
    auth: AuthService = Depends(get_auth_service),
) -> AccessTokenResponse:
    token = auth.refresh(body.refresh_token)
    return AccessTokenResponse(
        access_token=token.access_token,
        token_type=token.token_type,
    )


@router.get("/me", response_model=UserResponse)
async def me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    return UserResponse.model_validate(current_user)
