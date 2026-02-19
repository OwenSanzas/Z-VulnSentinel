"""Tests for AuthService."""

import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import bcrypt
import pytest
from jose import jwt

from vulnsentinel.dao.user_dao import UserDAO
from vulnsentinel.models.user import User
from vulnsentinel.services import AuthenticationError
from vulnsentinel.services.auth_service import (
    _ACCESS_TOKEN_EXPIRE,
    _ALGORITHM,
    _REFRESH_TOKEN_EXPIRE,
    AccessToken,
    AuthService,
    TokenPair,
)

# Shared test secret
TEST_SECRET = "test-jwt-secret-for-unit-tests"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(
    *,
    user_id: uuid.UUID | None = None,
    username: str = "alice",
    email: str = "alice@example.com",
    password: str = "s3cret!",
    role: str = "admin",
) -> User:
    """Build a User ORM object without hitting the database."""
    u = User(
        id=user_id or uuid.uuid4(),
        username=username,
        email=email,
        password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        role=role,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    return u


def _make_service() -> tuple[AuthService, UserDAO]:
    """Create an AuthService with a mocked UserDAO."""
    dao = UserDAO()
    service = AuthService(dao)
    return service, dao


def _encode_token(payload: dict, secret: str = TEST_SECRET) -> str:
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


# ---------------------------------------------------------------------------
# ensure_admin_exists
# ---------------------------------------------------------------------------


class TestEnsureAdminExists:
    """Tests for AuthService.ensure_admin_exists."""

    async def test_creates_admin_when_env_set(self):
        service, dao = _make_service()
        session = AsyncMock()
        user = _make_user()
        dao.upsert = AsyncMock(return_value=user)

        env = {
            "VULNSENTINEL_ADMIN_USERNAME": "admin",
            "VULNSENTINEL_ADMIN_EMAIL": "admin@example.com",
            "VULNSENTINEL_ADMIN_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env, clear=False):
            await service.ensure_admin_exists(session)

        dao.upsert.assert_awaited_once()
        call_kwargs = dao.upsert.call_args
        assert call_kwargs.kwargs["username"] == "admin"
        assert call_kwargs.kwargs["email"] == "admin@example.com"
        assert call_kwargs.kwargs["role"] == "admin"
        # password_hash should be a bcrypt hash, not the plaintext
        assert call_kwargs.kwargs["password_hash"] != "password123"
        assert bcrypt.checkpw(b"password123", call_kwargs.kwargs["password_hash"].encode())

    async def test_skips_when_username_missing(self):
        service, dao = _make_service()
        session = AsyncMock()
        dao.upsert = AsyncMock()

        env = {
            "VULNSENTINEL_ADMIN_EMAIL": "admin@example.com",
            "VULNSENTINEL_ADMIN_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env, clear=False):
            # Remove the username key if it exists
            os.environ.pop("VULNSENTINEL_ADMIN_USERNAME", None)
            await service.ensure_admin_exists(session)

        dao.upsert.assert_not_awaited()

    async def test_skips_when_email_missing(self):
        service, dao = _make_service()
        session = AsyncMock()
        dao.upsert = AsyncMock()

        env = {
            "VULNSENTINEL_ADMIN_USERNAME": "admin",
            "VULNSENTINEL_ADMIN_PASSWORD": "password123",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("VULNSENTINEL_ADMIN_EMAIL", None)
            await service.ensure_admin_exists(session)

        dao.upsert.assert_not_awaited()

    async def test_skips_when_password_missing(self):
        service, dao = _make_service()
        session = AsyncMock()
        dao.upsert = AsyncMock()

        env = {
            "VULNSENTINEL_ADMIN_USERNAME": "admin",
            "VULNSENTINEL_ADMIN_EMAIL": "admin@example.com",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("VULNSENTINEL_ADMIN_PASSWORD", None)
            await service.ensure_admin_exists(session)

        dao.upsert.assert_not_awaited()


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


class TestLogin:
    """Tests for AuthService.login."""

    async def test_login_success(self):
        password = "s3cret!"
        user = _make_user(password=password)
        service, dao = _make_service()
        dao.get_by_username = AsyncMock(return_value=user)

        with patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}):
            result = await service.login(AsyncMock(), user.username, password)

        assert isinstance(result, TokenPair)
        assert result.token_type == "bearer"

        # Decode access token
        access = jwt.decode(result.access_token, TEST_SECRET, algorithms=[_ALGORITHM])
        assert access["sub"] == str(user.id)
        assert access["type"] == "access"
        assert "role" not in access

        # Decode refresh token
        refresh = jwt.decode(result.refresh_token, TEST_SECRET, algorithms=[_ALGORITHM])
        assert refresh["sub"] == str(user.id)
        assert refresh["type"] == "refresh"
        assert "role" not in refresh

    async def test_login_user_not_found(self):
        service, dao = _make_service()
        dao.get_by_username = AsyncMock(return_value=None)

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid credentials"),
        ):
            await service.login(AsyncMock(), "nobody", "password")

    async def test_login_wrong_password(self):
        user = _make_user(password="correct-password")
        service, dao = _make_service()
        dao.get_by_username = AsyncMock(return_value=user)

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid credentials"),
        ):
            await service.login(AsyncMock(), user.username, "wrong-password")

    async def test_login_access_token_expiry(self):
        """Access token should expire around 30 minutes from now."""
        user = _make_user()
        service, dao = _make_service()
        dao.get_by_username = AsyncMock(return_value=user)

        with patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}):
            result = await service.login(AsyncMock(), user.username, "s3cret!")

        payload = jwt.decode(result.access_token, TEST_SECRET, algorithms=[_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = exp - now
        # Should be close to 30 minutes (allow 10 seconds tolerance)
        assert abs(delta - _ACCESS_TOKEN_EXPIRE) < timedelta(seconds=10)

    async def test_login_refresh_token_expiry(self):
        """Refresh token should expire around 7 days from now."""
        user = _make_user()
        service, dao = _make_service()
        dao.get_by_username = AsyncMock(return_value=user)

        with patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}):
            result = await service.login(AsyncMock(), user.username, "s3cret!")

        payload = jwt.decode(result.refresh_token, TEST_SECRET, algorithms=[_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = exp - now
        assert abs(delta - _REFRESH_TOKEN_EXPIRE) < timedelta(seconds=10)

    async def test_login_no_jwt_secret_raises(self):
        user = _make_user()
        service, dao = _make_service()
        dao.get_by_username = AsyncMock(return_value=user)

        with (
            patch.dict(os.environ, {}, clear=False),
            pytest.raises(RuntimeError, match="VULNSENTINEL_JWT_SECRET"),
        ):
            os.environ.pop("VULNSENTINEL_JWT_SECRET", None)
            await service.login(AsyncMock(), user.username, "s3cret!")


# ---------------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------------


class TestRefresh:
    """Tests for AuthService.refresh."""

    async def test_refresh_success(self):
        user_id = uuid.uuid4()
        service, _ = _make_service()

        refresh_token = _encode_token(
            {
                "sub": str(user_id),
                "type": "refresh",
                "exp": datetime.now(timezone.utc) + timedelta(days=7),
            }
        )

        with patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}):
            result = service.refresh(refresh_token)

        assert isinstance(result, AccessToken)
        assert result.token_type == "bearer"

        payload = jwt.decode(result.access_token, TEST_SECRET, algorithms=[_ALGORITHM])
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"

    async def test_refresh_invalid_token(self):
        service, _ = _make_service()

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid refresh token"),
        ):
            service.refresh("not-a-valid-jwt")

    async def test_refresh_expired_token(self):
        service, _ = _make_service()

        expired_token = _encode_token(
            {
                "sub": str(uuid.uuid4()),
                "type": "refresh",
                "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            }
        )

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid refresh token"),
        ):
            service.refresh(expired_token)

    async def test_refresh_wrong_token_type(self):
        """Using an access token for refresh should fail."""
        service, _ = _make_service()

        access_token = _encode_token(
            {
                "sub": str(uuid.uuid4()),
                "type": "access",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            }
        )

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid token type"),
        ):
            service.refresh(access_token)

    async def test_refresh_wrong_secret(self):
        """Token signed with a different secret should fail."""
        service, _ = _make_service()

        token = jwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "type": "refresh",
                "exp": datetime.now(timezone.utc) + timedelta(days=7),
            },
            "different-secret",
            algorithm=_ALGORITHM,
        )

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid refresh token"),
        ):
            service.refresh(token)

    async def test_refresh_is_stateless(self):
        """Refresh should NOT call any DAO method."""
        service, dao = _make_service()
        dao.get_by_id = AsyncMock()
        dao.get_by_username = AsyncMock()

        refresh_token = _encode_token(
            {
                "sub": str(uuid.uuid4()),
                "type": "refresh",
                "exp": datetime.now(timezone.utc) + timedelta(days=7),
            }
        )

        with patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}):
            service.refresh(refresh_token)

        dao.get_by_id.assert_not_awaited()
        dao.get_by_username.assert_not_awaited()

    async def test_refresh_missing_sub(self):
        """Refresh token without sub should raise."""
        service, _ = _make_service()

        token = _encode_token(
            {
                "type": "refresh",
                "exp": datetime.now(timezone.utc) + timedelta(days=7),
            }
        )

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid token payload"),
        ):
            service.refresh(token)


# ---------------------------------------------------------------------------
# get_current_user
# ---------------------------------------------------------------------------


class TestGetCurrentUser:
    """Tests for AuthService.get_current_user."""

    async def test_get_current_user_success(self):
        user = _make_user()
        service, dao = _make_service()
        dao.get_by_id = AsyncMock(return_value=user)

        token = _encode_token(
            {
                "sub": str(user.id),
                "type": "access",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            }
        )

        session = AsyncMock()
        with patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}):
            result = await service.get_current_user(session, token)

        assert result.id == user.id
        dao.get_by_id.assert_awaited_once_with(session, user.id)

    async def test_get_current_user_invalid_token(self):
        service, _ = _make_service()

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid access token"),
        ):
            await service.get_current_user(AsyncMock(), "garbage")

    async def test_get_current_user_wrong_token_type(self):
        """Using a refresh token for authentication should fail."""
        service, _ = _make_service()

        refresh_token = _encode_token(
            {
                "sub": str(uuid.uuid4()),
                "type": "refresh",
                "exp": datetime.now(timezone.utc) + timedelta(days=7),
            }
        )

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid token type"),
        ):
            await service.get_current_user(AsyncMock(), refresh_token)

    async def test_get_current_user_user_deleted(self):
        """If the user no longer exists, should raise."""
        service, dao = _make_service()
        dao.get_by_id = AsyncMock(return_value=None)

        token = _encode_token(
            {
                "sub": str(uuid.uuid4()),
                "type": "access",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            }
        )

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="user not found"),
        ):
            await service.get_current_user(AsyncMock(), token)

    async def test_get_current_user_expired_token(self):
        service, _ = _make_service()

        token = _encode_token(
            {
                "sub": str(uuid.uuid4()),
                "type": "access",
                "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            }
        )

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid access token"),
        ):
            await service.get_current_user(AsyncMock(), token)

    async def test_get_current_user_bad_sub_format(self):
        """Token with invalid UUID in sub should raise."""
        service, _ = _make_service()

        token = _encode_token(
            {
                "sub": "not-a-uuid",
                "type": "access",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            }
        )

        with (
            patch.dict(os.environ, {"VULNSENTINEL_JWT_SECRET": TEST_SECRET}),
            pytest.raises(AuthenticationError, match="invalid token payload"),
        ):
            await service.get_current_user(AsyncMock(), token)


# ---------------------------------------------------------------------------
# TokenPair / AccessToken
# ---------------------------------------------------------------------------


class TestTokenDataClasses:
    def test_token_pair(self):
        tp = TokenPair("access", "refresh")
        assert tp.access_token == "access"
        assert tp.refresh_token == "refresh"
        assert tp.token_type == "bearer"

    def test_access_token(self):
        at = AccessToken("access")
        assert at.access_token == "access"
        assert at.token_type == "bearer"
