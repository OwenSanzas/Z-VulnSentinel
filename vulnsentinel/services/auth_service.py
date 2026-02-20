"""AuthService — JWT authentication and admin bootstrap."""

import os
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.user_dao import UserDAO
from vulnsentinel.models.user import User
from vulnsentinel.services import AuthenticationError

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def _hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode(), password_hash.encode())


# ---------------------------------------------------------------------------
# JWT configuration
# ---------------------------------------------------------------------------

# Pre-computed bcrypt hash for timing-safe login (user-not-found path)
_DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt()).decode()

_ALGORITHM = "HS256"
_ACCESS_TOKEN_EXPIRE = timedelta(minutes=30)
_REFRESH_TOKEN_EXPIRE = timedelta(days=7)

# Environment variable keys
_ENV_JWT_SECRET = "VULNSENTINEL_JWT_SECRET"
_ENV_ADMIN_USERNAME = "VULNSENTINEL_ADMIN_USERNAME"
_ENV_ADMIN_EMAIL = "VULNSENTINEL_ADMIN_EMAIL"
_ENV_ADMIN_PASSWORD = "VULNSENTINEL_ADMIN_PASSWORD"


def _get_secret() -> str:
    """Read JWT secret from environment. Raises if not set."""
    secret = os.environ.get(_ENV_JWT_SECRET)
    if not secret:
        raise RuntimeError(f"{_ENV_JWT_SECRET} environment variable is required")
    return secret


# ---------------------------------------------------------------------------
# Token data classes
# ---------------------------------------------------------------------------


class TokenPair:
    """Access + refresh token pair returned by login."""

    __slots__ = ("access_token", "refresh_token", "token_type")

    def __init__(self, access_token: str, refresh_token: str) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_type = "bearer"


class AccessToken:
    """Single access token returned by refresh."""

    __slots__ = ("access_token", "token_type")

    def __init__(self, access_token: str) -> None:
        self.access_token = access_token
        self.token_type = "bearer"


# ---------------------------------------------------------------------------
# AuthService
# ---------------------------------------------------------------------------


class AuthService:
    """Stateless authentication service.

    Handles JWT token lifecycle and admin user bootstrapping.
    """

    def __init__(self, user_dao: UserDAO) -> None:
        self._user_dao = user_dao

    # -- Bootstrap ---------------------------------------------------------

    async def ensure_admin_exists(self, session: AsyncSession) -> None:
        """Create the initial admin user from environment variables.

        Reads ``VULNSENTINEL_ADMIN_USERNAME``, ``VULNSENTINEL_ADMIN_EMAIL``,
        and ``VULNSENTINEL_ADMIN_PASSWORD``. Silently skips if any are missing.
        """
        username = os.environ.get(_ENV_ADMIN_USERNAME)
        email = os.environ.get(_ENV_ADMIN_EMAIL)
        password = os.environ.get(_ENV_ADMIN_PASSWORD)

        if not all([username, email, password]):
            return

        password_hash = _hash_password(password)
        await self._user_dao.upsert(
            session,
            username=username,
            email=email,
            password_hash=password_hash,
            role="admin",
        )

    # -- Login / Token -----------------------------------------------------

    async def login(self, session: AsyncSession, username: str, password: str) -> TokenPair:
        """Verify credentials and return an access + refresh token pair.

        Raises :class:`AuthenticationError` on invalid credentials.
        Does not distinguish between "user not found" and "wrong password".
        """
        user = await self._user_dao.get_by_username(session, username)
        if user is None:
            # Constant-time: run bcrypt even when user doesn't exist
            _verify_password(password, _DUMMY_HASH)
            raise AuthenticationError("invalid credentials")
        if not _verify_password(password, user.password_hash):
            raise AuthenticationError("invalid credentials")

        secret = _get_secret()
        now = datetime.now(timezone.utc)

        access_token = jwt.encode(
            {
                "sub": str(user.id),
                "type": "access",
                "exp": now + _ACCESS_TOKEN_EXPIRE,
            },
            secret,
            algorithm=_ALGORITHM,
        )

        refresh_token = jwt.encode(
            {
                "sub": str(user.id),
                "type": "refresh",
                "exp": now + _REFRESH_TOKEN_EXPIRE,
            },
            secret,
            algorithm=_ALGORITHM,
        )

        return TokenPair(access_token, refresh_token)

    def refresh(self, refresh_token: str) -> AccessToken:
        """Validate a refresh token and issue a new access token.

        Stateless — no database query. Token revocation requires a future
        Redis blacklist.

        Raises :class:`AuthenticationError` on invalid or expired token.
        """
        secret = _get_secret()
        try:
            payload = jwt.decode(refresh_token, secret, algorithms=[_ALGORITHM])
        except JWTError:
            raise AuthenticationError("invalid refresh token")

        if payload.get("type") != "refresh":
            raise AuthenticationError("invalid token type")

        sub = payload.get("sub")
        if not sub:
            raise AuthenticationError("invalid token payload")

        now = datetime.now(timezone.utc)
        access_token = jwt.encode(
            {
                "sub": sub,
                "type": "access",
                "exp": now + _ACCESS_TOKEN_EXPIRE,
            },
            secret,
            algorithm=_ALGORITHM,
        )

        return AccessToken(access_token)

    async def get_current_user(self, session: AsyncSession, token: str) -> User:
        """Decode an access token and return the corresponding user.

        Intended for use as a FastAPI dependency.

        Raises :class:`AuthenticationError` on invalid token or unknown user.
        """
        secret = _get_secret()
        try:
            payload = jwt.decode(token, secret, algorithms=[_ALGORITHM])
        except JWTError:
            raise AuthenticationError("invalid access token")

        if payload.get("type") != "access":
            raise AuthenticationError("invalid token type")

        try:
            user_id = uuid.UUID(payload["sub"])
        except (KeyError, ValueError):
            raise AuthenticationError("invalid token payload")

        user = await self._user_dao.get_by_id(session, user_id)
        if user is None:
            raise AuthenticationError("user not found")

        return user
