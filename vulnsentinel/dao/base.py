"""Generic base DAO — CRUD (ORM) + cursor pagination (Core)."""

import base64
import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

from sqlalchemy import Select, func, select, tuple_
from sqlalchemy import exists as sa_exists
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.core.database import Base

ModelT = TypeVar("ModelT", bound=Base)

PAGE_SIZE_MIN = 1
PAGE_SIZE_MAX = 100
PAGE_SIZE_DEFAULT = 20

# HMAC secret for cursor signing.
# In production set VULNSENTINEL_CURSOR_SECRET env var.
_CURSOR_SECRET: bytes = os.environ.get(
    "VULNSENTINEL_CURSOR_SECRET", "changeme-cursor-secret"
).encode()


class InvalidCursorError(ValueError):
    """Raised when a cursor string cannot be decoded or has invalid signature."""


@dataclass
class Cursor:
    """Decoded cursor: (created_at, id)."""

    created_at: datetime
    id: uuid.UUID


@dataclass
class Page(Generic[ModelT]):
    """Paginated result set."""

    data: list[ModelT]
    next_cursor: str | None
    has_more: bool
    total: int | None = None


def _sign(payload: str) -> str:
    """Return a truncated HMAC-SHA256 hex digest for *payload*."""
    return hmac.new(_CURSOR_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:16]


def encode_cursor(created_at: datetime, row_id: uuid.UUID) -> str:
    """Encode (created_at, id) into a signed, URL-safe base64 string."""
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    payload = json.dumps(
        {
            "c": created_at.isoformat(),
            "i": str(row_id),
        }
    )
    sig = _sign(payload)
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def decode_cursor(cursor: str) -> Cursor:
    """Decode a signed base64 cursor string back to (created_at, id).

    Raises ``InvalidCursorError`` for malformed or tampered cursors.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        payload, sig = raw.rsplit("|", 1)
        expected = _sign(payload)
        if not hmac.compare_digest(sig, expected):
            raise InvalidCursorError(f"cursor signature mismatch: {cursor!r}")
        data = json.loads(payload)
        return Cursor(
            created_at=datetime.fromisoformat(data["c"]),
            id=uuid.UUID(data["i"]),
        )
    except InvalidCursorError:
        raise
    except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError) as exc:
        raise InvalidCursorError(f"invalid cursor: {cursor!r}") from exc


def _clamp_page_size(page_size: int) -> int:
    return max(PAGE_SIZE_MIN, min(page_size, PAGE_SIZE_MAX))


class BaseDAO(Generic[ModelT]):
    """Base data-access object. Subclasses set ``model`` class attribute."""

    model: type[ModelT]

    # ── ORM methods ──────────────────────────────────────────────────────

    @staticmethod
    def _require_pk(pk: uuid.UUID) -> None:
        """Raise ValueError if *pk* is None."""
        if pk is None:
            raise ValueError("pk must not be None")

    async def get_by_id(self, session: AsyncSession, pk: uuid.UUID) -> ModelT | None:
        self._require_pk(pk)
        return await session.get(self.model, pk)

    async def create(self, session: AsyncSession, **values: Any) -> ModelT:
        obj = self.model(**values)
        session.add(obj)
        await session.flush()
        await session.refresh(obj)
        return obj

    async def bulk_create(self, session: AsyncSession, items: list[dict[str, Any]]) -> list[ModelT]:
        """Insert multiple rows in a single flush.

        After flush, primary keys (``id``) are available via RETURNING.
        Other ``server_default`` columns (``created_at``, ``updated_at``)
        are **not** eagerly loaded — accessing them without an explicit
        ``session.refresh(obj)`` will raise ``MissingGreenlet`` in async.
        Set ``eager_defaults=True`` on the mapper to change this behavior.

        For upsert (ON CONFLICT) semantics, override in the sub-DAO with
        a Core ``insert().on_conflict_do_update()`` statement.
        """
        objs = [self.model(**vals) for vals in items]
        session.add_all(objs)
        await session.flush()
        return objs

    async def update(self, session: AsyncSession, pk: uuid.UUID, **values: Any) -> ModelT | None:
        self._require_pk(pk)
        obj = await session.get(self.model, pk)
        if obj is None:
            return None
        immutable = {"id", "created_at", "updated_at"}
        column_keys = set(self.model.__mapper__.column_attrs.keys())
        for key in values:
            if key in immutable:
                raise AttributeError(f"'{key}' is immutable and cannot be updated")
            if key not in column_keys:
                raise AttributeError(f"{self.model.__name__} has no column '{key}'")
        for key, val in values.items():
            setattr(obj, key, val)
        await session.flush()
        await session.refresh(obj)
        return obj

    async def delete(self, session: AsyncSession, pk: uuid.UUID) -> bool:
        self._require_pk(pk)
        obj = await session.get(self.model, pk)
        if obj is None:
            return False
        await session.delete(obj)
        await session.flush()
        return True

    async def exists(self, session: AsyncSession, pk: uuid.UUID) -> bool:
        """Check existence without loading the full ORM object."""
        self._require_pk(pk)
        table = self.model.__table__
        stmt = select(sa_exists().where(table.c.id == pk))
        result = await session.execute(stmt)
        return result.scalar_one()

    async def get_by_field(self, session: AsyncSession, **filters: Any) -> ModelT | None:
        """Return the first row matching all *filters*, or None.

        Usage::

            user = await dao.get_by_field(session, username="alice")

        Raises ``ValueError`` if called without any filters.
        """
        if not filters:
            raise ValueError("get_by_field() requires at least one filter")
        stmt = select(self.model)
        for key, val in filters.items():
            stmt = stmt.where(getattr(self.model, key) == val)
        result = await session.execute(stmt)
        return result.scalars().first()

    # ── Core methods ─────────────────────────────────────────────────────

    async def paginate(
        self,
        session: AsyncSession,
        query: Select,
        cursor: str | None = None,
        page_size: int = PAGE_SIZE_DEFAULT,
    ) -> Page[ModelT]:
        """Apply cursor-based pagination to *query*.

        The query must select from a table that has ``created_at`` and ``id``
        columns. Ordering (created_at DESC, id DESC) and LIMIT are appended
        by this method — callers should NOT add their own ORDER BY / LIMIT.

        Raises ``InvalidCursorError`` if *cursor* is malformed.
        """
        page_size = _clamp_page_size(page_size)
        table = self.model.__table__

        if cursor:
            cur = decode_cursor(cursor)
            query = query.where(tuple_(table.c.created_at, table.c.id) < (cur.created_at, cur.id))

        query = query.order_by(
            table.c.created_at.desc(),
            table.c.id.desc(),
        ).limit(page_size + 1)

        result = await session.execute(query)
        rows = list(result.scalars().all())

        has_more = len(rows) > page_size
        data = rows[:page_size]

        next_cursor = None
        if has_more and data:
            last = data[-1]
            next_cursor = encode_cursor(last.created_at, last.id)

        return Page(data=data, next_cursor=next_cursor, has_more=has_more)

    async def count(self, session: AsyncSession, query: Select | None = None) -> int:
        """Return the row count for *query*, or total rows if query is None."""
        if query is None:
            query = select(func.count()).select_from(self.model.__table__)
        else:
            query = select(func.count()).select_from(query.subquery())

        result = await session.execute(query)
        return result.scalar_one()
