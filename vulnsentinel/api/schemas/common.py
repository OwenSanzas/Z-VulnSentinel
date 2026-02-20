"""Shared pagination schemas."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class PageMeta(BaseModel):
    """Cursor-based pagination metadata."""

    next_cursor: str | None
    has_more: bool
    total: int | None = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated list response."""

    data: list[T]
    meta: PageMeta
