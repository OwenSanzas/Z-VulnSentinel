"""Shared pagination schemas."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class PageMeta(BaseModel):
    """Pagination metadata (supports both cursor and offset modes)."""

    next_cursor: str | None
    has_more: bool
    total: int | None = None
    page: int | None = None
    total_pages: int | None = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated list response."""

    data: list[T]
    meta: PageMeta
