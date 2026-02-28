"""Library request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class LibraryListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    repo_url: str
    platform: str
    ecosystem: str = "c_cpp"
    default_branch: str
    latest_tag_version: str | None
    latest_commit_sha: str | None
    monitoring_since: datetime
    last_scanned_at: datetime | None
    collect_status: str = "healthy"
    used_by_count: int = 0
    created_at: datetime


class LibraryUsedBy(BaseModel):
    project_id: uuid.UUID
    project_name: str | None
    constraint_expr: str | None
    resolved_version: str | None
    constraint_source: str


class LibraryDetail(LibraryListItem):
    collect_error: str | None = None
    collect_detail: dict | None = None
    used_by: list[LibraryUsedBy]
    events_tracked: int
