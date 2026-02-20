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
    default_branch: str
    latest_tag_version: str | None
    latest_commit_sha: str | None
    monitoring_since: datetime
    last_activity_at: datetime | None
    created_at: datetime


class LibraryUsedBy(BaseModel):
    project_id: uuid.UUID
    project_name: str | None
    constraint_expr: str | None
    resolved_version: str | None
    constraint_source: str


class LibraryDetail(LibraryListItem):
    used_by: list[LibraryUsedBy]
    events_tracked: int
