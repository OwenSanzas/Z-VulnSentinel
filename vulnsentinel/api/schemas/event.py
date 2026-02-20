"""Event request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from vulnsentinel.api.schemas.upstream_vuln import UpstreamVulnListItem


class EventListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    library_id: uuid.UUID
    type: str
    ref: str
    source_url: str | None
    author: str | None
    title: str
    message: str | None
    classification: str | None
    confidence: float | None
    is_bugfix: bool
    created_at: datetime


class EventDetail(EventListItem):
    related_issue_ref: str | None
    related_issue_url: str | None
    related_pr_ref: str | None
    related_pr_url: str | None
    related_commit_sha: str | None
    related_vulns: list[UpstreamVulnListItem]
