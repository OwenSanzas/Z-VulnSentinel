"""Upstream vulnerability request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class UpstreamVulnListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event_id: uuid.UUID
    library_id: uuid.UUID
    commit_sha: str
    vuln_type: str | None
    severity: str | None
    status: str
    summary: str | None
    detected_at: datetime
    published_at: datetime | None
    created_at: datetime


class ClientImpactItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    status: str | None
    pipeline_status: str
    is_affected: bool | None


class UpstreamVulnDetail(UpstreamVulnListItem):
    affected_versions: str | None
    reasoning: str | None
    error_message: str | None
    upstream_poc: dict[str, Any] | None
    client_impact: list[ClientImpactItem]
