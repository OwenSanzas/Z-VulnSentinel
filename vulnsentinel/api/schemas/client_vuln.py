"""Client vulnerability request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from vulnsentinel.api.schemas.common import PageMeta
from vulnsentinel.api.schemas.upstream_vuln import UpstreamVulnListItem


class ClientVulnListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    upstream_vuln_id: uuid.UUID
    project_id: uuid.UUID
    pipeline_status: str
    status: str | None
    is_affected: bool | None
    created_at: datetime


class ClientVulnDetail(ClientVulnListItem):
    constraint_expr: str | None
    constraint_source: str | None
    resolved_version: str | None
    fix_version: str | None
    verdict: str | None
    reachable_path: dict[str, Any] | None
    poc_results: dict[str, Any] | None
    report: dict[str, Any] | None
    error_message: str | None
    recorded_at: datetime | None
    reported_at: datetime | None
    confirmed_at: datetime | None
    confirmed_msg: str | None
    fixed_at: datetime | None
    fixed_msg: str | None
    upstream_vuln: UpstreamVulnListItem


class VulnStatsResponse(BaseModel):
    total_recorded: int
    total_reported: int
    total_confirmed: int
    total_fixed: int


class UpdateStatusRequest(BaseModel):
    status: str
    msg: str | None = None


class ClientVulnListResponse(BaseModel):
    data: list[ClientVulnListItem]
    meta: PageMeta
    stats: VulnStatsResponse
