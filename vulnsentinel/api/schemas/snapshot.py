"""Snapshot request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CreateSnapshotRequest(BaseModel):
    repo_url: str
    repo_name: str
    version: str
    backend: str
    trigger_type: str | None = None


class SnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID | None
    repo_url: str
    repo_name: str
    version: str
    backend: str
    status: str
    trigger_type: str | None
    is_active: bool
    storage_path: str | None
    node_count: int
    edge_count: int
    fuzzer_names: list[str]
    analysis_duration_sec: float
    language: str
    size_bytes: int
    error: str | None
    created_at: datetime
