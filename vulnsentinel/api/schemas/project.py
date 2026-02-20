"""Project request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DependencyInputSchema(BaseModel):
    library_name: str
    library_repo_url: str
    constraint_expr: str | None = None
    resolved_version: str | None = None
    constraint_source: str = "manifest"
    platform: str = "github"
    default_branch: str = "main"


class CreateProjectRequest(BaseModel):
    name: str
    repo_url: str
    organization: str | None = None
    contact: str | None = None
    platform: str = "github"
    default_branch: str = "main"
    auto_sync_deps: bool = True
    dependencies: list[DependencyInputSchema] | None = None


class UpdateProjectRequest(BaseModel):
    name: str | None = None
    organization: str | None = None
    contact: str | None = None
    auto_sync_deps: bool | None = None


class ProjectResponse(BaseModel):
    """Base project fields (used for create response)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    organization: str | None
    repo_url: str
    platform: str
    default_branch: str
    contact: str | None
    current_version: str | None
    monitoring_since: datetime
    last_update_at: datetime | None
    auto_sync_deps: bool
    created_at: datetime


class ProjectListItem(ProjectResponse):
    """Project with computed counts (used in list/detail)."""

    deps_count: int
    vuln_count: int


class ProjectDetail(ProjectListItem):
    pass


class DependencyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    library_id: uuid.UUID
    library_name: str
    constraint_expr: str | None
    resolved_version: str | None
    constraint_source: str
    notify_enabled: bool
    created_at: datetime


class UpdateDependencyRequest(BaseModel):
    notify_enabled: bool
