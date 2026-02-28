"""Dashboard stats response schemas."""

from __future__ import annotations

from pydantic import BaseModel


class DiskUsage(BaseModel):
    total_gb: float
    used_gb: float
    percent: float


class DashboardResponse(BaseModel):
    projects_count: int
    libraries_count: int
    vuln_recorded: int
    vuln_reported: int
    vuln_confirmed: int
    vuln_fixed: int
    disk: DiskUsage
