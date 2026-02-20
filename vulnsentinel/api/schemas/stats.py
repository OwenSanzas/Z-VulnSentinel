"""Dashboard stats response schemas."""

from __future__ import annotations

from pydantic import BaseModel


class DashboardResponse(BaseModel):
    projects_count: int
    libraries_count: int
    vuln_recorded: int
    vuln_reported: int
    vuln_confirmed: int
    vuln_fixed: int
