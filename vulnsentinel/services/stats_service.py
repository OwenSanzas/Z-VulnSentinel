"""StatsService — dashboard statistics aggregation."""

from __future__ import annotations

import shutil

from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.services.client_vuln_service import ClientVulnService


class StatsService:
    """Stateless service for dashboard statistics."""

    def __init__(
        self,
        project_dao: ProjectDAO,
        library_dao: LibraryDAO,
        client_vuln_service: ClientVulnService,
    ) -> None:
        self._project_dao = project_dao
        self._library_dao = library_dao
        self._cv_service = client_vuln_service

    @staticmethod
    def _get_disk_usage() -> dict:
        """Return disk usage for the root partition."""
        usage = shutil.disk_usage("/")
        total_gb = round(usage.total / (1024**3), 1)
        used_gb = round(usage.used / (1024**3), 1)
        percent = round(usage.used / usage.total * 100, 1)
        return {"total_gb": total_gb, "used_gb": used_gb, "percent": percent}

    async def get_dashboard(self, session: AsyncSession) -> dict:
        """Return aggregated stats for the main dashboard."""
        projects_count = await self._project_dao.count(session)
        libraries_count = await self._library_dao.count(session)
        vuln_stats = await self._cv_service.get_stats(session)

        return {
            "projects_count": projects_count,
            "libraries_count": libraries_count,
            "vuln_recorded": vuln_stats["total_recorded"],
            "vuln_reported": vuln_stats["total_reported"],
            "vuln_confirmed": vuln_stats["total_confirmed"],
            "vuln_fixed": vuln_stats["total_fixed"],
            "disk": self._get_disk_usage(),
        }
