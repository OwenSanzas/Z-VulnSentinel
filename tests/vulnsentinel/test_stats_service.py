"""Tests for StatsService."""

from unittest.mock import AsyncMock

from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.services.client_vuln_service import ClientVulnService
from vulnsentinel.services.stats_service import StatsService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service() -> tuple[StatsService, ProjectDAO, LibraryDAO, ClientVulnService]:
    project_dao = ProjectDAO()
    library_dao = LibraryDAO()
    cv_service = ClientVulnService.__new__(ClientVulnService)
    service = StatsService(project_dao, library_dao, cv_service)
    return service, project_dao, library_dao, cv_service


# ---------------------------------------------------------------------------
# get_dashboard
# ---------------------------------------------------------------------------


class TestGetDashboard:
    async def test_get_dashboard(self):
        service, project_dao, library_dao, cv_service = _make_service()
        project_dao.count = AsyncMock(return_value=12)
        library_dao.count = AsyncMock(return_value=45)
        cv_service.get_stats = AsyncMock(
            return_value={
                "total_recorded": 100,
                "total_reported": 60,
                "total_confirmed": 30,
                "total_fixed": 10,
            }
        )

        session = AsyncMock()
        result = await service.get_dashboard(session)

        assert result["projects_count"] == 12
        assert result["libraries_count"] == 45
        assert result["vuln_recorded"] == 100
        assert result["vuln_reported"] == 60
        assert result["vuln_confirmed"] == 30
        assert result["vuln_fixed"] == 10
        project_dao.count.assert_awaited_once_with(session)
        library_dao.count.assert_awaited_once_with(session)
        cv_service.get_stats.assert_awaited_once_with(session)

    async def test_get_dashboard_empty(self):
        service, project_dao, library_dao, cv_service = _make_service()
        project_dao.count = AsyncMock(return_value=0)
        library_dao.count = AsyncMock(return_value=0)
        cv_service.get_stats = AsyncMock(
            return_value={
                "total_recorded": 0,
                "total_reported": 0,
                "total_confirmed": 0,
                "total_fixed": 0,
            }
        )

        result = await service.get_dashboard(AsyncMock())

        assert result["projects_count"] == 0
        assert result["libraries_count"] == 0
        assert result["vuln_recorded"] == 0
        assert result["vuln_fixed"] == 0
