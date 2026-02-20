"""Tests for ClientVulnDAO."""

from datetime import datetime, timedelta, timezone

import pytest

from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO, ClientVulnFilters
from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO


@pytest.fixture
def dao():
    return ClientVulnDAO()


@pytest.fixture
def lib_dao():
    return LibraryDAO()


@pytest.fixture
def ev_dao():
    return EventDAO()


@pytest.fixture
def uv_dao():
    return UpstreamVulnDAO()


@pytest.fixture
def proj_dao():
    return ProjectDAO()


# ── shared FK data ────────────────────────────────────────────────────────


@pytest.fixture
async def library(lib_dao, session):
    return await lib_dao.create(session, name="curl", repo_url="https://github.com/curl/curl")


@pytest.fixture
async def library2(lib_dao, session):
    return await lib_dao.create(
        session, name="openssl", repo_url="https://github.com/openssl/openssl"
    )


@pytest.fixture
async def project(proj_dao, session):
    return await proj_dao.create(session, name="my-app", repo_url="https://github.com/org/my-app")


@pytest.fixture
async def project2(proj_dao, session):
    return await proj_dao.create(
        session, name="other-app", repo_url="https://github.com/org/other-app"
    )


@pytest.fixture
async def upstream_vuln(ev_dao, uv_dao, session, library):
    """Create Event → UpstreamVuln chain."""
    ev = await ev_dao.create(
        session,
        library_id=library.id,
        type="commit",
        ref="abc123",
        title="fix: overflow",
    )
    return await uv_dao.create(
        session,
        event_id=ev.id,
        library_id=library.id,
        commit_sha="abc123",
    )


@pytest.fixture
async def upstream_vuln2(ev_dao, uv_dao, session, library):
    ev = await ev_dao.create(
        session,
        library_id=library.id,
        type="commit",
        ref="def456",
        title="fix: uaf",
    )
    return await uv_dao.create(
        session,
        event_id=ev.id,
        library_id=library.id,
        commit_sha="def456",
    )


@pytest.fixture
async def upstream_vuln_lib2(ev_dao, uv_dao, session, library2):
    ev = await ev_dao.create(
        session,
        library_id=library2.id,
        type="commit",
        ref="xyz789",
        title="fix: timing",
    )
    vuln = await uv_dao.create(
        session,
        event_id=ev.id,
        library_id=library2.id,
        commit_sha="xyz789",
    )
    # Set severity for filter tests
    await uv_dao.update_analysis(
        session,
        vuln.id,
        vuln_type="timing_attack",
        severity="medium",
        affected_versions="<3.0",
        summary="timing",
        reasoning="r",
    )
    await session.refresh(vuln)
    return vuln


def _cv(upstream_vuln_id, project_id, **overrides) -> dict:
    defaults = {
        "upstream_vuln_id": upstream_vuln_id,
        "project_id": project_id,
    }
    defaults.update(overrides)
    return defaults


# ── create + get_by_id ────────────────────────────────────────────────────


class TestCreate:
    async def test_create_with_defaults(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        assert cv.id is not None
        assert cv.pipeline_status == "pending"
        assert cv.status is None
        assert cv.is_affected is None

    async def test_get_by_id(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        found = await dao.get_by_id(session, cv.id)
        assert found is not None
        assert found.upstream_vuln_id == upstream_vuln.id


# ── list_by_upstream_vuln ─────────────────────────────────────────────────


class TestListByUpstreamVuln:
    async def test_returns_matching(self, dao, session, upstream_vuln, project, project2):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln.id, project2.id))

        result = await dao.list_by_upstream_vuln(session, upstream_vuln.id)
        assert len(result) == 2
        assert all(r.upstream_vuln_id == upstream_vuln.id for r in result)

    async def test_does_not_return_other_vulns(
        self, dao, session, upstream_vuln, upstream_vuln2, project
    ):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        # upstream_vuln2 + project would violate unique(upstream_vuln_id, project_id)
        # if same project, so use it with project2 not needed — just don't create

        result = await dao.list_by_upstream_vuln(session, upstream_vuln2.id)
        assert result == []

    async def test_empty(self, dao, session, upstream_vuln):
        result = await dao.list_by_upstream_vuln(session, upstream_vuln.id)
        assert result == []


# ── list_by_project ───────────────────────────────────────────────────────


class TestListByProject:
    async def test_returns_only_target_project(
        self, dao, session, upstream_vuln, upstream_vuln2, project, project2
    ):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln2.id, project2.id))

        page = await dao.list_by_project(session, project.id)
        assert len(page.data) == 1
        assert page.data[0].project_id == project.id

    async def test_empty(self, dao, session, project):
        page = await dao.list_by_project(session, project.id)
        assert page.data == []

    async def test_pagination(self, dao, session, project, ev_dao, uv_dao, library):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            ev = await ev_dao.create(
                session,
                library_id=library.id,
                type="commit",
                ref=f"pag_{i}",
                title=f"fix #{i}",
            )
            uv = await uv_dao.create(
                session,
                event_id=ev.id,
                library_id=library.id,
                commit_sha=f"sha_{i}",
            )
            cv = await dao.create(session, **_cv(uv.id, project.id))
            cv.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        page1 = await dao.list_by_project(session, project.id, page_size=3)
        assert len(page1.data) == 3
        assert page1.has_more is True

        page2 = await dao.list_by_project(
            session, project.id, cursor=page1.next_cursor, page_size=3
        )
        assert len(page2.data) == 2
        assert page2.has_more is False


# ── active_count_by_project ───────────────────────────────────────────────


class TestActiveCountByProject:
    async def test_zero(self, dao, session, project):
        assert await dao.active_count_by_project(session, project.id) == 0

    async def test_includes_null_status(self, dao, session, upstream_vuln, project):
        """Newly created vulns (status=NULL, still in pipeline) should be active."""
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        assert await dao.active_count_by_project(session, project.id) == 1

    async def test_excludes_fixed_and_not_affect(
        self,
        dao,
        session,
        upstream_vuln,
        upstream_vuln2,
        project,
        ev_dao,
        uv_dao,
        library,
    ):
        # recorded → active
        cv1 = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.finalize(
            session,
            cv1.id,
            pipeline_status="verified",
            status="recorded",
            is_affected=True,
        )

        # fixed → not active
        cv2 = await dao.create(session, **_cv(upstream_vuln2.id, project.id))
        await dao.update_status(session, cv2.id, status="fixed", msg="patched")

        # Create a third with not_affect
        ev3 = await ev_dao.create(
            session,
            library_id=library.id,
            type="commit",
            ref="na_ref",
            title="fix: na",
        )
        uv3 = await uv_dao.create(
            session,
            event_id=ev3.id,
            library_id=library.id,
            commit_sha="na_sha",
        )
        cv3 = await dao.create(session, **_cv(uv3.id, project.id))
        await dao.finalize(
            session,
            cv3.id,
            pipeline_status="not_affect",
            status="not_affect",
            is_affected=False,
        )

        assert await dao.active_count_by_project(session, project.id) == 1


# ── list_pending_pipeline ─────────────────────────────────────────────────


class TestListPendingPipeline:
    async def test_returns_pending_statuses(
        self,
        dao,
        session,
        upstream_vuln,
        upstream_vuln2,
        project,
        ev_dao,
        uv_dao,
        library,
    ):
        # pending
        cv1 = await dao.create(session, **_cv(upstream_vuln.id, project.id))

        # path_searching
        cv2 = await dao.create(session, **_cv(upstream_vuln2.id, project.id))
        await dao.update_pipeline(session, cv2.id, pipeline_status="path_searching")

        # verified (should be excluded)
        ev3 = await ev_dao.create(
            session,
            library_id=library.id,
            type="commit",
            ref="v_ref",
            title="fix: v",
        )
        uv3 = await uv_dao.create(
            session,
            event_id=ev3.id,
            library_id=library.id,
            commit_sha="v_sha",
        )
        cv3 = await dao.create(session, **_cv(uv3.id, project.id))
        await dao.update_pipeline(session, cv3.id, pipeline_status="verified")

        result = await dao.list_pending_pipeline(session, limit=10)
        ids = {r.id for r in result}
        assert cv1.id in ids
        assert cv2.id in ids
        assert cv3.id not in ids

    async def test_ordered_by_created_at_asc(self, dao, session, project, ev_dao, uv_dao, library):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(3):
            ev = await ev_dao.create(
                session,
                library_id=library.id,
                type="commit",
                ref=f"asc_{i}",
                title=f"fix #{i}",
            )
            uv = await uv_dao.create(
                session,
                event_id=ev.id,
                library_id=library.id,
                commit_sha=f"asc_sha_{i}",
            )
            cv = await dao.create(session, **_cv(uv.id, project.id))
            cv.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        result = await dao.list_pending_pipeline(session, limit=10)
        timestamps = [r.created_at for r in result]
        assert timestamps == sorted(timestamps)  # ASC

    async def test_respects_limit(self, dao, session, project, ev_dao, uv_dao, library):
        for i in range(5):
            ev = await ev_dao.create(
                session,
                library_id=library.id,
                type="commit",
                ref=f"lim_{i}",
                title=f"fix #{i}",
            )
            uv = await uv_dao.create(
                session,
                event_id=ev.id,
                library_id=library.id,
                commit_sha=f"lim_sha_{i}",
            )
            await dao.create(session, **_cv(uv.id, project.id))

        result = await dao.list_pending_pipeline(session, limit=2)
        assert len(result) == 2

    async def test_empty(self, dao, session):
        result = await dao.list_pending_pipeline(session, limit=10)
        assert result == []


# ── update_pipeline ───────────────────────────────────────────────────────


class TestUpdatePipeline:
    async def test_update_status(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_pipeline(session, cv.id, pipeline_status="path_searching")
        await session.refresh(cv)
        assert cv.pipeline_status == "path_searching"

    async def test_update_with_results(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_pipeline(
            session,
            cv.id,
            pipeline_status="verified",
            is_affected=True,
            reachable_path={"path": ["main", "parse_url", "vuln_func"]},
            poc_results={"success": True, "output": "crash"},
        )
        await session.refresh(cv)
        assert cv.is_affected is True
        assert cv.reachable_path == {"path": ["main", "parse_url", "vuln_func"]}
        assert cv.poc_results == {"success": True, "output": "crash"}

    async def test_update_with_error(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_pipeline(
            session,
            cv.id,
            pipeline_status="pending",
            error_message="timeout",
        )
        await session.refresh(cv)
        assert cv.error_message == "timeout"

    async def test_clear_error(self, dao, session, upstream_vuln, project):
        """clear_error=True resets error_message to NULL."""
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_pipeline(
            session, cv.id, pipeline_status="pending", error_message="timeout"
        )
        await session.refresh(cv)
        assert cv.error_message == "timeout"

        await dao.update_pipeline(
            session, cv.id, pipeline_status="path_searching", clear_error=True
        )
        await session.refresh(cv)
        assert cv.error_message is None

    async def test_error_message_takes_priority_over_clear(
        self, dao, session, upstream_vuln, project
    ):
        """If both error_message and clear_error are passed, error_message wins."""
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_pipeline(
            session,
            cv.id,
            pipeline_status="pending",
            error_message="new error",
            clear_error=True,
        )
        await session.refresh(cv)
        assert cv.error_message == "new error"

    async def test_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.update_pipeline(session, None, pipeline_status="pending")


# ── finalize ──────────────────────────────────────────────────────────────


class TestFinalize:
    async def test_finalize_recorded(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.finalize(
            session,
            cv.id,
            pipeline_status="verified",
            status="recorded",
            is_affected=True,
        )
        await session.refresh(cv)
        assert cv.pipeline_status == "verified"
        assert cv.status == "recorded"
        assert cv.is_affected is True
        assert cv.analysis_completed_at is not None
        assert cv.recorded_at is not None
        assert cv.not_affect_at is None

    async def test_finalize_not_affect(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.finalize(
            session,
            cv.id,
            pipeline_status="not_affect",
            status="not_affect",
            is_affected=False,
        )
        await session.refresh(cv)
        assert cv.status == "not_affect"
        assert cv.is_affected is False
        assert cv.not_affect_at is not None
        assert cv.recorded_at is None

    async def test_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.finalize(
                session,
                None,
                pipeline_status="verified",
                status="recorded",
                is_affected=True,
            )


# ── update_status ─────────────────────────────────────────────────────────


class TestUpdateStatus:
    async def test_confirmed(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_status(session, cv.id, status="confirmed", msg="verified by maintainer")
        await session.refresh(cv)
        assert cv.status == "confirmed"
        assert cv.confirmed_at is not None
        assert cv.confirmed_msg == "verified by maintainer"
        assert cv.fixed_at is None

    async def test_fixed(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_status(session, cv.id, status="fixed", msg="patched in v2.0")
        await session.refresh(cv)
        assert cv.status == "fixed"
        assert cv.fixed_at is not None
        assert cv.fixed_msg == "patched in v2.0"
        assert cv.confirmed_at is None

    async def test_confirmed_then_fixed(self, dao, session, upstream_vuln, project):
        """Confirm first, then fix — both timestamps should be set."""
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_status(session, cv.id, status="confirmed", msg="yes")
        await dao.update_status(session, cv.id, status="fixed", msg="done")
        await session.refresh(cv)
        assert cv.status == "fixed"
        assert cv.confirmed_at is not None
        assert cv.fixed_at is not None

    async def test_without_msg(self, dao, session, upstream_vuln, project):
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_status(session, cv.id, status="confirmed")
        await session.refresh(cv)
        assert cv.status == "confirmed"
        assert cv.confirmed_at is not None
        assert cv.confirmed_msg is None

    async def test_reported_sets_reported_at(self, dao, session, upstream_vuln, project):
        """Status 'reported' sets reported_at but not confirmed/fixed timestamps."""
        cv = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.update_status(session, cv.id, status="reported")
        await session.refresh(cv)
        assert cv.status == "reported"
        assert cv.reported_at is not None
        assert cv.confirmed_at is None
        assert cv.fixed_at is None

    async def test_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.update_status(session, None, status="confirmed")


# ── count_by_status ───────────────────────────────────────────────────────


class TestCountByStatus:
    async def test_empty(self, dao, session):
        result = await dao.count_by_status(session)
        assert result == {
            "total_recorded": 0,
            "total_reported": 0,
            "total_confirmed": 0,
            "total_fixed": 0,
        }

    async def test_forward_inclusive_counting(self, dao, session, project, ev_dao, uv_dao, library):
        """recorded includes recorded+reported+confirmed+fixed."""
        statuses = ["recorded", "reported", "confirmed", "fixed"]
        for i, status in enumerate(statuses):
            ev = await ev_dao.create(
                session,
                library_id=library.id,
                type="commit",
                ref=f"st_{i}",
                title=f"fix #{i}",
            )
            uv = await uv_dao.create(
                session,
                event_id=ev.id,
                library_id=library.id,
                commit_sha=f"st_sha_{i}",
            )
            cv = await dao.create(session, **_cv(uv.id, project.id))
            await dao.finalize(
                session,
                cv.id,
                pipeline_status="verified",
                status=status,
                is_affected=True,
            )

        result = await dao.count_by_status(session)
        assert result["total_recorded"] == 4  # all four
        assert result["total_reported"] == 3  # reported + confirmed + fixed
        assert result["total_confirmed"] == 2  # confirmed + fixed
        assert result["total_fixed"] == 1  # fixed only

    async def test_filter_by_project(
        self, dao, session, project, project2, ev_dao, uv_dao, library
    ):
        # project: recorded
        ev1 = await ev_dao.create(
            session,
            library_id=library.id,
            type="commit",
            ref="p1",
            title="fix",
        )
        uv1 = await uv_dao.create(
            session,
            event_id=ev1.id,
            library_id=library.id,
            commit_sha="s1",
        )
        cv1 = await dao.create(session, **_cv(uv1.id, project.id))
        await dao.finalize(
            session,
            cv1.id,
            pipeline_status="verified",
            status="recorded",
            is_affected=True,
        )

        # project2: fixed
        ev2 = await ev_dao.create(
            session,
            library_id=library.id,
            type="commit",
            ref="p2",
            title="fix",
        )
        uv2 = await uv_dao.create(
            session,
            event_id=ev2.id,
            library_id=library.id,
            commit_sha="s2",
        )
        cv2 = await dao.create(session, **_cv(uv2.id, project2.id))
        await dao.finalize(
            session,
            cv2.id,
            pipeline_status="verified",
            status="fixed",
            is_affected=True,
        )

        r1 = await dao.count_by_status(session, project_id=project.id)
        assert r1["total_recorded"] == 1
        assert r1["total_fixed"] == 0

        r2 = await dao.count_by_status(session, project_id=project2.id)
        assert r2["total_recorded"] == 1  # fixed is also recorded
        assert r2["total_fixed"] == 1


# ── list_paginated with filters ──────────────────────────────────────────


class TestListPaginatedFiltered:
    async def test_no_filters(self, dao, session, upstream_vuln, project):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        page = await dao.list_paginated(session)
        assert len(page.data) == 1

    async def test_filter_by_status(self, dao, session, upstream_vuln, upstream_vuln2, project):
        cv1 = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln2.id, project.id))
        await dao.finalize(
            session,
            cv1.id,
            pipeline_status="verified",
            status="recorded",
            is_affected=True,
        )

        page = await dao.list_paginated(session, filters=ClientVulnFilters(status="recorded"))
        assert len(page.data) == 1
        assert page.data[0].id == cv1.id

    async def test_filter_by_project(
        self, dao, session, upstream_vuln, upstream_vuln2, project, project2
    ):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln2.id, project2.id))

        page = await dao.list_paginated(session, filters=ClientVulnFilters(project_id=project.id))
        assert len(page.data) == 1
        assert page.data[0].project_id == project.id

    async def test_filter_by_severity(
        self,
        dao,
        session,
        upstream_vuln,
        upstream_vuln_lib2,
        project,
        uv_dao,
    ):
        # upstream_vuln has no severity set; upstream_vuln_lib2 has "medium"
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln_lib2.id, project.id))

        page = await dao.list_paginated(session, filters=ClientVulnFilters(severity="medium"))
        assert len(page.data) == 1
        assert page.data[0].upstream_vuln_id == upstream_vuln_lib2.id

    async def test_filter_by_library(
        self,
        dao,
        session,
        upstream_vuln,
        upstream_vuln_lib2,
        project,
        library,
        library2,
    ):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln_lib2.id, project.id))

        page = await dao.list_paginated(session, filters=ClientVulnFilters(library_id=library2.id))
        assert len(page.data) == 1
        assert page.data[0].upstream_vuln_id == upstream_vuln_lib2.id

    async def test_filter_by_date_range(self, dao, session, upstream_vuln, upstream_vuln2, project):
        base = datetime(2026, 6, 1, tzinfo=timezone.utc)
        cv1 = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        cv1.created_at = base
        cv2 = await dao.create(session, **_cv(upstream_vuln2.id, project.id))
        cv2.created_at = base + timedelta(days=10)
        await session.flush()

        page = await dao.list_paginated(
            session,
            filters=ClientVulnFilters(
                date_from=base + timedelta(days=5),
                date_to=base + timedelta(days=15),
            ),
        )
        assert len(page.data) == 1
        assert page.data[0].id == cv2.id


# ── count with filters ────────────────────────────────────────────────────


class TestCountFiltered:
    async def test_count_no_filters(self, dao, session, upstream_vuln, project):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        assert await dao.count(session) == 1

    async def test_count_with_status_filter(
        self, dao, session, upstream_vuln, upstream_vuln2, project
    ):
        cv1 = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln2.id, project.id))
        await dao.finalize(
            session,
            cv1.id,
            pipeline_status="verified",
            status="recorded",
            is_affected=True,
        )

        assert await dao.count(session, filters=ClientVulnFilters(status="recorded")) == 1

    async def test_count_with_severity_filter(
        self, dao, session, upstream_vuln, upstream_vuln_lib2, project
    ):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln_lib2.id, project.id))

        assert await dao.count(session, filters=ClientVulnFilters(severity="medium")) == 1

    async def test_count_with_library_filter(
        self,
        dao,
        session,
        upstream_vuln,
        upstream_vuln_lib2,
        project,
        library,
        library2,
    ):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln_lib2.id, project.id))

        assert await dao.count(session, filters=ClientVulnFilters(library_id=library2.id)) == 1
        assert await dao.count(session, filters=ClientVulnFilters(library_id=library.id)) == 1

    async def test_count_with_project_filter(
        self, dao, session, upstream_vuln, upstream_vuln2, project, project2
    ):
        await dao.create(session, **_cv(upstream_vuln.id, project.id))
        await dao.create(session, **_cv(upstream_vuln2.id, project2.id))

        assert await dao.count(session, filters=ClientVulnFilters(project_id=project.id)) == 1

    async def test_count_with_date_filter(
        self, dao, session, upstream_vuln, upstream_vuln2, project
    ):
        base = datetime(2026, 6, 1, tzinfo=timezone.utc)
        cv1 = await dao.create(session, **_cv(upstream_vuln.id, project.id))
        cv1.created_at = base
        cv2 = await dao.create(session, **_cv(upstream_vuln2.id, project.id))
        cv2.created_at = base + timedelta(days=10)
        await session.flush()

        assert (
            await dao.count(
                session,
                filters=ClientVulnFilters(
                    date_from=base + timedelta(days=5),
                    date_to=base + timedelta(days=15),
                ),
            )
            == 1
        )

    async def test_count_empty(self, dao, session):
        assert await dao.count(session) == 0
