"""Tests for the notification engine."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from vulnsentinel.dao.client_vuln_dao import ClientVulnDAO
from vulnsentinel.dao.event_dao import EventDAO
from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.dao.project_dao import ProjectDAO
from vulnsentinel.dao.upstream_vuln_dao import UpstreamVulnDAO
from vulnsentinel.engines.notification.mailer import Mailer
from vulnsentinel.engines.notification.runner import NotificationRunner
from vulnsentinel.engines.notification.template import render_notification
from vulnsentinel.services.client_vuln_service import ClientVulnService

# ── fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def cv_dao():
    return ClientVulnDAO()


@pytest.fixture
def uv_dao():
    return UpstreamVulnDAO()


@pytest.fixture
def lib_dao():
    return LibraryDAO()


@pytest.fixture
def ev_dao():
    return EventDAO()


@pytest.fixture
def proj_dao():
    return ProjectDAO()


@pytest.fixture
async def library(lib_dao, session):
    return await lib_dao.create(session, name="curl", repo_url="https://github.com/curl/curl")


@pytest.fixture
async def project(proj_dao, session):
    return await proj_dao.create(session, name="my-app", repo_url="https://github.com/org/my-app")


@pytest.fixture
async def upstream_vuln(ev_dao, uv_dao, session, library):
    ev = await ev_dao.create(
        session,
        library_id=library.id,
        type="commit",
        ref="abc123",
        title="fix: overflow",
    )
    vuln = await uv_dao.create(
        session,
        event_id=ev.id,
        library_id=library.id,
        commit_sha="abc123",
    )
    await uv_dao.update_analysis(
        session,
        vuln.id,
        vuln_type="buffer_overflow",
        severity="high",
        affected_versions="<1.0",
        summary="Stack buffer overflow in parse_url",
        reasoning="test",
    )
    await uv_dao.publish(session, vuln.id)
    await session.refresh(vuln)
    return vuln


@pytest.fixture
async def verified_cv(cv_dao, session, upstream_vuln, project):
    """A client_vuln in verified+recorded state, ready for notification."""
    cv = await cv_dao.create(
        session,
        upstream_vuln_id=upstream_vuln.id,
        project_id=project.id,
        fix_version="1.0.1",
    )
    await cv_dao.finalize(
        session,
        cv.id,
        pipeline_status="verified",
        status="recorded",
        is_affected=True,
    )
    await session.refresh(cv)
    return cv


# ── DAO: list_verified_unnotified ─────────────────────────────────────────


class TestListVerifiedUnnotified:
    @pytest.mark.asyncio
    async def test_returns_verified_recorded_with_null_reported_at(
        self, cv_dao, session, verified_cv
    ):
        result = await cv_dao.list_verified_unnotified(session, limit=10)
        assert len(result) == 1
        assert result[0].id == verified_cv.id

    @pytest.mark.asyncio
    async def test_excludes_already_reported(self, cv_dao, session, verified_cv):
        await cv_dao.update_status(session, verified_cv.id, status="reported")
        result = await cv_dao.list_verified_unnotified(session, limit=10)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_excludes_not_affect(self, cv_dao, session, upstream_vuln, project):
        cv = await cv_dao.create(
            session,
            upstream_vuln_id=upstream_vuln.id,
            project_id=project.id,
        )
        await cv_dao.finalize(
            session,
            cv.id,
            pipeline_status="not_affect",
            status="not_affect",
            is_affected=False,
        )
        result = await cv_dao.list_verified_unnotified(session, limit=10)
        # Should not include the not_affect record
        ids = [r.id for r in result]
        assert cv.id not in ids

    @pytest.mark.asyncio
    async def test_respects_limit(self, cv_dao, session, verified_cv):
        result = await cv_dao.list_verified_unnotified(session, limit=0)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_orders_by_created_at_asc(
        self, cv_dao, ev_dao, uv_dao, session, library, project
    ):
        # Create two verified CVs
        ids = []
        for i, ref in enumerate(["ref1", "ref2"]):
            ev = await ev_dao.create(
                session, library_id=library.id, type="commit", ref=ref, title=f"fix {i}"
            )
            uv = await uv_dao.create(session, event_id=ev.id, library_id=library.id, commit_sha=ref)
            # Need a unique project per upstream_vuln+project pair
            proj = await ProjectDAO().create(
                session, name=f"proj-{ref}", repo_url=f"https://github.com/org/{ref}"
            )
            cv = await cv_dao.create(session, upstream_vuln_id=uv.id, project_id=proj.id)
            await cv_dao.finalize(
                session, cv.id, pipeline_status="verified", status="recorded", is_affected=True
            )
            ids.append(cv.id)

        result = await cv_dao.list_verified_unnotified(session, limit=10)
        result_ids = [r.id for r in result]
        # First created should come first (asc)
        assert result_ids.index(ids[0]) < result_ids.index(ids[1])


# ── DAO: set_report ───────────────────────────────────────────────────────


class TestSetReport:
    @pytest.mark.asyncio
    async def test_stores_report_jsonb(self, cv_dao, session, verified_cv):
        report = {"type": "email", "to": "test@example.com", "subject": "test"}
        await cv_dao.set_report(session, verified_cv.id, report=report)
        await session.refresh(verified_cv)
        assert verified_cv.report == report


# ── Template rendering ────────────────────────────────────────────────────


class TestRenderNotification:
    @pytest.mark.asyncio
    async def test_subject_format(self, session, project, library, upstream_vuln, verified_cv):
        subject, body = render_notification(project, library, upstream_vuln, verified_cv)
        assert "[VulnSentinel]" in subject
        assert "HIGH" in subject
        assert library.name in subject
        assert project.name in subject

    @pytest.mark.asyncio
    async def test_body_contains_key_info(
        self, session, project, library, upstream_vuln, verified_cv
    ):
        subject, body = render_notification(project, library, upstream_vuln, verified_cv)
        assert project.name in body
        assert library.name in body
        assert upstream_vuln.commit_sha in body
        assert "Stack buffer overflow" in body
        assert "1.0.1" in body  # fix_version


# ── Runner: notify_one ────────────────────────────────────────────────────


class TestNotifyOne:
    @pytest.mark.asyncio
    async def test_sends_email_and_marks_reported(
        self, cv_dao, uv_dao, session, verified_cv, upstream_vuln, library, project
    ):
        mailer = Mailer(
            host="localhost", port=587, user="u", password="p", from_addr="from@test.com"
        )
        mailer.send = AsyncMock()

        # Use real cv_service (thin DAO wrapper) for status transition
        cv_service = ClientVulnService(cv_dao, uv_dao)

        # Mock services that need complex construction
        uv_service = AsyncMock()
        uv_service.get.return_value = {"vuln": upstream_vuln}

        lib_service = AsyncMock()
        lib_service.get_by_id.return_value = library

        project_service = AsyncMock()
        project_service.get_project.return_value = project

        runner = NotificationRunner(
            client_vuln_service=cv_service,
            upstream_vuln_service=uv_service,
            library_service=lib_service,
            project_service=project_service,
            mailer=mailer,
        )
        runner._notify_to = "alert@example.com"

        await runner.notify_one(session, verified_cv)

        # Email was sent
        mailer.send.assert_called_once()
        call_args = mailer.send.call_args
        assert call_args[0][0] == "alert@example.com"
        assert "[VulnSentinel]" in call_args[0][1]

        # Status transitioned to reported
        await session.refresh(verified_cv)
        assert verified_cv.status == "reported"
        assert verified_cv.reported_at is not None

        # Report JSONB was stored
        assert verified_cv.report is not None
        assert verified_cv.report["type"] == "email"
        assert verified_cv.report["to"] == "alert@example.com"

    @pytest.mark.asyncio
    async def test_not_sent_again_after_reported(self, cv_dao, uv_dao, session, verified_cv):
        """After notification, list_verified_unnotified should not return this CV."""
        await cv_dao.update_status(session, verified_cv.id, status="reported")
        result = await cv_dao.list_verified_unnotified(session, limit=10)
        assert all(r.id != verified_cv.id for r in result)
