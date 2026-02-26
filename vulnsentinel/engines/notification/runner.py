"""NotificationRunner — send email alerts for verified vulnerabilities."""

from __future__ import annotations

import os
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnsentinel.engines.notification.mailer import Mailer
from vulnsentinel.engines.notification.template import render_notification
from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.services.client_vuln_service import ClientVulnService
from vulnsentinel.services.library_service import LibraryService
from vulnsentinel.services.project_service import ProjectService
from vulnsentinel.services.upstream_vuln_service import UpstreamVulnService

log = structlog.get_logger("vulnsentinel.engine.notification")


class NotificationRunner:
    """Poll verified-but-unnotified client_vulns and send email notifications."""

    def __init__(
        self,
        client_vuln_service: ClientVulnService,
        upstream_vuln_service: UpstreamVulnService,
        library_service: LibraryService,
        project_service: ProjectService,
        mailer: Mailer,
    ) -> None:
        self._cv_service = client_vuln_service
        self._uv_service = upstream_vuln_service
        self._lib_service = library_service
        self._project_service = project_service
        self._mailer = mailer
        self._notify_to = os.getenv("VULNSENTINEL_NOTIFY_TO", "")

    async def notify_one(self, session: AsyncSession, client_vuln: ClientVuln) -> None:
        """Send notification for a single verified client_vuln.

        Steps:
        1. Load upstream_vuln, library, project.
        2. Render email subject + body.
        3. Send via mailer.
        4. Store report JSONB and transition status to 'reported'.
        """
        # 1. Load related records
        uv_detail = await self._uv_service.get(session, client_vuln.upstream_vuln_id)
        upstream_vuln = uv_detail["vuln"]

        library = await self._lib_service.get_by_id(session, upstream_vuln.library_id)
        project = await self._project_service.get_project(session, client_vuln.project_id)

        if library is None or project is None:
            log.error(
                "notification.missing_related_record",
                client_vuln_id=str(client_vuln.id),
                library_found=library is not None,
                project_found=project is not None,
            )
            return

        # 2. Render email
        subject, html_body = render_notification(project, library, upstream_vuln, client_vuln)

        # 3. Send
        to = self._notify_to or self._mailer.from_addr
        await self._mailer.send(to, subject, html_body)

        # 4. Store report and update status
        report: dict[str, Any] = {
            "type": "email",
            "to": to,
            "subject": subject,
        }
        await self._cv_service.set_report(session, client_vuln.id, report=report)
        await self._cv_service.update_status(session, client_vuln.id, status="reported")

        log.info(
            "notification.sent",
            client_vuln_id=str(client_vuln.id),
            to=to,
            severity=upstream_vuln.severity,
        )

    async def run_batch(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        limit: int = 20,
    ) -> int:
        """Poll verified-unnotified client_vulns and send notifications.

        Each client_vuln is processed in its own session for isolation.
        Returns the number of notifications sent.
        """
        async with session_factory() as session:
            pending = await self._cv_service.list_verified_unnotified(session, limit)
        if not pending:
            return 0

        sent = 0
        for cv in pending:
            try:
                async with session_factory() as session:
                    await self.notify_one(session, cv)
                    await session.commit()
                    sent += 1
            except Exception:
                log.error(
                    "notification.batch_failed",
                    client_vuln_id=str(cv.id),
                    exc_info=True,
                )

        return sent
