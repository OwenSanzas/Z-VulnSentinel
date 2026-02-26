"""Mailer — async SMTP email sending via asyncio.to_thread."""

from __future__ import annotations

import asyncio
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class Mailer:
    """Thin async wrapper around smtplib SMTP + STARTTLS."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        user: str | None = None,
        password: str | None = None,
        from_addr: str | None = None,
    ) -> None:
        self.host = host or os.getenv("VULNSENTINEL_SMTP_HOST", "smtp.gmail.com")
        self.port = port or int(os.getenv("VULNSENTINEL_SMTP_PORT", "587"))
        self.user = user or os.getenv("VULNSENTINEL_SMTP_USER", "")
        self.password = password or os.getenv("VULNSENTINEL_SMTP_PASSWORD", "")
        self.from_addr = from_addr or os.getenv("VULNSENTINEL_SMTP_FROM", "") or self.user

    async def send(self, to: str, subject: str, html_body: str) -> None:
        """Send an HTML email via SMTP in a background thread."""
        await asyncio.to_thread(self._send_sync, to, subject, html_body)

    def _send_sync(self, to: str, subject: str, html_body: str) -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = to
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(self.host, self.port) as server:
            server.starttls()
            server.login(self.user, self.password)
            server.sendmail(self.from_addr, [to], msg.as_string())
