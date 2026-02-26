"""upstream_vulns table."""

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Text, desc, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin

severity_level_enum = Enum(
    "critical",
    "high",
    "medium",
    "low",
    name="severity_level",
    create_type=False,
)
upstream_vuln_status_enum = Enum(
    "analyzing",
    "published",
    name="upstream_vuln_status",
    create_type=False,
)


class UpstreamVuln(TimestampMixin, Base):
    __tablename__ = "upstream_vulns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("events.id", ondelete="CASCADE"),
        nullable=False,
    )
    library_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("libraries.id", ondelete="CASCADE"),
        nullable=False,
    )
    commit_sha: Mapped[str] = mapped_column(Text, nullable=False)
    vuln_type: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(severity_level_enum)
    affected_versions: Mapped[Optional[str]] = mapped_column(Text)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    reasoning: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        upstream_vuln_status_enum, nullable=False, server_default=text("'analyzing'")
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    upstream_poc: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)
    affected_functions: Mapped[Optional[list]] = mapped_column(JSONB)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_upvulns_event", "event_id"),
        Index("idx_upvulns_library", "library_id"),
        Index("idx_upvulns_cursor", desc("created_at"), desc("id")),
        Index("idx_upvulns_status", "status"),
    )
