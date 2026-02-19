"""client_vulns table."""

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    desc,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin

client_vuln_status_enum = Enum(
    "recorded",
    "reported",
    "confirmed",
    "fixed",
    "not_affect",
    name="client_vuln_status",
    create_type=False,
)
pipeline_status_enum = Enum(
    "pending",
    "path_searching",
    "poc_generating",
    "verified",
    "not_affect",
    name="pipeline_status",
    create_type=False,
)


class ClientVuln(TimestampMixin, Base):
    __tablename__ = "client_vulns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    upstream_vuln_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("upstream_vulns.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )

    # analysis pipeline
    pipeline_status: Mapped[str] = mapped_column(
        pipeline_status_enum, nullable=False, server_default=text("'pending'")
    )
    is_affected: Mapped[Optional[bool]] = mapped_column(Boolean)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    analysis_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    analysis_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # client vuln status
    status: Mapped[Optional[str]] = mapped_column(client_vuln_status_enum)

    # status timeline — system-managed
    recorded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    reported_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    not_affect_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # status timeline — maintainer feedback
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    confirmed_msg: Mapped[Optional[str]] = mapped_column(Text)
    fixed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    fixed_msg: Mapped[Optional[str]] = mapped_column(Text)

    # version analysis (denormalized)
    constraint_expr: Mapped[Optional[str]] = mapped_column(Text)
    constraint_source: Mapped[Optional[str]] = mapped_column(Text)
    resolved_version: Mapped[Optional[str]] = mapped_column(Text)
    fix_version: Mapped[Optional[str]] = mapped_column(Text)
    verdict: Mapped[Optional[str]] = mapped_column(Text)

    # analysis results (JSONB)
    reachable_path: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)
    poc_results: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)
    report: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("upstream_vuln_id", "project_id"),
        Index("idx_clientvulns_upstream", "upstream_vuln_id"),
        Index("idx_clientvulns_project", "project_id"),
        Index("idx_clientvulns_cursor", desc("created_at"), desc("id")),
        Index("idx_clientvulns_status", "status"),
        Index(
            "idx_clientvulns_pipeline",
            "pipeline_status",
            postgresql_where=("pipeline_status IN ('pending', 'path_searching', 'poc_generating')"),
        ),
    )
