"""events table."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Double,
    Enum,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    desc,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin

event_type_enum = Enum(
    "commit",
    "pr_merge",
    "tag",
    "bug_issue",
    name="event_type",
    create_type=False,
)
event_classification_enum = Enum(
    "security_bugfix",
    "normal_bugfix",
    "refactor",
    "feature",
    "other",
    name="event_classification",
    create_type=False,
)


class Event(TimestampMixin, Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    library_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("libraries.id", ondelete="CASCADE"),
        nullable=False,
    )
    type: Mapped[str] = mapped_column(event_type_enum, nullable=False)
    ref: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(Text)
    author: Mapped[Optional[str]] = mapped_column(Text)
    event_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    title: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text)

    # related references
    related_issue_ref: Mapped[Optional[str]] = mapped_column(Text)
    related_issue_url: Mapped[Optional[str]] = mapped_column(Text)
    related_pr_ref: Mapped[Optional[str]] = mapped_column(Text)
    related_pr_url: Mapped[Optional[str]] = mapped_column(Text)
    related_commit_sha: Mapped[Optional[str]] = mapped_column(Text)

    # classification
    classification: Mapped[Optional[str]] = mapped_column(event_classification_enum)
    confidence: Mapped[Optional[float]] = mapped_column(Double)
    is_bugfix: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    __table_args__ = (
        UniqueConstraint("library_id", "type", "ref", name="uq_events_library_type_ref"),
        Index("idx_events_library", "library_id"),
        Index("idx_events_cursor", desc("created_at"), desc("id")),
        Index(
            "idx_events_bugfix",
            desc("created_at"),
            postgresql_where="is_bugfix = TRUE",
        ),
        Index(
            "idx_events_unclassified",
            desc("created_at"),
            postgresql_where="classification IS NULL",
        ),
    )
