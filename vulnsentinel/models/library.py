"""libraries table."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, Text, desc, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin


class Library(TimestampMixin, Base):
    __tablename__ = "libraries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    repo_url: Mapped[str] = mapped_column(Text, nullable=False)
    platform: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'github'"))
    ecosystem: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'c_cpp'"))
    default_branch: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'main'"))
    latest_tag_version: Mapped[Optional[str]] = mapped_column(Text)
    latest_commit_sha: Mapped[Optional[str]] = mapped_column(Text)
    monitoring_since: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    collect_status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'healthy'")
    )
    collect_error: Mapped[Optional[str]] = mapped_column(Text)
    collect_detail: Mapped[Optional[dict]] = mapped_column(JSONB)

    __table_args__ = (
        Index(
            "idx_libraries_cursor",
            desc("created_at"),
            desc("id"),
        ),
    )
