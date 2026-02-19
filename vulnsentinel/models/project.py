"""projects table."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, Text, desc, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin


class Project(TimestampMixin, Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    organization: Mapped[Optional[str]] = mapped_column(Text)
    repo_url: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    platform: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'github'")
    )
    default_branch: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'main'")
    )
    contact: Mapped[Optional[str]] = mapped_column(Text)
    current_version: Mapped[Optional[str]] = mapped_column(Text)
    monitoring_since: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_update_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )

    __table_args__ = (
        Index("idx_projects_cursor", desc("created_at"), desc("id")),
    )
