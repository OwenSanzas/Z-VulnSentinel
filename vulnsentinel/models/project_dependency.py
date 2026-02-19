"""project_dependencies table."""

import uuid
from typing import Optional

from sqlalchemy import ForeignKey, Index, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin


class ProjectDependency(TimestampMixin, Base):
    __tablename__ = "project_dependencies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    library_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("libraries.id", ondelete="CASCADE"),
        nullable=False,
    )
    constraint_expr: Mapped[Optional[str]] = mapped_column(Text)
    resolved_version: Mapped[Optional[str]] = mapped_column(Text)
    constraint_source: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("''")
    )

    __table_args__ = (
        UniqueConstraint(
            "project_id", "library_id", "constraint_source",
            name="uq_projdeps_project_library_source",
        ),
        Index("idx_projdeps_project", "project_id"),
        Index("idx_projdeps_library", "library_id"),
    )
