"""snapshots table."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Double,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    desc,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin

snapshot_status_enum = Enum(
    "building", "completed", name="snapshot_status", create_type=False
)
snapshot_backend_enum = Enum(
    "svf", "joern", "introspector", "prebuild",
    name="snapshot_backend", create_type=False,
)
snapshot_trigger_enum = Enum(
    "tag_push", "manual", "scheduled", "on_upstream_vuln_analysis",
    name="snapshot_trigger", create_type=False,
)


class Snapshot(TimestampMixin, Base):
    __tablename__ = "snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="SET NULL"),
    )
    repo_url: Mapped[str] = mapped_column(Text, nullable=False)
    repo_name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(Text, nullable=False)
    backend: Mapped[str] = mapped_column(snapshot_backend_enum, nullable=False)
    status: Mapped[str] = mapped_column(
        snapshot_status_enum, nullable=False, server_default=text("'building'")
    )
    trigger_type: Mapped[Optional[str]] = mapped_column(snapshot_trigger_enum)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    storage_path: Mapped[Optional[str]] = mapped_column(Text)

    # preserved from MongoDB
    node_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    edge_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    fuzzer_names: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    analysis_duration_sec: Mapped[float] = mapped_column(
        Double, nullable=False, server_default=text("0")
    )
    language: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("''")
    )
    size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text("0")
    )
    error: Mapped[Optional[str]] = mapped_column(Text)

    last_accessed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )
    access_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )

    __table_args__ = (
        UniqueConstraint("repo_url", "version", "backend"),
        Index("idx_snapshots_project", "project_id"),
        Index("idx_snapshots_cursor", desc("created_at"), desc("id")),
        Index(
            "idx_snapshots_active", "project_id",
            postgresql_where="is_active = TRUE",
        ),
        Index("idx_snapshots_accessed", "last_accessed_at"),
    )
