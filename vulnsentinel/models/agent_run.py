"""agent_runs table."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    VARCHAR,
    DateTime,
    Enum,
    Index,
    Integer,
    Numeric,
    Text,
    desc,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin

agent_type_enum = Enum(
    "event_classifier",
    "vuln_analyzer",
    "reachability",
    "poc_generator",
    "report",
    name="agent_type",
    create_type=False,
)
agent_run_status_enum = Enum(
    "running",
    "completed",
    "failed",
    "timeout",
    name="agent_run_status",
    create_type=False,
)


class AgentRun(TimestampMixin, Base):
    __tablename__ = "agent_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    agent_type: Mapped[str] = mapped_column(agent_type_enum, nullable=False)
    status: Mapped[str] = mapped_column(
        agent_run_status_enum, nullable=False, server_default=text("'running'")
    )

    # LLM config
    engine_name: Mapped[Optional[str]] = mapped_column(VARCHAR(50))
    model: Mapped[Optional[str]] = mapped_column(VARCHAR(80))

    # target reference (event, vuln, etc.)
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    target_type: Mapped[Optional[str]] = mapped_column(VARCHAR(30))

    # run stats
    total_turns: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    total_tool_calls: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    estimated_cost: Mapped[Optional[float]] = mapped_column(Numeric(10, 6))
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)

    # result
    result_summary: Mapped[Optional[dict]] = mapped_column(JSONB)
    error: Mapped[Optional[str]] = mapped_column(Text)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_agent_runs_type", "agent_type"),
        Index("idx_agent_runs_status", "status"),
        Index("idx_agent_runs_target", "target_type", "target_id"),
        Index("idx_agent_runs_cursor", desc("created_at"), desc("id")),
    )
