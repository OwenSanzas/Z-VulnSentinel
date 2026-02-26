"""agent_tool_calls table."""

import uuid
from typing import Optional

from sqlalchemy import (
    VARCHAR,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    desc,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vulnsentinel.core.database import Base, TimestampMixin


class AgentToolCall(TimestampMixin, Base):
    __tablename__ = "agent_tool_calls"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agent_runs.id", ondelete="CASCADE"),
        nullable=False,
    )

    turn: Mapped[int] = mapped_column(Integer, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_name: Mapped[str] = mapped_column(VARCHAR(80), nullable=False)
    tool_input: Mapped[Optional[dict]] = mapped_column(JSONB)
    output_chars: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    is_error: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    __table_args__ = (
        Index("idx_agent_tool_calls_run", "run_id"),
        Index("idx_agent_tool_calls_cursor", desc("created_at"), desc("id")),
        Index("idx_agent_tool_calls_name", "tool_name"),
    )
