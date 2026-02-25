"""Data classes returned by agent runs."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCallRecord:
    """Single tool invocation metadata — maps to agent_tool_calls row."""

    turn: int
    seq: int
    tool_name: str
    tool_input: dict[str, Any]
    output_chars: int = 0
    duration_ms: int = 0
    is_error: bool = False


@dataclass
class AgentResult:
    """Return value of ``BaseAgent.run()``."""

    run_id: uuid.UUID
    content: str = ""
    parsed: Any = None
    tool_calls: list[ToolCallRecord] = field(default_factory=list)

    # final status
    status: str = "completed"  # completed | failed | timeout
    error: str | None = None

    # aggregate stats
    input_tokens: int = 0
    output_tokens: int = 0
    total_turns: int = 0
    estimated_cost: float = 0.0
    duration_ms: int = 0
