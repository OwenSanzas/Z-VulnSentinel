"""AgentContext — mutable accumulator for a single agent run."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from shared.agent.llm_client import LLMResponse, estimate_cost
from shared.agent.result import AgentResult, ToolCallRecord

log = structlog.get_logger("shared.agent")


class AgentContext:
    """Tracks tokens, tool calls, and timing for one ``BaseAgent.run()`` invocation.

    Not a context-manager — call :meth:`finish` then :meth:`save` explicitly.
    """

    def __init__(
        self,
        *,
        agent_type: str,
        model: str,
        engine_name: str | None = None,
        target_id: uuid.UUID | None = None,
        target_type: str | None = None,
    ) -> None:
        self.run_id = uuid.uuid4()
        self.agent_type = agent_type
        self.model = model
        self.engine_name = engine_name
        self.target_id = target_id
        self.target_type = target_type

        # mutable accumulators
        self._input_tokens: int = 0
        self._output_tokens: int = 0
        self._turn: int = 0
        self._tool_calls: list[ToolCallRecord] = []
        self._cost: float = 0.0

        # status
        self._status: str = "running"
        self._error: str | None = None

        # timing
        self._started_at = time.monotonic()
        self._started_dt = datetime.now(timezone.utc)
        self._ended_dt: datetime | None = None
        self._cancelled = False

    # ── Accumulation ─────────────────────────────────────────────────────

    def add_usage(self, response: LLMResponse) -> None:
        """Accumulate token counts and cost from an LLM response."""
        self._input_tokens += response.input_tokens
        self._output_tokens += response.output_tokens
        self._cost += estimate_cost(self.model, response.input_tokens, response.output_tokens)

    def increment_turn(self) -> int:
        """Advance and return the current turn number."""
        self._turn += 1
        return self._turn

    def record_tool_call(
        self,
        *,
        seq: int,
        tool_name: str,
        tool_input: dict[str, Any],
        output_chars: int = 0,
        duration_ms: int = 0,
        is_error: bool = False,
    ) -> None:
        """Append a :class:`ToolCallRecord` for the current turn."""
        self._tool_calls.append(
            ToolCallRecord(
                turn=self._turn,
                seq=seq,
                tool_name=tool_name,
                tool_input=tool_input,
                output_chars=output_chars,
                duration_ms=duration_ms,
                is_error=is_error,
            )
        )

    # ── Lifecycle ────────────────────────────────────────────────────────

    def finish(self, status: str = "completed", error: str | None = None) -> None:
        """Mark the run as finished."""
        self._status = status
        self._error = error
        self._ended_dt = datetime.now(timezone.utc)

    def cancel(self) -> None:
        """Signal graceful cancellation — the loop should check :attr:`cancelled`."""
        self._cancelled = True

    # ── Computed properties ──────────────────────────────────────────────

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def total_input_tokens(self) -> int:
        return self._input_tokens

    @property
    def estimated_cost(self) -> float:
        return self._cost

    @property
    def duration_ms(self) -> int:
        return int((time.monotonic() - self._started_at) * 1000)

    @property
    def turn(self) -> int:
        return self._turn

    # ── Build result ─────────────────────────────────────────────────────

    def to_result(self, *, content: str = "", parsed: Any = None) -> AgentResult:
        """Build an :class:`AgentResult` snapshot."""
        return AgentResult(
            run_id=self.run_id,
            content=content,
            parsed=parsed,
            tool_calls=list(self._tool_calls),
            status=self._status,
            error=self._error,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            total_turns=self._turn,
            estimated_cost=self._cost,
            duration_ms=self.duration_ms,
        )

    # ── Persistence ──────────────────────────────────────────────────────

    async def save(self, session: Any) -> None:
        """Override in subclasses for DB persistence."""
