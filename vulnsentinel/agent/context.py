"""PersistentAgentContext — AgentContext subclass with DB persistence."""

from __future__ import annotations

from typing import Any

import structlog

from shared.agent.context import AgentContext

log = structlog.get_logger("vulnsentinel.agent")


class PersistentAgentContext(AgentContext):
    """AgentContext that persists runs and tool calls to PostgreSQL."""

    async def save(self, session: Any) -> None:
        """Write agent_runs + agent_tool_calls to PG in one flush.

        Parameters
        ----------
        session:
            An ``AsyncSession`` (sqlalchemy). Caller owns the transaction.
        """
        from vulnsentinel.models.agent_run import AgentRun
        from vulnsentinel.models.agent_tool_call import AgentToolCall

        run = AgentRun(
            id=self.run_id,
            agent_type=self.agent_type,
            status=self._status,
            engine_name=self.engine_name,
            model=self.model,
            target_id=self.target_id,
            target_type=self.target_type,
            total_turns=self._turn,
            total_tool_calls=len(self._tool_calls),
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            estimated_cost=self._cost,
            duration_ms=self.duration_ms,
            error=self._error,
            ended_at=self._ended_dt,
        )
        session.add(run)

        if self._tool_calls:
            session.add_all(
                [
                    AgentToolCall(
                        run_id=self.run_id,
                        turn=tc.turn,
                        seq=tc.seq,
                        tool_name=tc.tool_name,
                        tool_input=tc.tool_input,
                        output_chars=tc.output_chars,
                        duration_ms=tc.duration_ms,
                        is_error=tc.is_error,
                    )
                    for tc in self._tool_calls
                ]
            )

        await session.flush()
        log.info(
            "agent.saved",
            run_id=str(self.run_id),
            agent_type=self.agent_type,
            status=self._status,
            turns=self._turn,
            tool_calls=len(self._tool_calls),
        )
