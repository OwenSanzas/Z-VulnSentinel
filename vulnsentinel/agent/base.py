"""BaseAgent — abstract LLM-tool loop driven by LiteLLM + FastMCP."""

from __future__ import annotations

import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

import structlog
from mcp import types as mcp_types
from mcp.server.fastmcp import FastMCP

from vulnsentinel.agent.context import AgentContext
from vulnsentinel.agent.llm_client import LLMClient, LLMResponse, get_context_window
from vulnsentinel.agent.result import AgentResult

logger = logging.getLogger(__name__)

# Shared LLM client — stateless, safe to reuse.
_llm = LLMClient()


class BaseAgent(ABC):
    """Abstract base for all VulnSentinel agents.

    Subclasses **must** implement:
    - :meth:`create_mcp_server`  — return a ``FastMCP`` with tools registered
    - :meth:`get_system_prompt`  — return the system prompt string
    - :meth:`get_initial_message` — return the first user message

    Subclasses **may** override:
    - :meth:`parse_result`         — extract structured data from final content
    - :meth:`get_urgency_message`  — extra instruction injected on last turns
    - :meth:`get_compression_criteria` — what to keep when compressing context
    - :meth:`should_stop`          — custom early-stop logic
    """

    # ── Class-level config (override in subclasses) ──────────────────────
    agent_type: str = ""  # must match agent_type_enum values
    max_turns: int = 25
    temperature: float = 0.0
    model: str | None = None  # None → use LLMConfig default_model
    enable_compression: bool = True
    max_tool_output_tokens: int = 4000  # truncate single tool result beyond this
    max_context_tokens: int = 16000  # hard budget — break loop when exceeded

    # ── Abstract methods ─────────────────────────────────────────────────

    @abstractmethod
    def create_mcp_server(self) -> FastMCP:
        """Return a FastMCP instance with tools registered."""

    @abstractmethod
    def get_system_prompt(self, **kwargs: Any) -> str:
        """Return the system prompt for this agent."""

    @abstractmethod
    def get_initial_message(self, **kwargs: Any) -> str:
        """Return the first user message that kicks off the loop."""

    # ── Optional overrides ───────────────────────────────────────────────

    def parse_result(self, content: str) -> Any:
        """Extract structured data from the final assistant message.

        Returns ``None`` by default (plain text mode).
        """
        return None

    def get_urgency_message(self) -> str | None:
        """Injected as a user message when approaching *max_turns*.

        Return ``None`` to skip.
        """
        return None

    def get_compression_criteria(self) -> str:
        """Describe what to preserve when compressing mid-conversation."""
        return "Keep all tool results, key findings, and decisions."

    def should_stop(self, response: LLMResponse) -> bool:
        """Return ``True`` to break the loop early (before max_turns)."""
        return False

    # ── Public API ───────────────────────────────────────────────────────

    async def run(
        self,
        *,
        target_id: uuid.UUID | None = None,
        target_type: str | None = None,
        engine_name: str | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> AgentResult:
        """Execute the LLM-tool loop and return an :class:`AgentResult`.

        Parameters
        ----------
        target_id / target_type:
            Optional reference to the entity being analysed.
        engine_name:
            Name of the engine runner that spawned this agent.
        session:
            SQLAlchemy ``AsyncSession`` — if provided, results are persisted.
        **kwargs:
            Forwarded to :meth:`get_system_prompt` and :meth:`get_initial_message`.
        """
        resolved_model = _llm.resolve_model(self.model)
        ctx = AgentContext(
            agent_type=self.agent_type,
            model=resolved_model,
            engine_name=engine_name,
            target_id=target_id,
            target_type=target_type,
        )

        # Bind structured log context for the duration of this run.
        structlog.contextvars.bind_contextvars(
            run_id=str(ctx.run_id),
            agent_type=self.agent_type,
        )

        try:
            content = await self._run_loop(ctx, **kwargs)
            parsed = self.parse_result(content)
            ctx.finish("completed")
        except Exception as exc:
            logger.exception("agent run failed run_id=%s", ctx.run_id)
            content = ""
            parsed = None
            ctx.finish("failed", error=str(exc))
        finally:
            structlog.contextvars.unbind_contextvars("run_id", "agent_type")

        if session is not None:
            await ctx.save(session)

        result = ctx.to_result(content=content, parsed=parsed)
        logger.info(
            "agent run finished run_id=%s status=%s turns=%d cost=$%.4f",
            ctx.run_id,
            result.status,
            result.total_turns,
            result.estimated_cost,
        )
        return result

    def cancel(self, ctx: AgentContext) -> None:
        """Signal the loop to stop at the next iteration."""
        ctx.cancel()

    # ── Core loop ────────────────────────────────────────────────────────

    async def _run_loop(self, ctx: AgentContext, **kwargs: Any) -> str:
        """LLM call -> tool execution -> repeat."""
        mcp = self.create_mcp_server()
        tools = await self._load_tools(mcp)

        system = self.get_system_prompt(**kwargs)
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": self.get_initial_message(**kwargs)},
        ]

        last_content = ""

        while ctx.turn < self.max_turns:
            if ctx.cancelled:
                logger.info("agent cancelled turn=%d", ctx.turn)
                break

            turn = ctx.increment_turn()

            # ── Token budget guard ────────────────────────────────
            if ctx.total_input_tokens >= self.max_context_tokens:
                logger.warning(
                    "token budget exceeded, stopping loop turn=%d tokens=%d budget=%d",
                    turn,
                    ctx.total_input_tokens,
                    self.max_context_tokens,
                )
                break

            # Inject urgency hint near the end.
            if turn == self.max_turns - 2:
                urgency = self.get_urgency_message()
                if urgency:
                    messages.append({"role": "user", "content": urgency})

            # ── LLM call ─────────────────────────────────────────────
            response = await _llm.create(
                model=ctx.model,
                system=system,
                messages=messages,
                tools=tools if tools else None,
                temperature=self.temperature,
            )
            ctx.add_usage(response)

            logger.debug(
                "llm response turn=%d stop=%s tools=%d in=%d out=%d",
                turn,
                response.stop_reason,
                len(response.tool_calls),
                response.input_tokens,
                response.output_tokens,
            )

            # ── No tool calls → done ─────────────────────────────────
            if not response.has_tool_calls:
                last_content = response.content
                messages.append({"role": "assistant", "content": response.content})
                break

            # Custom early-stop check.
            if self.should_stop(response):
                last_content = response.content
                messages.append({"role": "assistant", "content": response.content})
                break

            # ── Append assistant message with tool_calls ─────────────
            messages.append(
                {
                    "role": "assistant",
                    "content": response.content,
                    "tool_calls": response.tool_calls,
                }
            )

            # ── Execute tools via MCP ────────────────────────────────
            for seq, tc in enumerate(response.tool_calls):
                func = tc["function"]
                tool_name = func["name"]
                try:
                    tool_input = json.loads(func["arguments"])
                except (json.JSONDecodeError, TypeError):
                    tool_input = {}

                t0 = time.monotonic()
                is_error = False
                output_text = ""
                try:
                    result = await mcp.call_tool(tool_name, tool_input)
                    # FastMCP >=1.25 returns (list[ContentBlock], dict).
                    content_blocks = result[0] if isinstance(result, tuple) else result
                    output_text = _extract_mcp_text(content_blocks)
                except Exception as exc:
                    is_error = True
                    output_text = f"Error: {exc}"
                    logger.warning("tool error tool=%s: %s", tool_name, exc)
                duration_ms = int((time.monotonic() - t0) * 1000)

                # Truncate oversized tool output (~4 chars/token heuristic).
                char_limit = self.max_tool_output_tokens * 4
                if len(output_text) > char_limit:
                    output_text = (
                        output_text[:char_limit]
                        + f"\n\n[truncated — {len(output_text)} chars total,"
                        f" limit {char_limit}]"
                    )

                ctx.record_tool_call(
                    seq=seq,
                    tool_name=tool_name,
                    tool_input=tool_input,
                    output_chars=len(output_text),
                    duration_ms=duration_ms,
                    is_error=is_error,
                )

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": output_text,
                    }
                )

            # ── Context compression ──────────────────────────────────
            # Trigger on: (a) every 5 turns, or (b) cumulative input tokens
            # reach 80% of the model's context window.
            if self.enable_compression and turn > 1:
                token_threshold = int(get_context_window(ctx.model) * 0.8)
                needs_compress = (
                    turn % 5 == 0 or ctx.total_input_tokens >= token_threshold
                )
                if needs_compress:
                    messages = await self._compress_context(ctx, system, messages)

        return last_content

    # ── Tool loading ─────────────────────────────────────────────────────

    async def _load_tools(self, mcp: FastMCP) -> list[dict[str, Any]]:
        """Convert MCP tool list to OpenAI function-calling format."""
        mcp_tools = await mcp.list_tools()
        openai_tools: list[dict[str, Any]] = []
        for tool in mcp_tools:
            schema = tool.inputSchema if tool.inputSchema else {"type": "object", "properties": {}}
            # Strip `title` keys — some providers (DeepSeek) reject them.
            schema = _strip_titles(schema)
            openai_tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or "",
                        "parameters": schema,
                    },
                }
            )
        return openai_tools

    # ── Context compression ──────────────────────────────────────────────

    async def _compress_context(
        self,
        ctx: AgentContext,
        system: str,
        messages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Summarise middle messages with a cheap model to save tokens."""
        if len(messages) < 6:
            return messages

        # Keep first user message + last 4 messages, compress the middle.
        head = messages[:1]
        tail = messages[-4:]
        middle = messages[1:-4]

        if not middle:
            return messages

        # Build a summary prompt from the middle messages.
        middle_text = "\n".join(
            f"[{m.get('role', '?')}] {str(m.get('content', ''))[:500]}" for m in middle
        )
        criteria = self.get_compression_criteria()
        compress_prompt = (
            f"Summarise the following conversation excerpt concisely.\n"
            f"Criteria: {criteria}\n\n{middle_text}"
        )

        try:
            resp = await _llm.create(
                model="claude-haiku-4-20250414",
                system="You are a concise summariser.",
                messages=[{"role": "user", "content": compress_prompt}],
                temperature=0.0,
                max_tokens=1024,
            )
            ctx.add_usage(resp)
            summary_msg: dict[str, Any] = {
                "role": "user",
                "content": f"[Context summary of turns 1-{len(middle)}]\n{resp.content}",
            }
            logger.debug(
                "context compressed msgs=%d summary_chars=%d",
                len(middle),
                len(resp.content),
            )
            return head + [summary_msg] + tail
        except Exception:
            logger.warning("context compression failed, keeping original messages")
            return messages


# ── Helpers ──────────────────────────────────────────────────────────────────


def _strip_titles(schema: dict[str, Any]) -> dict[str, Any]:
    """Recursively remove ``title`` keys from a JSON Schema.

    Some LLM providers (notably DeepSeek) reject tool schemas that contain
    the ``title`` keyword generated by Pydantic / FastMCP.
    """
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "title":
            continue
        if isinstance(value, dict):
            out[key] = _strip_titles(value)
        elif isinstance(value, list):
            out[key] = [_strip_titles(v) if isinstance(v, dict) else v for v in value]
        else:
            out[key] = value
    return out


def _extract_mcp_text(content: Sequence[Any]) -> str:
    """Pull text from a sequence of MCP content blocks."""
    parts: list[str] = []
    for block in content:
        if isinstance(block, mcp_types.TextContent):
            parts.append(block.text)
        elif isinstance(block, mcp_types.EmbeddedResource):
            if isinstance(block.resource, mcp_types.TextResourceContents):
                parts.append(block.resource.text)
    return "\n".join(parts)
