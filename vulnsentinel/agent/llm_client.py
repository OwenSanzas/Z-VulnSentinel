"""Thin async wrapper around litellm.acompletion()."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import litellm

logger = logging.getLogger(__name__)

# ── Model metadata ───────────────────────────────────────────────────────────


def get_context_window(model: str) -> int:
    """Return the context window size (tokens) for a model.

    Uses ``litellm.get_model_info()`` with a 128k fallback.
    """
    try:
        info = litellm.get_model_info(model)
        return info.get("max_input_tokens") or 128_000
    except Exception:
        return 128_000


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Return estimated USD cost (input + output) for a single LLM call.

    Uses FBv2's ``ModelInfo`` registry for pricing. Falls back to a conservative
    $3/$15 per 1M tokens for unknown models.

    Same logic as ``fuzzingbrain.llms.client._calculate_cost()``.
    """
    from fuzzingbrain.llms.models import get_model_by_id

    model_info = get_model_by_id(model)
    if model_info:
        price_input = model_info.price_input
        price_output = model_info.price_output
    else:
        price_input = 3.0
        price_output = 15.0

    return (input_tokens / 1_000_000) * price_input + (output_tokens / 1_000_000) * price_output


# ── LLM Response ─────────────────────────────────────────────────────────────
@dataclass
class LLMResponse:
    """Standardised response from a single LLM call."""

    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


# ── LLM Client ───────────────────────────────────────────────────────────────
class LLMClient:
    """Async-only wrapper around ``litellm.acompletion()``.

    Usage::

        client = LLMClient()
        resp = await client.create(
            model="claude-sonnet-4-20250514",
            system="You are a security analyst.",
            messages=[{"role": "user", "content": "..."}],
            tools=[...],
        )
    """

    async def create(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a chat completion request and return a standardised response."""
        # Prepend system prompt as messages[0].
        full_messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            *messages,
        ]

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": full_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = tools

        t0 = time.monotonic()
        raw = await litellm.acompletion(**kwargs)
        latency_ms = int((time.monotonic() - t0) * 1000)

        choice = raw.choices[0]
        message = choice.message

        # Parse tool calls into plain dicts (OpenAI format).
        tool_calls: list[dict[str, Any]] = []
        if message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append(
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                )

        usage = raw.usage or litellm.Usage()

        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            stop_reason=choice.finish_reason or "",
            input_tokens=usage.prompt_tokens or 0,
            output_tokens=usage.completion_tokens or 0,
            latency_ms=latency_ms,
        )
