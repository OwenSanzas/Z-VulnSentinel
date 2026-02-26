"""Agent infrastructure — LLM-tool loop, context tracking, cost estimation."""

from shared.agent import (
    AgentResult,
    LLMClient,
    LLMResponse,
    ToolCallRecord,
    estimate_cost,
    get_context_window,
)
from shared.agent.base import BaseAgent
from vulnsentinel.agent.agents.classifier import ClassificationResult, EventClassifierAgent
from vulnsentinel.agent.base import VulnSentinelAgent
from vulnsentinel.agent.context import PersistentAgentContext as AgentContext

__all__ = [
    "BaseAgent",
    "VulnSentinelAgent",
    "AgentContext",
    "ClassificationResult",
    "EventClassifierAgent",
    "LLMClient",
    "LLMResponse",
    "AgentResult",
    "ToolCallRecord",
    "estimate_cost",
    "get_context_window",
]
