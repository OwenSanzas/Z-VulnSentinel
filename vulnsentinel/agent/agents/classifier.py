"""EventClassifierAgent — classifies GitHub events via LLM + tool use."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import structlog
from mcp.server.fastmcp import FastMCP

from vulnsentinel.agent.base import VulnSentinelAgent
from vulnsentinel.agent.prompts.classifier import CLASSIFIER_SYSTEM_PROMPT, format_event_message
from vulnsentinel.agent.tools.github_tools import create_github_mcp
from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.models.event import Event

log = structlog.get_logger("vulnsentinel.agent")

# LLM may output extended labels — map to the 5 DB enum values.
_LABEL_MAP: dict[str, str] = {
    "security_bugfix": "security_bugfix",
    "security": "security_bugfix",
    "normal_bugfix": "normal_bugfix",
    "bugfix": "normal_bugfix",
    "bug_fix": "normal_bugfix",
    "bug": "normal_bugfix",
    "feature": "feature",
    "refactor": "refactor",
    "refactoring": "refactor",
    "other": "other",
    "documentation": "other",
    "docs": "other",
    "test": "other",
    "tests": "other",
    "ci": "other",
    "chore": "other",
    "build": "other",
    "performance": "other",
    "perf": "other",
    "style": "other",
}

# Regex to find JSON object in LLM output.
_JSON_RE = re.compile(r"\{[^{}]*\}")


@dataclass
class ClassificationResult:
    """Structured output from the classifier agent."""

    classification: str  # one of the 5 DB enum values
    confidence: float
    reasoning: str


class EventClassifierAgent(VulnSentinelAgent):
    """Classifies a single GitHub event using LLM with tool access."""

    agent_type = "event_classifier"
    max_turns = 5
    temperature = 0.2
    model = "deepseek/deepseek-chat"
    enable_compression = False

    def __init__(self, client: GitHubClient, owner: str, repo: str) -> None:
        self._client = client
        self._owner = owner
        self._repo = repo
        self._event: Event | None = None

    # ── Abstract implementations ─────────────────────────────────────────

    def create_mcp_server(self) -> FastMCP:
        return create_github_mcp(self._client, self._owner, self._repo)

    def get_system_prompt(self, **kwargs: Any) -> str:
        return CLASSIFIER_SYSTEM_PROMPT

    def get_initial_message(self, **kwargs: Any) -> str:
        event: Event = kwargs["event"]
        self._event = event
        return format_event_message(event)

    # ── Result parsing ───────────────────────────────────────────────────

    def parse_result(self, content: str) -> ClassificationResult | None:
        """Extract ClassificationResult from the final LLM message."""
        if not content:
            return None

        # Try to find a JSON object in the output.
        match = _JSON_RE.search(content)
        if not match:
            log.warning("agent.parse_failed", reason="no JSON found", output=content[:200])
            return None

        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            log.warning("agent.parse_failed", reason="invalid JSON", output=match.group(0)[:200])
            return None

        raw_label = str(data.get("label", "other")).lower().strip()
        classification = _LABEL_MAP.get(raw_label, "other")

        confidence = data.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)):
            confidence = 0.5
        confidence = max(0.0, min(1.0, float(confidence)))

        reasoning = str(data.get("reasoning", ""))

        return ClassificationResult(
            classification=classification,
            confidence=confidence,
            reasoning=reasoning,
        )

    def get_urgency_message(self) -> str | None:
        return (
            "You are running low on turns. Please output your final classification "
            "JSON now, even if you haven't gathered all the evidence you wanted."
        )

    def should_stop(self, response: Any) -> bool:
        """Stop early if the LLM already emitted a JSON classification."""
        if response.content and _JSON_RE.search(response.content):
            return True
        return False
