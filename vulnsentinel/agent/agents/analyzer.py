"""VulnAnalyzerAgent — deep vulnerability analysis via LLM + tool use."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import structlog
from mcp.server.fastmcp import FastMCP

from vulnsentinel.agent.base import BaseAgent
from vulnsentinel.agent.prompts.analyzer import ANALYZER_SYSTEM_PROMPT, format_bugfix_message
from vulnsentinel.agent.tools.github_tools import create_github_mcp
from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.models.event import Event

log = structlog.get_logger("vulnsentinel.agent")

# ── vuln_type mapping ─────────────────────────────────────────────────────

_VULN_TYPE_MAP: dict[str, str] = {
    # Standard values (identity)
    "buffer_overflow": "buffer_overflow",
    "use_after_free": "use_after_free",
    "integer_overflow": "integer_overflow",
    "null_deref": "null_deref",
    "injection": "injection",
    "auth_bypass": "auth_bypass",
    "info_leak": "info_leak",
    "dos": "dos",
    "race_condition": "race_condition",
    "memory_corruption": "memory_corruption",
    "other": "other",
    # Common aliases
    "heap_overflow": "buffer_overflow",
    "stack_overflow": "buffer_overflow",
    "buffer_overread": "buffer_overflow",
    "heap_buffer_overflow": "buffer_overflow",
    "stack_buffer_overflow": "buffer_overflow",
    "oob_read": "buffer_overflow",
    "oob_write": "buffer_overflow",
    "out_of_bounds": "buffer_overflow",
    "double_free": "use_after_free",
    "uaf": "use_after_free",
    "use-after-free": "use_after_free",
    "int_overflow": "integer_overflow",
    "integer_underflow": "integer_overflow",
    "null_pointer": "null_deref",
    "null_dereference": "null_deref",
    "nullptr": "null_deref",
    "command_injection": "injection",
    "sql_injection": "injection",
    "header_injection": "injection",
    "authentication_bypass": "auth_bypass",
    "authorization_bypass": "auth_bypass",
    "information_leak": "info_leak",
    "information_disclosure": "info_leak",
    "uninitialized_memory": "info_leak",
    "denial_of_service": "dos",
    "infinite_loop": "dos",
    "toctou": "race_condition",
    "data_race": "race_condition",
}

# ── severity mapping ──────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    # Common aliases
    "moderate": "medium",
    "important": "high",
    "severe": "critical",
    "minor": "low",
    "negligible": "low",
}


@dataclass
class VulnAnalysisResult:
    """Structured output from the analyzer agent."""

    vuln_type: str
    severity: str
    affected_versions: str
    summary: str
    reasoning: str
    upstream_poc: dict[str, Any] | None = None


def _extract_json(content: str) -> list[dict] | None:
    """Extract vulnerability JSON from LLM output.

    Supports two formats:
    - JSON array: ``[{...}, {...}]`` → returned as-is
    - Single JSON object: ``{...}`` → wrapped in a list

    Returns ``None`` when no valid JSON is found.
    """
    if not content:
        return None

    # --- Try array first (``[...]``) ---
    i = 0
    while i < len(content):
        i = content.find("[", i)
        if i == -1:
            break

        try:
            data = json.loads(content[i:])
            if isinstance(data, list) and data and all(isinstance(d, dict) for d in data):
                return data
        except json.JSONDecodeError:
            pass

        j = content.rfind("]", i)
        if j > i:
            try:
                data = json.loads(content[i : j + 1])
                if isinstance(data, list) and data and all(isinstance(d, dict) for d in data):
                    return data
            except json.JSONDecodeError:
                pass

        i += 1

    # --- Fallback: single object (``{...}``) → wrap in list ---
    i = 0
    while i < len(content):
        i = content.find("{", i)
        if i == -1:
            return None

        try:
            data = json.loads(content[i:])
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass

        j = content.rfind("}", i)
        if j > i:
            try:
                data = json.loads(content[i : j + 1])
                if isinstance(data, dict):
                    return [data]
            except json.JSONDecodeError:
                pass

        i += 1

    return None


class VulnAnalyzerAgent(BaseAgent):
    """Analyzes a confirmed security bugfix using LLM with tool access."""

    agent_type = "vuln_analyzer"
    max_turns = 15
    temperature = 0.2
    model = "deepseek/deepseek-chat"
    enable_compression = True
    max_context_tokens = 90000

    def __init__(self, client: GitHubClient, owner: str, repo: str) -> None:
        self._client = client
        self._owner = owner
        self._repo = repo

    # ── Abstract implementations ─────────────────────────────────────────

    def create_mcp_server(self) -> FastMCP:
        return create_github_mcp(self._client, self._owner, self._repo)

    def get_system_prompt(self, **kwargs: Any) -> str:
        return ANALYZER_SYSTEM_PROMPT

    def get_initial_message(self, **kwargs: Any) -> str:
        event: Event = kwargs["event"]
        return format_bugfix_message(event)

    # ── Result parsing ───────────────────────────────────────────────────

    def parse_result(self, content: str) -> list[VulnAnalysisResult]:
        """Extract one or more VulnAnalysisResult from the final LLM message.

        Returns an empty list when parsing fails.
        """
        if not content:
            return []

        items = _extract_json(content)
        if items is None:
            log.warning("agent.parse_failed", reason="no JSON found", output=content[:200])
            return []

        results: list[VulnAnalysisResult] = []
        for data in items:
            raw_type = str(data.get("vuln_type", "other")).lower().strip()
            vuln_type = _VULN_TYPE_MAP.get(raw_type, "other")

            raw_severity = str(data.get("severity", "medium")).lower().strip()
            severity = _SEVERITY_MAP.get(raw_severity, "medium")

            affected_versions = str(data.get("affected_versions", "unknown"))
            summary = str(data.get("summary", ""))
            reasoning = str(data.get("reasoning", ""))
            upstream_poc = data.get("upstream_poc")

            if upstream_poc is not None and not isinstance(upstream_poc, dict):
                upstream_poc = None

            results.append(
                VulnAnalysisResult(
                    vuln_type=vuln_type,
                    severity=severity,
                    affected_versions=affected_versions,
                    summary=summary,
                    reasoning=reasoning,
                    upstream_poc=upstream_poc,
                )
            )

        return results

    def should_stop(self, response: Any) -> bool:
        """Stop early if the LLM already emitted a JSON analysis result."""
        if response.content and _extract_json(response.content) is not None:
            return True
        return False

    def get_urgency_message(self) -> str | None:
        return (
            "You are running low on turns. Please output your final vulnerability "
            "analysis JSON now, even if you haven't gathered all the evidence you wanted."
        )

    def get_compression_criteria(self) -> str:
        return (
            "Preserve: diff analysis findings, vulnerability discoveries, severity "
            "assessment reasoning, affected version information, PoC evidence. "
            "Discard: raw tool outputs already summarized, intermediate reasoning "
            "that led to dead ends."
        )
