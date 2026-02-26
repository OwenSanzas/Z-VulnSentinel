"""Tests for the VulnAnalyzer: prompt, mappings, JSON extraction, agent, and standalone."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnsentinel.agent.agents.analyzer import (
    VulnAnalysisResult,
    VulnAnalyzerAgent,
    _SEVERITY_MAP,
    _VULN_TYPE_MAP,
    _extract_json,
)
from vulnsentinel.agent.prompts.analyzer import (
    ANALYZER_SYSTEM_PROMPT,
    format_bugfix_message,
)
from vulnsentinel.engines.vuln_analyzer.analyzer import AnalysisError, AnalyzerInput, analyze


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_event(**overrides):
    """Create a minimal mock Event ORM object."""
    defaults = {
        "id": "00000000-0000-0000-0000-000000000001",
        "library_id": "00000000-0000-0000-0000-000000000099",
        "type": "commit",
        "ref": "abc123def456",
        "title": "fix: heap buffer overflow in parse_url",
        "message": None,
        "author": "alice",
        "source_url": None,
        "event_at": datetime(2026, 1, 15, tzinfo=timezone.utc),
        "related_issue_ref": None,
        "related_issue_url": None,
        "related_pr_ref": None,
        "related_pr_url": None,
        "related_commit_sha": None,
        "classification": "security_bugfix",
        "confidence": 0.95,
        "is_bugfix": True,
    }
    defaults.update(overrides)
    ev = MagicMock()
    for k, v in defaults.items():
        setattr(ev, k, v)
    return ev


def _mock_client():
    """Create a mock GitHubClient with async get() and get_paginated()."""
    client = AsyncMock()
    client.get = AsyncMock()
    client.get_paginated = MagicMock()
    return client


# ── TestPrompt ───────────────────────────────────────────────────────────────


class TestPrompt:
    def test_system_prompt_has_vuln_types(self):
        for vt in (
            "buffer_overflow",
            "use_after_free",
            "integer_overflow",
            "null_deref",
            "injection",
            "auth_bypass",
            "info_leak",
            "dos",
            "race_condition",
            "memory_corruption",
            "other",
        ):
            assert vt in ANALYZER_SYSTEM_PROMPT

    def test_system_prompt_has_severity_levels(self):
        for level in ("critical", "high", "medium", "low"):
            assert level in ANALYZER_SYSTEM_PROMPT

    def test_system_prompt_has_output_format(self):
        assert "vuln_type" in ANALYZER_SYSTEM_PROMPT
        assert "severity" in ANALYZER_SYSTEM_PROMPT
        assert "upstream_poc" in ANALYZER_SYSTEM_PROMPT

    def test_format_bugfix_message_basic(self):
        ev = _make_event(title="fix: heap overflow", ref="abc123")
        msg = format_bugfix_message(ev)
        assert "Event type: commit" in msg
        assert "Ref: abc123" in msg
        assert "fix: heap overflow" in msg
        assert "security bugfix" in msg
        assert "Analyze the vulnerability" in msg

    def test_format_bugfix_message_with_refs(self):
        ev = _make_event(
            related_issue_ref="#42",
            related_pr_ref="#55",
            related_commit_sha="deadbeef",
        )
        msg = format_bugfix_message(ev)
        assert "#42" in msg
        assert "#55" in msg
        assert "deadbeef" in msg

    def test_format_bugfix_message_truncates_long_message(self):
        ev = _make_event(message="x" * 3000)
        msg = format_bugfix_message(ev)
        assert len(msg) < 3000

    def test_format_bugfix_message_ends_with_analyze(self):
        ev = _make_event()
        msg = format_bugfix_message(ev)
        assert msg.endswith("Analyze the vulnerability in detail.")


# ── TestVulnTypeMapping ──────────────────────────────────────────────────────


class TestVulnTypeMapping:
    def test_all_standard_values_identity(self):
        standard = [
            "buffer_overflow", "use_after_free", "integer_overflow", "null_deref",
            "injection", "auth_bypass", "info_leak", "dos", "race_condition",
            "memory_corruption", "other",
        ]
        for v in standard:
            assert _VULN_TYPE_MAP[v] == v

    def test_aliases(self):
        assert _VULN_TYPE_MAP["heap_overflow"] == "buffer_overflow"
        assert _VULN_TYPE_MAP["double_free"] == "use_after_free"
        assert _VULN_TYPE_MAP["uaf"] == "use_after_free"
        assert _VULN_TYPE_MAP["int_overflow"] == "integer_overflow"
        assert _VULN_TYPE_MAP["null_pointer"] == "null_deref"
        assert _VULN_TYPE_MAP["command_injection"] == "injection"
        assert _VULN_TYPE_MAP["authentication_bypass"] == "auth_bypass"
        assert _VULN_TYPE_MAP["information_disclosure"] == "info_leak"
        assert _VULN_TYPE_MAP["denial_of_service"] == "dos"
        assert _VULN_TYPE_MAP["toctou"] == "race_condition"

    def test_unknown_maps_to_other(self):
        """Unknown values should not be in the map — parse_result uses .get(x, 'other')."""
        assert _VULN_TYPE_MAP.get("banana", "other") == "other"
        assert _VULN_TYPE_MAP.get("xss", "other") == "other"


# ── TestSeverityMapping ──────────────────────────────────────────────────────


class TestSeverityMapping:
    def test_standard_values(self):
        for v in ("critical", "high", "medium", "low"):
            assert _SEVERITY_MAP[v] == v

    def test_aliases(self):
        assert _SEVERITY_MAP["moderate"] == "medium"
        assert _SEVERITY_MAP["important"] == "high"
        assert _SEVERITY_MAP["severe"] == "critical"
        assert _SEVERITY_MAP["minor"] == "low"
        assert _SEVERITY_MAP["negligible"] == "low"

    def test_case_handled_by_parse_result(self):
        """parse_result does .lower().strip() before lookup — verify map keys are lowercase."""
        for k in _SEVERITY_MAP:
            assert k == k.lower().strip()


# ── TestExtractJson ──────────────────────────────────────────────────────────


class TestExtractJson:
    def test_simple_json(self):
        content = '{"vuln_type": "dos", "severity": "medium"}'
        result = _extract_json(content)
        assert result == {"vuln_type": "dos", "severity": "medium"}

    def test_json_with_prefix(self):
        content = 'Here is my analysis:\n{"vuln_type": "dos"}'
        result = _extract_json(content)
        assert result["vuln_type"] == "dos"

    def test_nested_json(self):
        content = (
            '{"vuln_type": "buffer_overflow", "severity": "high", '
            '"upstream_poc": {"has_poc": true, "poc_type": "test_case", '
            '"description": "test added"}}'
        )
        result = _extract_json(content)
        assert result is not None
        assert result["vuln_type"] == "buffer_overflow"
        assert result["upstream_poc"]["has_poc"] is True

    def test_nested_json_with_surrounding_text(self):
        content = (
            'Based on my analysis:\n'
            '{"vuln_type": "dos", "upstream_poc": {"has_poc": false, '
            '"poc_type": "none", "description": ""}}\n'
            'That concludes my analysis.'
        )
        result = _extract_json(content)
        assert result is not None
        assert result["vuln_type"] == "dos"

    def test_no_json_returns_none(self):
        assert _extract_json("No JSON here.") is None

    def test_empty_returns_none(self):
        assert _extract_json("") is None

    def test_invalid_json_returns_none(self):
        assert _extract_json("{broken json}") is None

    def test_multiple_braces_finds_valid(self):
        """When there are stray { before the real JSON, should still find it."""
        content = 'some text { not json } then {"vuln_type": "dos"}'
        result = _extract_json(content)
        assert result is not None
        assert result["vuln_type"] == "dos"


# ── TestParseResult ──────────────────────────────────────────────────────────


class TestParseResult:
    """Test VulnAnalyzerAgent.parse_result() in isolation."""

    @pytest.fixture()
    def agent(self):
        client = _mock_client()
        return VulnAnalyzerAgent(client, "org", "repo")

    def test_valid_full_json(self, agent):
        content = (
            '{"vuln_type": "buffer_overflow", "severity": "high", '
            '"affected_versions": "< 8.12.0", '
            '"summary": "Heap overflow in parse_url().", '
            '"reasoning": "The diff adds bounds check.", '
            '"upstream_poc": {"has_poc": true, "poc_type": "test_case", '
            '"description": "test added"}}'
        )
        result = agent.parse_result(content)
        assert isinstance(result, VulnAnalysisResult)
        assert result.vuln_type == "buffer_overflow"
        assert result.severity == "high"
        assert result.affected_versions == "< 8.12.0"
        assert "Heap overflow" in result.summary
        assert result.upstream_poc["has_poc"] is True

    def test_vuln_type_alias_mapped(self, agent):
        content = '{"vuln_type": "heap_overflow", "severity": "high", "affected_versions": "all", "summary": "x", "reasoning": "y"}'
        result = agent.parse_result(content)
        assert result.vuln_type == "buffer_overflow"

    def test_severity_alias_mapped(self, agent):
        content = '{"vuln_type": "dos", "severity": "Moderate", "affected_versions": "all", "summary": "x", "reasoning": "y"}'
        result = agent.parse_result(content)
        assert result.severity == "medium"

    def test_severity_case_insensitive(self, agent):
        content = '{"vuln_type": "dos", "severity": "HIGH", "affected_versions": "all", "summary": "x", "reasoning": "y"}'
        result = agent.parse_result(content)
        assert result.severity == "high"

    def test_unknown_vuln_type_maps_to_other(self, agent):
        content = '{"vuln_type": "banana", "severity": "low", "affected_versions": "all", "summary": "x", "reasoning": "y"}'
        result = agent.parse_result(content)
        assert result.vuln_type == "other"

    def test_unknown_severity_defaults_to_medium(self, agent):
        content = '{"vuln_type": "dos", "severity": "banana", "affected_versions": "all", "summary": "x", "reasoning": "y"}'
        result = agent.parse_result(content)
        assert result.severity == "medium"

    def test_missing_fields_have_defaults(self, agent):
        content = '{"vuln_type": "dos"}'
        result = agent.parse_result(content)
        assert result.severity == "medium"
        assert result.affected_versions == "unknown"
        assert result.summary == ""
        assert result.reasoning == ""
        assert result.upstream_poc is None

    def test_no_json_returns_none(self, agent):
        result = agent.parse_result("I need more info.")
        assert result is None

    def test_empty_returns_none(self, agent):
        result = agent.parse_result("")
        assert result is None

    def test_upstream_poc_non_dict_becomes_none(self, agent):
        content = '{"vuln_type": "dos", "severity": "low", "affected_versions": "all", "summary": "x", "reasoning": "y", "upstream_poc": "none"}'
        result = agent.parse_result(content)
        assert result.upstream_poc is None

    def test_upstream_poc_null_stays_none(self, agent):
        content = '{"vuln_type": "dos", "severity": "low", "affected_versions": "all", "summary": "x", "reasoning": "y", "upstream_poc": null}'
        result = agent.parse_result(content)
        assert result.upstream_poc is None


# ── TestShouldStop ───────────────────────────────────────────────────────────


class TestShouldStop:
    @pytest.fixture()
    def agent(self):
        client = _mock_client()
        return VulnAnalyzerAgent(client, "org", "repo")

    def test_stops_when_json_present(self, agent):
        resp = MagicMock()
        resp.content = '{"vuln_type": "dos", "severity": "medium", "upstream_poc": null}'
        assert agent.should_stop(resp) is True

    def test_stops_with_nested_json(self, agent):
        resp = MagicMock()
        resp.content = '{"vuln_type": "dos", "upstream_poc": {"has_poc": true}}'
        assert agent.should_stop(resp) is True

    def test_continues_when_no_json(self, agent):
        resp = MagicMock()
        resp.content = "I need to fetch the diff first."
        assert agent.should_stop(resp) is False

    def test_continues_on_empty(self, agent):
        resp = MagicMock()
        resp.content = ""
        assert agent.should_stop(resp) is False


# ── TestAgentConfig ──────────────────────────────────────────────────────────


class TestAgentConfig:
    def test_class_attributes(self):
        assert VulnAnalyzerAgent.agent_type == "vuln_analyzer"
        assert VulnAnalyzerAgent.max_turns == 15
        assert VulnAnalyzerAgent.temperature == 0.2
        assert VulnAnalyzerAgent.model == "deepseek/deepseek-chat"
        assert VulnAnalyzerAgent.enable_compression is True

    def test_creates_mcp_server(self):
        client = _mock_client()
        agent = VulnAnalyzerAgent(client, "org", "repo")
        mcp = agent.create_mcp_server()
        assert mcp is not None

    def test_system_prompt(self):
        client = _mock_client()
        agent = VulnAnalyzerAgent(client, "org", "repo")
        prompt = agent.get_system_prompt()
        assert "buffer_overflow" in prompt
        assert "severity" in prompt

    def test_initial_message(self):
        client = _mock_client()
        agent = VulnAnalyzerAgent(client, "org", "repo")
        ev = _make_event(title="Fix heap overflow")
        msg = agent.get_initial_message(event=ev)
        assert "Fix heap overflow" in msg
        assert "security bugfix" in msg

    def test_urgency_message(self):
        client = _mock_client()
        agent = VulnAnalyzerAgent(client, "org", "repo")
        msg = agent.get_urgency_message()
        assert msg is not None
        assert "JSON" in msg

    def test_compression_criteria(self):
        client = _mock_client()
        agent = VulnAnalyzerAgent(client, "org", "repo")
        criteria = agent.get_compression_criteria()
        assert criteria is not None
        assert "diff" in criteria.lower()
        assert "severity" in criteria.lower()


# ── TestAnalyzeStandalone ────────────────────────────────────────────────────


class TestAnalyzeStandalone:
    """Test the standalone analyze() function with mocked agent."""

    @pytest.mark.anyio()
    async def test_success(self):
        expected = VulnAnalysisResult(
            vuln_type="buffer_overflow",
            severity="high",
            affected_versions="< 8.12.0",
            summary="Heap overflow in parse_url().",
            reasoning="Bounds check added.",
            upstream_poc=None,
        )
        mock_agent_result = MagicMock()
        mock_agent_result.parsed = expected

        event = AnalyzerInput(
            type="commit",
            ref="abc123",
            title="fix: heap overflow",
        )

        with patch(
            "vulnsentinel.engines.vuln_analyzer.analyzer.VulnAnalyzerAgent"
        ) as MockAgent:
            instance = MockAgent.return_value
            instance.run = AsyncMock(return_value=mock_agent_result)

            result = await analyze(_mock_client(), "org", "repo", event)

        assert result is expected
        assert result.vuln_type == "buffer_overflow"

    @pytest.mark.anyio()
    async def test_parse_failure_raises(self):
        mock_agent_result = MagicMock()
        mock_agent_result.parsed = None  # parse failed

        event = AnalyzerInput(
            type="commit",
            ref="abc123",
            title="fix: something",
        )

        with patch(
            "vulnsentinel.engines.vuln_analyzer.analyzer.VulnAnalyzerAgent"
        ) as MockAgent:
            instance = MockAgent.return_value
            instance.run = AsyncMock(return_value=mock_agent_result)

            with pytest.raises(AnalysisError):
                await analyze(_mock_client(), "org", "repo", event)
