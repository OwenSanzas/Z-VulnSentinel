"""Tests for the EventClassifier: MCP tools, pre-filter, prompt, and agent."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from vulnsentinel.agent.agents.classifier import (
    ClassificationResult,
    EventClassifierAgent,
    _JSON_RE,
    _LABEL_MAP,
)
from vulnsentinel.agent.pre_filter import PreFilterResult, pre_filter
from vulnsentinel.agent.prompts.classifier import (
    CLASSIFIER_SYSTEM_PROMPT,
    format_event_message,
)
from vulnsentinel.agent.tools.github_tools import create_github_mcp


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_event(**overrides):
    """Create a minimal mock Event ORM object."""
    defaults = {
        "id": "00000000-0000-0000-0000-000000000001",
        "library_id": "00000000-0000-0000-0000-000000000099",
        "type": "commit",
        "ref": "abc123def456",
        "title": "fix: correct buffer size check",
        "message": None,
        "author": "alice",
        "source_url": None,
        "event_at": datetime(2026, 1, 15, tzinfo=timezone.utc),
        "related_issue_ref": None,
        "related_issue_url": None,
        "related_pr_ref": None,
        "related_pr_url": None,
        "related_commit_sha": None,
        "classification": None,
        "confidence": None,
        "is_bugfix": False,
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
    # get_paginated needs to be an async generator
    client.get_paginated = MagicMock()
    return client


# ── TestPreFilter ────────────────────────────────────────────────────────────


class TestPreFilter:
    def test_tag_event(self):
        ev = _make_event(type="tag", title="v1.2.3")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "other"
        assert result.confidence == 0.95

    def test_bot_author_dependabot(self):
        ev = _make_event(author="dependabot[bot]")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "other"
        assert result.confidence == 0.90

    def test_bot_author_renovate(self):
        ev = _make_event(author="renovate[bot]")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "other"

    def test_bot_author_snyk(self):
        ev = _make_event(author="snyk-bot")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "other"

    def test_conventional_fix(self):
        ev = _make_event(title="fix: correct off-by-one error")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "normal_bugfix"
        assert result.confidence == 0.70

    def test_conventional_feat(self):
        ev = _make_event(title="feat: add AVIF support")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "feature"

    def test_conventional_refactor(self):
        ev = _make_event(title="refactor(core): simplify loop")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "refactor"

    def test_conventional_docs(self):
        ev = _make_event(title="docs: update README")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "other"

    def test_conventional_chore(self):
        ev = _make_event(title="chore: bump version")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "other"

    def test_no_match_returns_none(self):
        ev = _make_event(title="Fix heap buffer overflow in png_read_row")
        result = pre_filter(ev)
        assert result is None

    def test_never_returns_security_bugfix(self):
        """Pre-filter must never output security_bugfix."""
        events = [
            _make_event(type="tag"),
            _make_event(author="dependabot[bot]"),
            _make_event(title="fix: something"),
            _make_event(title="feat: something"),
            _make_event(title="refactor: something"),
            _make_event(title="docs: something"),
            _make_event(title="ci: something"),
        ]
        for ev in events:
            result = pre_filter(ev)
            if result is not None:
                assert result.classification != "security_bugfix"

    def test_tag_takes_priority_over_conventional(self):
        """Tag rule fires before conventional commit check."""
        ev = _make_event(type="tag", title="fix: release v1.0")
        result = pre_filter(ev)
        assert result is not None
        assert result.classification == "other"
        assert result.confidence == 0.95


# ── TestPrompt ───────────────────────────────────────────────────────────────


class TestPrompt:
    def test_system_prompt_has_labels(self):
        for label in ("security_bugfix", "normal_bugfix", "feature", "refactor", "other"):
            assert label in CLASSIFIER_SYSTEM_PROMPT

    def test_format_event_basic(self):
        ev = _make_event(title="fix: bounds check", ref="abc123")
        msg = format_event_message(ev)
        assert "Event type: commit" in msg
        assert "Ref: abc123" in msg
        assert "fix: bounds check" in msg
        assert "Classify this event" in msg

    def test_format_event_with_refs(self):
        ev = _make_event(
            related_issue_ref="#42",
            related_pr_ref="#55",
            related_commit_sha="deadbeef",
        )
        msg = format_event_message(ev)
        assert "#42" in msg
        assert "#55" in msg
        assert "deadbeef" in msg

    def test_format_event_truncates_long_message(self):
        ev = _make_event(message="x" * 3000)
        msg = format_event_message(ev)
        # Should be truncated to 2000 + "…"
        assert len(msg) < 3000


# ── TestMCPTools ─────────────────────────────────────────────────────────────


class TestMCPTools:
    """Test the 5 GitHub MCP tools with a mocked GitHubClient."""

    @pytest.fixture()
    def client(self):
        return _mock_client()

    @pytest.fixture()
    def mcp(self, client):
        return create_github_mcp(client, "org", "repo")

    @pytest.mark.anyio()
    async def test_fetch_commit_diff_diffstat(self, mcp, client):
        client.get.return_value = {
            "files": [
                {
                    "filename": "src/main.c",
                    "status": "modified",
                    "additions": 10,
                    "deletions": 3,
                    "patch": "@@ -1,3 +1,10 @@\n+new code",
                },
                {
                    "filename": "include/header.h",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 0,
                },
            ]
        }
        result = await mcp.call_tool("fetch_commit_diff", {"sha": "abc123"})
        text = result[0][0].text
        assert "2 file(s) changed" in text
        assert "src/main.c" in text
        assert "include/header.h" in text
        client.get.assert_called_once_with("/repos/org/repo/commits/abc123")

    @pytest.mark.anyio()
    async def test_fetch_commit_diff_single_file(self, mcp, client):
        client.get.return_value = {
            "files": [
                {
                    "filename": "src/main.c",
                    "status": "modified",
                    "additions": 10,
                    "deletions": 3,
                    "patch": "@@ -1,3 +1,10 @@\n+fixed buffer",
                },
            ]
        }
        result = await mcp.call_tool(
            "fetch_commit_diff",
            {"sha": "abc123", "file_path": "src/main.c"},
        )
        text = result[0][0].text
        assert "src/main.c" in text
        assert "+fixed buffer" in text

    @pytest.mark.anyio()
    async def test_fetch_commit_diff_file_not_found(self, mcp, client):
        client.get.return_value = {
            "files": [{"filename": "src/main.c", "status": "modified"}]
        }
        result = await mcp.call_tool(
            "fetch_commit_diff",
            {"sha": "abc123", "file_path": "nonexistent.c"},
        )
        text = result[0][0].text
        assert "not found" in text

    @pytest.mark.anyio()
    async def test_fetch_commit_diff_no_files(self, mcp, client):
        client.get.return_value = {"files": []}
        result = await mcp.call_tool("fetch_commit_diff", {"sha": "abc123"})
        text = result[0][0].text
        assert "No files changed" in text

    @pytest.mark.anyio()
    async def test_fetch_pr_diff_diffstat(self, mcp, client):
        async def _gen(*args, **kwargs):
            yield {
                "filename": "lib/parse.c",
                "status": "added",
                "additions": 50,
                "deletions": 0,
                "patch": "+new file",
            }
            yield {
                "filename": "lib/parse.h",
                "status": "added",
                "additions": 10,
                "deletions": 0,
            }

        client.get_paginated.return_value = _gen()
        result = await mcp.call_tool("fetch_pr_diff", {"pr_number": 42})
        text = result[0][0].text
        assert "2 file(s) changed" in text
        assert "lib/parse.c" in text

    @pytest.mark.anyio()
    async def test_fetch_pr_diff_single_file(self, mcp, client):
        async def _gen(*args, **kwargs):
            yield {
                "filename": "lib/parse.c",
                "status": "modified",
                "additions": 5,
                "deletions": 2,
                "patch": "@@ -10,2 +10,5 @@\n+bounds check",
            }

        client.get_paginated.return_value = _gen()
        result = await mcp.call_tool(
            "fetch_pr_diff",
            {"pr_number": 42, "file_path": "lib/parse.c"},
        )
        text = result[0][0].text
        assert "+bounds check" in text

    @pytest.mark.anyio()
    async def test_fetch_file_content_base64(self, mcp, client):
        import base64

        content = "int main() { return 0; }"
        encoded = base64.b64encode(content.encode()).decode()
        client.get.return_value = {"encoding": "base64", "content": encoded}

        result = await mcp.call_tool(
            "fetch_file_content",
            {"path": "src/main.c", "ref": "abc123"},
        )
        text = result[0][0].text
        assert "int main()" in text
        client.get.assert_called_once_with(
            "/repos/org/repo/contents/src/main.c",
            params={"ref": "abc123"},
        )

    @pytest.mark.anyio()
    async def test_fetch_file_content_default_ref(self, mcp, client):
        import base64

        client.get.return_value = {
            "encoding": "base64",
            "content": base64.b64encode(b"hello").decode(),
        }
        await mcp.call_tool("fetch_file_content", {"path": "README.md"})
        client.get.assert_called_once_with(
            "/repos/org/repo/contents/README.md",
            params={"ref": "HEAD"},
        )

    @pytest.mark.anyio()
    async def test_fetch_issue_body(self, mcp, client):
        client.get.return_value = {
            "title": "Crash on malformed input",
            "body": "Steps to reproduce:\n1. ...\n2. ...",
            "labels": [{"name": "bug"}, {"name": "P1"}],
        }
        result = await mcp.call_tool("fetch_issue_body", {"issue_number": 99})
        text = result[0][0].text
        assert "Crash on malformed input" in text
        assert "Steps to reproduce" in text
        assert "bug" in text
        assert "P1" in text

    @pytest.mark.anyio()
    async def test_fetch_issue_body_no_labels(self, mcp, client):
        client.get.return_value = {
            "title": "Minor issue",
            "body": "Details here",
            "labels": [],
        }
        result = await mcp.call_tool("fetch_issue_body", {"issue_number": 1})
        text = result[0][0].text
        assert "Minor issue" in text
        assert "Labels" not in text

    @pytest.mark.anyio()
    async def test_fetch_pr_body(self, mcp, client):
        client.get.return_value = {
            "title": "Fix CVE-2025-1234",
            "body": "This PR patches the vulnerability.",
            "labels": [{"name": "security"}],
        }
        result = await mcp.call_tool("fetch_pr_body", {"pr_number": 77})
        text = result[0][0].text
        assert "Fix CVE-2025-1234" in text
        assert "vulnerability" in text
        assert "security" in text
        client.get.assert_called_once_with("/repos/org/repo/pulls/77")

    @pytest.mark.anyio()
    async def test_fetch_pr_body_null_body(self, mcp, client):
        client.get.return_value = {
            "title": "Quick fix",
            "body": None,
            "labels": [],
        }
        result = await mcp.call_tool("fetch_pr_body", {"pr_number": 1})
        text = result[0][0].text
        assert "Quick fix" in text

    @pytest.mark.anyio()
    async def test_truncation(self, mcp, client):
        """Tool output should be truncated at 15,000 chars."""
        big_patch = "+" + "x" * 20_000
        client.get.return_value = {
            "files": [
                {
                    "filename": "big.c",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 0,
                    "patch": big_patch,
                }
            ]
        }
        result = await mcp.call_tool(
            "fetch_commit_diff",
            {"sha": "abc", "file_path": "big.c"},
        )
        text = result[0][0].text
        assert len(text) <= 15_100  # 15k + small header + truncation notice
        assert "[truncated" in text


# ── TestLabelMapping ─────────────────────────────────────────────────────────


class TestLabelMapping:
    def test_all_db_enums_mapped(self):
        db_enums = {"security_bugfix", "normal_bugfix", "feature", "refactor", "other"}
        mapped_values = set(_LABEL_MAP.values())
        assert mapped_values == db_enums

    def test_extended_labels_resolve(self):
        assert _LABEL_MAP["bugfix"] == "normal_bugfix"
        assert _LABEL_MAP["bug_fix"] == "normal_bugfix"
        assert _LABEL_MAP["security"] == "security_bugfix"
        assert _LABEL_MAP["documentation"] == "other"
        assert _LABEL_MAP["tests"] == "other"
        assert _LABEL_MAP["refactoring"] == "refactor"
        assert _LABEL_MAP["performance"] == "other"


# ── TestParseResult ──────────────────────────────────────────────────────────


class TestParseResult:
    """Test EventClassifierAgent.parse_result() in isolation."""

    @pytest.fixture()
    def agent(self):
        client = _mock_client()
        return EventClassifierAgent(client, "org", "repo")

    def test_valid_json(self, agent):
        content = (
            'Based on my analysis:\n'
            '{"label": "security_bugfix", "confidence": 0.95, '
            '"reasoning": "Fixes heap overflow."}'
        )
        result = agent.parse_result(content)
        assert isinstance(result, ClassificationResult)
        assert result.classification == "security_bugfix"
        assert result.confidence == 0.95
        assert "heap overflow" in result.reasoning

    def test_normal_bugfix_label(self, agent):
        content = '{"label": "bugfix", "confidence": 0.8, "reasoning": "Logic error."}'
        result = agent.parse_result(content)
        assert result.classification == "normal_bugfix"

    def test_unknown_label_maps_to_other(self, agent):
        content = '{"label": "banana", "confidence": 0.5, "reasoning": "?"}'
        result = agent.parse_result(content)
        assert result.classification == "other"

    def test_confidence_clamped(self, agent):
        content = '{"label": "feature", "confidence": 1.5, "reasoning": "over"}'
        result = agent.parse_result(content)
        assert result.confidence == 1.0

        content2 = '{"label": "feature", "confidence": -0.3, "reasoning": "under"}'
        result2 = agent.parse_result(content2)
        assert result2.confidence == 0.0

    def test_no_json_returns_none(self, agent):
        result = agent.parse_result("I think this is a bugfix.")
        assert result is None

    def test_empty_content_returns_none(self, agent):
        result = agent.parse_result("")
        assert result is None

    def test_invalid_json_returns_none(self, agent):
        result = agent.parse_result('{"label": broken}')
        assert result is None

    def test_missing_confidence_defaults(self, agent):
        content = '{"label": "feature", "reasoning": "new API"}'
        result = agent.parse_result(content)
        assert result.confidence == 0.5

    def test_non_numeric_confidence_defaults(self, agent):
        content = '{"label": "feature", "confidence": "high", "reasoning": "x"}'
        result = agent.parse_result(content)
        assert result.confidence == 0.5


# ── TestShouldStop ───────────────────────────────────────────────────────────


class TestShouldStop:
    @pytest.fixture()
    def agent(self):
        client = _mock_client()
        return EventClassifierAgent(client, "org", "repo")

    def test_stops_when_json_present(self, agent):
        resp = MagicMock()
        resp.content = 'Here is my answer: {"label": "feature", "confidence": 0.9, "reasoning": "new"}'
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
        assert EventClassifierAgent.agent_type == "event_classifier"
        assert EventClassifierAgent.max_turns == 5
        assert EventClassifierAgent.temperature == 0.2
        assert EventClassifierAgent.model == "deepseek/deepseek-chat"
        assert EventClassifierAgent.enable_compression is False

    def test_creates_mcp_server(self):
        client = _mock_client()
        agent = EventClassifierAgent(client, "org", "repo")
        mcp = agent.create_mcp_server()
        assert mcp is not None

    def test_system_prompt(self):
        client = _mock_client()
        agent = EventClassifierAgent(client, "org", "repo")
        prompt = agent.get_system_prompt()
        assert "security_bugfix" in prompt

    def test_initial_message(self):
        client = _mock_client()
        agent = EventClassifierAgent(client, "org", "repo")
        ev = _make_event(title="Fix heap overflow")
        msg = agent.get_initial_message(event=ev)
        assert "Fix heap overflow" in msg

    def test_urgency_message(self):
        client = _mock_client()
        agent = EventClassifierAgent(client, "org", "repo")
        msg = agent.get_urgency_message()
        assert msg is not None
        assert "classification" in msg.lower() or "JSON" in msg
