"""Vuln analyzer engine — pure analysis, no DB access."""

from __future__ import annotations

from dataclasses import dataclass

import structlog

from vulnsentinel.agent.agents.analyzer import VulnAnalysisResult, VulnAnalyzerAgent
from vulnsentinel.engines.event_collector.github_client import GitHubClient

log = structlog.get_logger("vulnsentinel.engine")


@dataclass
class AnalyzerInput:
    """Lightweight event descriptor for standalone analysis (no ORM)."""

    type: str  # commit | pr_merge | issue
    ref: str
    title: str
    message: str | None = None
    author: str | None = None
    related_issue_ref: str | None = None
    related_pr_ref: str | None = None
    related_commit_sha: str | None = None


class AnalysisError(Exception):
    """Raised when vulnerability analysis fails to produce a valid result."""


async def analyze(
    client: GitHubClient,
    owner: str,
    repo: str,
    event: AnalyzerInput,
) -> VulnAnalysisResult:
    """Analyze a single bugfix event without touching the database.

    Unlike the classifier, there is no pre-filter — all inputs are confirmed
    security bugfixes that need LLM deep analysis.

    Raises :class:`AnalysisError` if the agent fails to produce a parseable result.
    """
    agent = VulnAnalyzerAgent(client, owner, repo)
    agent_result = await agent.run(
        target_id=None,
        target_type="event",
        engine_name="vuln_analyzer",
        session=None,
        event=event,
    )

    if isinstance(agent_result.parsed, VulnAnalysisResult):
        return agent_result.parsed

    raise AnalysisError("LLM output could not be parsed into VulnAnalysisResult")
