"""Event classifier engine — pure classification, no DB access."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from vulnsentinel.agent.agents.classifier import ClassificationResult, EventClassifierAgent
from vulnsentinel.agent.pre_filter import pre_filter
from vulnsentinel.engines.event_collector.github_client import GitHubClient

logger = logging.getLogger(__name__)


@dataclass
class EventInput:
    """Lightweight event descriptor for standalone classification (no ORM)."""

    type: str  # commit | pr_merge | tag | bug_issue
    ref: str
    title: str
    message: str | None = None
    author: str | None = None
    related_issue_ref: str | None = None
    related_issue_url: str | None = None
    related_pr_ref: str | None = None
    related_pr_url: str | None = None
    related_commit_sha: str | None = None


async def classify(
    client: GitHubClient,
    owner: str,
    repo: str,
    event: EventInput,
) -> ClassificationResult:
    """Classify a single event without touching the database.

    1. Try the rule-based pre-filter (zero LLM cost).
    2. On miss, spin up an :class:`EventClassifierAgent` with GitHub tools.

    This is the standalone entry point — equivalent to ``collect()`` in the
    event_collector engine or ``scan()`` in the dependency_scanner engine.
    """
    pf = pre_filter(event)  # type: ignore[arg-type]  # duck-typed
    if pf is not None:
        logger.info(
            "pre-filter hit: classification=%s reason=%s",
            pf.classification,
            pf.reasoning,
        )
        return ClassificationResult(
            classification=pf.classification,
            confidence=pf.confidence,
            reasoning=pf.reasoning,
        )

    agent = EventClassifierAgent(client, owner, repo)
    agent_result = await agent.run(
        target_id=None,
        target_type="event",
        engine_name="event_classifier",
        session=None,
        event=event,
    )

    if isinstance(agent_result.parsed, ClassificationResult):
        return agent_result.parsed

    logger.warning("agent returned unparseable result, defaulting to other")
    return ClassificationResult(
        classification="other",
        confidence=0.3,
        reasoning="LLM output could not be parsed",
    )
