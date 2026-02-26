"""Rule-based pre-filter — classify obvious events without LLM calls."""

from __future__ import annotations

import re
from dataclasses import dataclass

from vulnsentinel.models.event import Event

_BOT_PATTERNS = re.compile(
    r"(?i)\b(dependabot|renovate|greenkeeper|snyk-bot|github-actions|"
    r"semantic-release-bot|mergify|codecov|depfu)\b"
)

# Conventional-commit prefix → (classification, confidence).
# NOTE: "fix:" maps to normal_bugfix with low confidence — could be a security fix.
_PREFIX_MAP: dict[str, tuple[str, float]] = {
    "fix": ("normal_bugfix", 0.70),
    "feat": ("feature", 0.80),
    "refactor": ("refactor", 0.80),
    "docs": ("other", 0.85),
    "test": ("other", 0.85),
    "perf": ("other", 0.85),
    "ci": ("other", 0.85),
    "chore": ("other", 0.85),
    "build": ("other", 0.85),
}

_CONVENTIONAL_RE = re.compile(r"^(\w+)(?:\([^)]*\))?!?:\s")


@dataclass
class PreFilterResult:
    """Result from the rule-based pre-filter."""

    classification: str
    confidence: float
    reasoning: str


def pre_filter(event: Event) -> PreFilterResult | None:
    """Attempt to classify *event* using cheap heuristics.

    Returns ``None`` when the event should be forwarded to the LLM agent.

    **Important**: This function never returns ``security_bugfix`` to avoid
    false negatives that would skip deeper LLM analysis.
    """
    # Rule 1: Tags are always "other".
    if event.type == "tag":
        return PreFilterResult("other", 0.95, "tag release event")

    # Rule 2: Bot authors → "other".
    if event.author and _BOT_PATTERNS.search(event.author):
        return PreFilterResult("other", 0.90, f"bot author: {event.author}")

    # Rule 3: Conventional commit prefix.
    title = (event.title or "").strip()
    match = _CONVENTIONAL_RE.match(title)
    if match:
        prefix = match.group(1).lower()
        if prefix in _PREFIX_MAP:
            classification, confidence = _PREFIX_MAP[prefix]
            return PreFilterResult(
                classification, confidence, f"conventional commit prefix: {prefix}:"
            )

    # No rule matched — needs LLM.
    return None
