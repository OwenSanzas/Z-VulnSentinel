"""Rule-based pre-filter — classify obvious events without LLM calls."""

from __future__ import annotations

import re
from dataclasses import dataclass

from vulnsentinel.models.event import Event

_BOT_PATTERNS = re.compile(
    r"(?i)\b(dependabot|renovate|greenkeeper|snyk-bot|github-actions|"
    r"semantic-release-bot|mergify|codecov|depfu)\b"
)

# Security-related keywords — if any appear in title or message, skip pre-filter
# and let the LLM decide (even if the conventional commit prefix says "fix:").
_SECURITY_KEYWORDS = re.compile(
    r"(?i)\b("
    r"CVE-\d{4}-\d+|CWE-\d+|"
    r"vulnerab|exploit|security|"
    r"buffer.?over(?:flow|read|write)|heap.?over(?:flow|read|write)|"
    r"stack.?over(?:flow|read|write)|"
    r"use.?after.?free|double.?free|"
    r"out.?of.?bounds|oob|"
    r"integer.?(?:over|under)flow|"
    r"null.?(?:pointer|ptr|deref)|"
    r"uninitiali[sz]ed|"
    r"race.?condition|TOCTOU|"
    r"injection|XSS|CSRF|SSRF|"
    r"auth.?bypass|privilege.?escalat|"
    r"info(?:rmation)?.?leak|"
    r"denial.?of.?service|dos\b|"
    r"memory.?corrupt|memory.?safety"
    r")\b"
)

# Conventional-commit prefix → (classification, confidence).
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


def _has_security_signals(event: Event) -> bool:
    """Return True if title or message contains security-related keywords."""
    text = (event.title or "") + " " + (getattr(event, "message", None) or "")
    return bool(_SECURITY_KEYWORDS.search(text))


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

    # Rule 3: If title/message mentions security keywords → always send to LLM.
    if _has_security_signals(event):
        return None

    # Rule 4: Conventional commit prefix.
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
