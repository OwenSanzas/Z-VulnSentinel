"""Parse commit/PR messages for issue and PR references."""

from __future__ import annotations

import re

from vulnsentinel.engines.event_collector.models import CollectedEvent

# "Fixes #123", "Closes #45", "Resolves #6"
ISSUE_FIX_PATTERN = re.compile(
    r"\b(?:fix(?:es|ed)?|close[sd]?|resolve[sd]?)\s+#(\d+)\b",
    re.IGNORECASE,
)

# "(#123)" — inline PR reference in commit titles
PR_REF_PATTERN = re.compile(r"\(#(\d+)\)")


def parse_refs(event: CollectedEvent, owner: str, repo: str) -> None:
    """Fill related_issue_ref/url and related_pr_ref/url in-place.

    Issue patterns (``Fixes #N``) are scanned in both ``title`` and
    ``message``.  The PR inline pattern ``(#N)`` is only matched against
    ``title`` to avoid false positives from PR/issue body text.
    """
    full_text = (event.title or "") + "\n" + (event.message or "")

    issue_match = ISSUE_FIX_PATTERN.search(full_text)
    if issue_match and not event.related_issue_ref:
        num = issue_match.group(1)
        event.related_issue_ref = f"#{num}"
        event.related_issue_url = f"https://github.com/{owner}/{repo}/issues/{num}"

    # Only scan title for PR refs — body text frequently contains (#N)
    # that refers to issues, not PRs.
    pr_match = PR_REF_PATTERN.search(event.title or "")
    if pr_match and not event.related_pr_ref:
        num = pr_match.group(1)
        event.related_pr_ref = f"#{num}"
        event.related_pr_url = f"https://github.com/{owner}/{repo}/pull/{num}"
