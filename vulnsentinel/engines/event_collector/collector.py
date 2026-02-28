"""Event collector engine — pure API collection, no DB access."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone

import structlog

from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.engines.event_collector.models import CollectedEvent
from vulnsentinel.engines.event_collector.ref_parser import parse_refs

log = structlog.get_logger("vulnsentinel.engine")

# Default lookback window for first-time collection.
_FIRST_COLLECT_DAYS = 30
_FIRST_COLLECT_MAX_PAGES = 3
_DEFAULT_MAX_PAGES = 10


async def collect(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    branch: str = "main",
    since: datetime | None = None,
    last_sha: str | None = None,
    latest_tag: str | None = None,
) -> tuple[list[CollectedEvent], list[str], dict[str, str]]:
    """Collect events from the GitHub API for a single repository.

    Returns ``(events, errors, detail)`` — *events* is a flat list of
    :class:`CollectedEvent` instances, *errors* contains one message
    per sub-collector that failed, and *detail* maps each sub-collector
    name to ``"ok"`` or an error string.  This function is pure — it
    never touches the database.
    """
    # First-time collection: limit scope
    first_time = since is None
    if first_time:
        since = datetime.now(timezone.utc) - timedelta(days=_FIRST_COLLECT_DAYS)
    max_pages = _FIRST_COLLECT_MAX_PAGES if first_time else _DEFAULT_MAX_PAGES

    sub_task_names = ["commits", "prs", "tags", "issues", "ghsa"]
    results = await asyncio.gather(
        _collect_commits(
            client, owner, repo, branch=branch, since=since, last_sha=last_sha, max_pages=max_pages
        ),
        _collect_prs(client, owner, repo, since=since, max_pages=max_pages),
        _collect_tags(client, owner, repo, latest_tag=latest_tag, max_pages=max_pages),
        _collect_issues(client, owner, repo, since=since, max_pages=max_pages),
        _collect_ghsa(client, owner, repo, since=since, max_pages=max_pages),
        return_exceptions=True,
    )

    events: list[CollectedEvent] = []
    errors: list[str] = []
    detail: dict[str, str] = {}
    for name, result in zip(sub_task_names, results, strict=False):
        if isinstance(result, BaseException):
            err_msg = f"{type(result).__name__}: {result}"
            msg = f"collect_{name} failed for {owner}/{repo}: {err_msg}"
            log.error(
                "collector.sub_failed",
                collector=name,
                library=f"{owner}/{repo}",
                error=str(result),
            )
            errors.append(msg)
            detail[name] = err_msg
            continue
        events.extend(result)
        detail[name] = "ok"

    # Enrich with cross-references
    for ev in events:
        parse_refs(ev, owner, repo)

    return events, errors, detail


# ── sub-collectors ────────────────────────────────────────────────────────


async def _collect_commits(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    branch: str,
    since: datetime,
    last_sha: str | None,
    max_pages: int,
) -> list[CollectedEvent]:
    """GET /repos/{owner}/{repo}/commits — exclude merge commits."""
    params: dict = {
        "sha": branch,
        "since": since.isoformat(),
    }
    events: list[CollectedEvent] = []
    async for item in client.get_paginated(
        f"/repos/{owner}/{repo}/commits", params, max_pages=max_pages
    ):
        sha = item["sha"]
        # Stop if we've reached the last known SHA
        if last_sha and sha == last_sha:
            break

        commit = item.get("commit", {})

        # Skip merge commits (2+ parents)
        parents = item.get("parents", [])
        if len(parents) > 1:
            continue

        message = commit.get("message", "")
        title = message.split("\n", 1)[0]

        author_info = commit.get("author") or {}
        event_at = _parse_datetime(author_info.get("date"))

        author_login = None
        if item.get("author"):
            author_login = item["author"].get("login")

        events.append(
            CollectedEvent(
                type="commit",
                ref=sha,
                title=title,
                source_url=item.get("html_url"),
                author=author_login,
                event_at=event_at,
                message=message if message != title else None,
            )
        )
    return events


async def _collect_prs(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    since: datetime,
    max_pages: int,
) -> list[CollectedEvent]:
    """GET /repos/{owner}/{repo}/pulls?state=closed — only merged PRs.

    Sorted by ``updated`` (desc) because the pulls API has no ``since``
    parameter.  We cannot ``break`` on ``merged_at < since`` because
    ``updated_at`` and ``merged_at`` are independent — a stale PR with a
    recent comment would appear first and cause us to miss newer merges.
    Instead we skip non-matching PRs and rely on ``max_pages`` to bound.
    """
    params: dict = {
        "state": "closed",
        "sort": "updated",
        "direction": "desc",
    }
    events: list[CollectedEvent] = []
    async for item in client.get_paginated(
        f"/repos/{owner}/{repo}/pulls", params, max_pages=max_pages
    ):
        merged_at = _parse_datetime(item.get("merged_at"))
        if not merged_at:
            continue
        # Skip PRs merged before our window — but don't break, because
        # sort=updated doesn't guarantee merged_at ordering.
        if merged_at < since:
            continue

        pr_number = item["number"]
        merge_sha = item.get("merge_commit_sha")

        events.append(
            CollectedEvent(
                type="pr_merge",
                ref=str(pr_number),
                title=item.get("title", ""),
                source_url=item.get("html_url"),
                author=item.get("user", {}).get("login"),
                event_at=merged_at,
                message=item.get("body"),
                related_commit_sha=merge_sha,
            )
        )
    return events


async def _collect_tags(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    latest_tag: str | None,
    max_pages: int,
) -> list[CollectedEvent]:
    """GET /repos/{owner}/{repo}/tags — stop at latest known tag."""
    events: list[CollectedEvent] = []
    async for item in client.get_paginated(f"/repos/{owner}/{repo}/tags", max_pages=max_pages):
        tag_name = item["name"]
        if latest_tag and tag_name == latest_tag:
            break

        sha = item.get("commit", {}).get("sha")

        events.append(
            CollectedEvent(
                type="tag",
                ref=tag_name,
                title=tag_name,
                source_url=f"https://github.com/{owner}/{repo}/releases/tag/{tag_name}",
                related_commit_sha=sha,
            )
        )
    return events


async def _collect_issues(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    since: datetime,
    max_pages: int,
) -> list[CollectedEvent]:
    """GET /repos/{owner}/{repo}/issues?labels=bug — exclude PRs."""
    params: dict = {
        "labels": "bug",
        "state": "all",
        "sort": "updated",
        "direction": "desc",
        "since": since.isoformat(),
    }
    events: list[CollectedEvent] = []
    async for item in client.get_paginated(
        f"/repos/{owner}/{repo}/issues", params, max_pages=max_pages
    ):
        # GitHub issues API includes PRs; skip them
        if "pull_request" in item:
            continue

        issue_number = item["number"]
        created_at = _parse_datetime(item.get("created_at"))

        events.append(
            CollectedEvent(
                type="bug_issue",
                ref=str(issue_number),
                title=item.get("title", ""),
                source_url=item.get("html_url"),
                author=item.get("user", {}).get("login"),
                event_at=created_at,
                message=item.get("body"),
            )
        )
    return events


async def _collect_ghsa(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    since: datetime,
    max_pages: int,
) -> list[CollectedEvent]:
    """GET /repos/{owner}/{repo}/security-advisories — published advisories."""
    params: dict = {
        "state": "published",
        "per_page": "30",
    }
    events: list[CollectedEvent] = []
    async for item in client.get_paginated(
        f"/repos/{owner}/{repo}/security-advisories", params, max_pages=max_pages
    ):
        published_at = _parse_datetime(item.get("published_at"))
        if published_at and published_at < since:
            continue

        ghsa_id = item.get("ghsa_id", "")
        summary = item.get("summary", "")

        events.append(
            CollectedEvent(
                type="ghsa",
                ref=ghsa_id,
                title=summary,
                source_url=item.get("html_url"),
                event_at=published_at,
                message=item.get("description"),
            )
        )
    return events


# ── helpers ───────────────────────────────────────────────────────────────


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse an ISO-8601 datetime string, returning None on failure."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def count_by_type(events: list[CollectedEvent]) -> dict[str, int]:
    """Count events grouped by type."""
    return dict(Counter(e.type for e in events))
