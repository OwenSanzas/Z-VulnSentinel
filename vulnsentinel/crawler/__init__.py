"""Shared utilities for ecosystem crawlers."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

_GITHUB_URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/#?]+)",
)


def parse_github_url(url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from various GitHub URL formats."""
    m = _GITHUB_URL_RE.search(url)
    if not m:
        return None
    owner = m.group(1)
    repo = m.group(2).removesuffix(".git")
    return owner, repo


async def resolve_github_default_branch(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    token: str | None = None,
) -> str | None:
    """Call GitHub API to get default_branch. Returns None on failure."""
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers=headers,
        )
        if resp.status_code == 200:
            return resp.json().get("default_branch")
    except httpx.HTTPError:
        pass
    return None


async def batch_resolve(
    entries: list[dict],
    token: str | None = None,
    concurrency: int = 10,
) -> list[dict]:
    """Resolve default_branch for entries concurrently.

    Each entry must have ``name`` and ``repo_url``.
    Returns entries enriched with ``default_branch`` and ``platform``.
    Entries whose repo_url is not a valid GitHub URL are dropped.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _resolve_one(client: httpx.AsyncClient, entry: dict) -> dict | None:
        parsed = parse_github_url(entry["repo_url"])
        if not parsed:
            return None
        owner, repo = parsed
        async with sem:
            branch = await resolve_github_default_branch(client, owner, repo, token)
        if branch is None:
            return None
        return {
            "name": entry["name"],
            "repo_url": f"https://github.com/{owner}/{repo}",
            "default_branch": branch,
            "platform": "github",
        }

    async with httpx.AsyncClient(timeout=15) as client:
        tasks = [_resolve_one(client, e) for e in entries]
        results = await asyncio.gather(*tasks)

    return [r for r in results if r is not None]


def get_github_token() -> str | None:
    """Try to read a GitHub token from env or gh CLI config."""
    import os
    import subprocess

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None
