"""Go ecosystem crawler — fetches top Go modules via GitHub search."""

from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path

import httpx

from vulnsentinel.crawler import get_github_token

REPOS_JSON = Path(__file__).parent / "repos.json"


async def _search_github_go_repos(
    client: httpx.AsyncClient,
    n: int,
    token: str | None,
) -> list[dict]:
    """Search GitHub for top Go repos by stars."""
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    entries: list[dict] = []
    per_page = 100
    pages = math.ceil(n / per_page)

    for page in range(1, pages + 1):
        resp = await client.get(
            "https://api.github.com/search/repositories",
            params={
                "q": "language:go stars:>500",
                "sort": "stars",
                "order": "desc",
                "per_page": per_page,
                "page": page,
            },
            headers=headers,
        )
        if resp.status_code != 200:
            print(f"  Warning: GitHub search returned {resp.status_code} on page {page}")
            break

        items = resp.json().get("items", [])
        if not items:
            break

        for item in items:
            entries.append({
                "name": item["full_name"],
                "repo_url": item["html_url"],
                "default_branch": item["default_branch"],
                "platform": "github",
            })
            if len(entries) >= n:
                break

        # Respect GitHub search rate limit (30 req/min for search)
        if page < pages:
            await asyncio.sleep(2)

    return entries[:n]


async def crawl_top(n: int = 100) -> list[dict]:
    """Crawl top N Go repositories by stars on GitHub."""
    token = get_github_token()

    async with httpx.AsyncClient(timeout=15) as client:
        entries = await _search_github_go_repos(client, n, token)

    print(f"  Found {len(entries)} Go repositories")
    return entries


def save(entries: list[dict]) -> None:
    with open(REPOS_JSON, "w") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  Saved {len(entries)} entries to {REPOS_JSON}")
