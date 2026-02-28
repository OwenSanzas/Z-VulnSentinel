"""Rust ecosystem crawler — fetches top crates from crates.io."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from vulnsentinel.crawler import batch_resolve, get_github_token, parse_github_url

REPOS_JSON = Path(__file__).parent / "repos.json"

CRATES_IO_API = "https://crates.io/api/v1/crates"


async def _fetch_top_crate_names(client: httpx.AsyncClient, n: int) -> list[dict]:
    """Fetch top N crates by download count from crates.io, return raw entries."""
    entries: list[dict] = []
    per_page = 100
    page = 1

    while len(entries) < n:
        resp = await client.get(
            CRATES_IO_API,
            params={"sort": "downloads", "per_page": per_page, "page": page},
        )
        resp.raise_for_status()
        data = resp.json()
        crates = data.get("crates", [])
        if not crates:
            break
        for c in crates:
            repo_url = c.get("repository") or ""
            if parse_github_url(repo_url):
                entries.append({"name": c["id"], "repo_url": repo_url})
            if len(entries) >= n:
                break
        page += 1

    return entries[:n]


async def crawl_top(n: int = 100) -> list[dict]:
    """Crawl top N Rust crates and resolve their GitHub repo metadata."""
    async with httpx.AsyncClient(
        timeout=15,
        headers={"User-Agent": "vulnsentinel-crawler/1.0"},
    ) as client:
        raw = await _fetch_top_crate_names(client, n)

    print(f"  Found {len(raw)} crates with GitHub repos, resolving branches...")
    token = get_github_token()
    resolved = await batch_resolve(raw, token=token)
    return resolved


def save(entries: list[dict]) -> None:
    with open(REPOS_JSON, "w") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  Saved {len(entries)} entries to {REPOS_JSON}")
