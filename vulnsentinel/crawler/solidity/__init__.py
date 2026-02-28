"""Solidity ecosystem crawler — fetches top Solidity libraries via GitHub search."""

from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path

import httpx

from vulnsentinel.crawler import get_github_token

REPOS_JSON = Path(__file__).parent / "repos.json"

# Well-known Solidity contract libraries that should always be included
_KNOWN_LIBS: list[dict] = [
    {"name": "OpenZeppelin/openzeppelin-contracts", "repo_url": "https://github.com/OpenZeppelin/openzeppelin-contracts"},
    {"name": "OpenZeppelin/openzeppelin-contracts-upgradeable", "repo_url": "https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable"},
    {"name": "smartcontractkit/chainlink", "repo_url": "https://github.com/smartcontractkit/chainlink"},
    {"name": "Uniswap/v3-core", "repo_url": "https://github.com/Uniswap/v3-core"},
    {"name": "Uniswap/v4-core", "repo_url": "https://github.com/Uniswap/v4-core"},
    {"name": "aave/aave-v3-core", "repo_url": "https://github.com/aave/aave-v3-core"},
    {"name": "compound-finance/compound-protocol", "repo_url": "https://github.com/compound-finance/compound-protocol"},
    {"name": "transmissions11/solmate", "repo_url": "https://github.com/transmissions11/solmate"},
    {"name": "Vectorized/solady", "repo_url": "https://github.com/Vectorized/solady"},
    {"name": "foundry-rs/forge-std", "repo_url": "https://github.com/foundry-rs/forge-std"},
    {"name": "safe-fndn/safe-smart-account", "repo_url": "https://github.com/safe-fndn/safe-smart-account"},
]


async def _search_github_solidity_repos(
    client: httpx.AsyncClient,
    n: int,
    token: str | None,
) -> list[dict]:
    """Search GitHub for top Solidity repos by stars."""
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    entries: list[dict] = []
    seen: set[str] = set()
    per_page = 100
    pages = math.ceil(n / per_page)

    for page in range(1, pages + 1):
        resp = await client.get(
            "https://api.github.com/search/repositories",
            params={
                "q": "language:solidity stars:>50",
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
            full_name = item["full_name"]
            if full_name in seen:
                continue
            seen.add(full_name)
            entries.append({
                "name": full_name,
                "repo_url": item["html_url"],
                "default_branch": item["default_branch"],
                "platform": "github",
            })
            if len(entries) >= n:
                break

        if page < pages:
            await asyncio.sleep(2)

    return entries[:n]


async def crawl_top(n: int = 100) -> list[dict]:
    """Crawl top N Solidity repositories, merging known libs with GitHub search."""
    token = get_github_token()

    async with httpx.AsyncClient(timeout=15) as client:
        searched = await _search_github_solidity_repos(client, n, token)

    # Merge: known libs first, then fill from search (dedup by name)
    seen: set[str] = set()
    merged: list[dict] = []

    # Resolve known libs' default_branch from search results if available
    search_by_name = {e["name"]: e for e in searched}

    for lib in _KNOWN_LIBS:
        name = lib["name"]
        if name in search_by_name:
            merged.append(search_by_name[name])
        else:
            # Will need branch resolution
            merged.append({
                "name": name,
                "repo_url": lib["repo_url"],
                "default_branch": "main",  # default guess, health_check --fix can correct
                "platform": "github",
            })
        seen.add(name)

    for entry in searched:
        if entry["name"] not in seen:
            merged.append(entry)
            seen.add(entry["name"])
        if len(merged) >= n:
            break

    print(f"  Found {len(merged)} Solidity repositories")
    return merged[:n]


def save(entries: list[dict]) -> None:
    with open(REPOS_JSON, "w") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  Saved {len(entries)} entries to {REPOS_JSON}")
