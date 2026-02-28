"""Python ecosystem crawler — fetches top packages from PyPI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx

from vulnsentinel.crawler import batch_resolve, get_github_token, parse_github_url

REPOS_JSON = Path(__file__).parent / "repos.json"

TOP_PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
PYPI_JSON_API = "https://pypi.org/pypi/{name}/json"

# Keys to check in project_urls, in priority order
_REPO_KEYS = ("Source", "Source Code", "Repository", "GitHub", "Code", "Homepage")


def _extract_github_url(info: dict) -> str | None:
    """Extract a GitHub URL from PyPI package info."""
    project_urls = info.get("project_urls") or {}
    for key in _REPO_KEYS:
        for pk, pv in project_urls.items():
            if pk.lower() == key.lower() and parse_github_url(pv):
                return pv

    # Fallback: check all project_urls values
    for url in project_urls.values():
        if parse_github_url(url):
            return url

    # Fallback: home_page
    home_page = info.get("home_page") or ""
    if parse_github_url(home_page):
        return home_page

    return None


async def _fetch_top_names(client: httpx.AsyncClient, n: int) -> list[str]:
    """Fetch top N package names from top-pypi-packages."""
    resp = await client.get(TOP_PYPI_URL)
    resp.raise_for_status()
    rows = resp.json().get("rows", [])
    return [r["project"] for r in rows[:n]]


async def _resolve_pypi_repo(
    client: httpx.AsyncClient,
    name: str,
    sem: asyncio.Semaphore,
) -> dict | None:
    """Query PyPI JSON API for a package and extract its GitHub repo URL."""
    async with sem:
        try:
            resp = await client.get(PYPI_JSON_API.format(name=name))
            if resp.status_code != 200:
                return None
        except httpx.HTTPError:
            return None

    info = resp.json().get("info", {})
    github_url = _extract_github_url(info)
    if not github_url:
        return None
    return {"name": name, "repo_url": github_url}


async def crawl_top(n: int = 100) -> list[dict]:
    """Crawl top N Python packages and resolve their GitHub repo metadata."""
    sem = asyncio.Semaphore(20)

    async with httpx.AsyncClient(timeout=15) as client:
        names = await _fetch_top_names(client, n)
        print(f"  Fetched {len(names)} package names, querying PyPI...")

        tasks = [_resolve_pypi_repo(client, name, sem) for name in names]
        results = await asyncio.gather(*tasks)

    raw = [r for r in results if r is not None]
    print(f"  Found {len(raw)} packages with GitHub repos, resolving branches...")

    token = get_github_token()
    resolved = await batch_resolve(raw, token=token)
    return resolved


def save(entries: list[dict]) -> None:
    with open(REPOS_JSON, "w") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  Saved {len(entries)} entries to {REPOS_JSON}")
