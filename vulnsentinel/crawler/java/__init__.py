"""Java ecosystem crawler — fetches top Java libraries via GitHub search + Maven POM fallback."""

from __future__ import annotations

import asyncio
import json
import math
import re
from pathlib import Path
from xml.etree import ElementTree

import httpx

from vulnsentinel.crawler import get_github_token, parse_github_url

REPOS_JSON = Path(__file__).parent / "repos.json"

MAVEN_REPO_BASE = "https://repo1.maven.org/maven2"
MAVEN_SEARCH_API = "https://search.maven.org/solrsearch/select"

_POM_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def _extract_scm_url(pom_xml: str) -> str | None:
    """Parse POM XML and extract SCM URL or project URL."""
    try:
        root = ElementTree.fromstring(pom_xml)
    except ElementTree.ParseError:
        return None

    for scm_path in ("m:scm/m:url", "scm/url"):
        el = root.find(scm_path, _POM_NS)
        if el is not None and el.text and parse_github_url(el.text):
            return el.text

    for tag in (
        "m:scm/m:connection",
        "m:scm/m:developerConnection",
        "scm/connection",
        "scm/developerConnection",
    ):
        el = root.find(tag, _POM_NS)
        if el is not None and el.text:
            url = el.text
            url = re.sub(r"^scm:(git|svn):", "", url)
            url = re.sub(r"^git://github\.com/", "https://github.com/", url)
            if parse_github_url(url):
                return url

    for url_path in ("m:url", "url"):
        el = root.find(url_path, _POM_NS)
        if el is not None and el.text and parse_github_url(el.text):
            return el.text

    return None


async def _search_github_java_repos(
    client: httpx.AsyncClient,
    n: int,
    token: str | None,
) -> list[dict]:
    """Search GitHub for top Java repos by stars."""
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
                "q": "language:java stars:>1000",
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
            entries.append(
                {
                    "name": item["full_name"],
                    "repo_url": item["html_url"],
                    "default_branch": item["default_branch"],
                    "platform": "github",
                }
            )
            if len(entries) >= n:
                break

        if page < pages:
            await asyncio.sleep(2)

    return entries[:n]


async def crawl_top(n: int = 100) -> list[dict]:
    """Crawl top N Java repositories by stars on GitHub."""
    token = get_github_token()

    async with httpx.AsyncClient(timeout=15) as client:
        entries = await _search_github_java_repos(client, n, token)

    print(f"  Found {len(entries)} Java repositories")
    return entries


def save(entries: list[dict]) -> None:
    with open(REPOS_JSON, "w") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  Saved {len(entries)} entries to {REPOS_JSON}")
