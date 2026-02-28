"""Seed libraries from repos.json into the database.

For each library:
1. Upsert into the libraries table
2. Fetch latest commit SHA and latest tag from GitHub
3. Set pointers so the event_collector only tracks future events
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from vulnsentinel.core.github import parse_repo_url
from vulnsentinel.dao.library_dao import LibraryDAO
from vulnsentinel.engines.event_collector.github_client import GitHubClient

CRAWLER_DIR = ROOT / "vulnsentinel" / "crawler"

_CONCURRENCY = 10


async def _probe_source(client: GitHubClient, url: str, params: dict | None = None) -> str:
    """Probe a GitHub API endpoint. Returns 'ok' or error string."""
    try:
        await client.get(url, params=params or {"per_page": "1"})
        return "ok"
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


async def _init_pointers(
    client: GitHubClient, owner: str, repo: str, branch: str
) -> dict:
    """Fetch current latest commit SHA and latest tag from GitHub,
    and probe all 5 sources to build collect_detail."""
    pointers: dict = {}

    # Latest commit on default branch
    try:
        commits = await client.get(f"/repos/{owner}/{repo}/commits", params={"sha": branch, "per_page": "1"})
        if isinstance(commits, list) and commits:
            pointers["latest_commit_sha"] = commits[0]["sha"]
    except Exception:
        pass

    # Latest tag
    try:
        tags = await client.get(f"/repos/{owner}/{repo}/tags", params={"per_page": "1"})
        if isinstance(tags, list) and tags:
            pointers["latest_tag_version"] = tags[0]["name"]
    except Exception:
        pass

    # Probe all 5 sources for collect_detail
    prefix = f"/repos/{owner}/{repo}"
    probe_results = await asyncio.gather(
        _probe_source(client, f"{prefix}/commits", {"sha": branch, "per_page": "1"}),
        _probe_source(client, f"{prefix}/pulls", {"state": "closed", "per_page": "1"}),
        _probe_source(client, f"{prefix}/tags", {"per_page": "1"}),
        _probe_source(client, f"{prefix}/issues", {"labels": "bug", "state": "all", "per_page": "1"}),
        _probe_source(client, f"{prefix}/security-advisories", {"state": "published", "per_page": "1"}),
    )
    source_names = ["commits", "prs", "tags", "issues", "ghsa"]
    pointers["collect_detail"] = dict(zip(source_names, probe_results))

    return pointers


async def main() -> None:
    url = os.environ.get(
        "VULNSENTINEL_DATABASE_URL",
        os.environ.get("DATABASE_URL", "postgresql+asyncpg://localhost/vulnsentinel"),
    )
    engine = create_async_engine(url, pool_pre_ping=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    client = GitHubClient()

    # Discover all ecosystem repos.json files
    all_repos: list[dict] = []
    for repos_json in sorted(CRAWLER_DIR.glob("*/repos.json")):
        ecosystem = repos_json.parent.name
        with open(repos_json) as f:
            eco_repos = json.load(f)
        for r in eco_repos:
            r["ecosystem"] = ecosystem
        all_repos.extend(eco_repos)
        print(f"  {ecosystem}: {len(eco_repos)} libraries")

    print(f"Seeding {len(all_repos)} libraries total ...")

    # Phase 1: upsert all libraries
    dao = LibraryDAO()
    lib_map: dict[str, dict] = {}  # name -> {id, repo_url, default_branch}

    async with factory() as session:
        for repo in all_repos:
            try:
                lib = await dao.upsert_by_name(
                    session,
                    name=repo["name"],
                    repo_url=repo["repo_url"],
                    platform=repo.get("platform", "github"),
                    default_branch=repo.get("default_branch", "main"),
                    ecosystem=repo.get("ecosystem", "c_cpp"),
                )
                # Set last_scanned_at on first seed so it counts as activity
                if lib.last_scanned_at is None:
                    await dao.update_pointers(
                        session, lib.id, last_scanned_at=datetime.now(timezone.utc)
                    )
                lib_map[lib.name] = {
                    "id": lib.id,
                    "repo_url": lib.repo_url,
                    "branch": lib.default_branch,
                    "has_pointers": lib.latest_commit_sha is not None,
                }
            except Exception as e:
                print(f"  SKIP {repo['name']}: {e}")
        await session.commit()

    # Phase 2: initialize pointers for libraries that don't have them yet
    need_init = {name: info for name, info in lib_map.items() if not info["has_pointers"]}
    if not need_init:
        print(f"All {len(lib_map)} libraries already have pointers. Done.")
        await client.close()
        await engine.dispose()
        return

    print(f"Initializing pointers for {len(need_init)} new libraries ...")
    sem = asyncio.Semaphore(_CONCURRENCY)
    now = datetime.now(timezone.utc)
    results: dict[str, dict] = {}

    async def _fetch_one(name: str, info: dict) -> None:
        async with sem:
            try:
                owner, repo = parse_repo_url(info["repo_url"])
                ptrs = await _init_pointers(client, owner, repo, info["branch"])
                results[name] = ptrs
            except Exception as e:
                print(f"  WARN {name}: {e}")

    await asyncio.gather(*[_fetch_one(n, i) for n, i in need_init.items()])

    # Write pointers to DB
    async with factory() as session:
        for name, ptrs in results.items():
            info = lib_map[name]
            await dao.update_pointers(
                session,
                info["id"],
                latest_commit_sha=ptrs.get("latest_commit_sha"),
                latest_tag_version=ptrs.get("latest_tag_version"),
                last_scanned_at=now,
                collect_detail=ptrs.get("collect_detail"),
            )
        await session.commit()

    ok = sum(1 for p in results.values() if p)
    print(f"Done: {len(lib_map)} libraries upserted, {ok} pointers initialized.")

    await client.close()
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
