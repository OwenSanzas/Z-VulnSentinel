"""GitHub API utilities."""

import httpx


async def verify_git_ref(repo_url: str, ref: str) -> bool:
    """Check if a git ref (tag or commit SHA) exists in a GitHub repo.

    Tries the commit endpoint first (works for both SHA and tags),
    then falls back to the git ref endpoint for tag names.

    Returns True if the ref exists, False otherwise.
    """
    owner_repo = _extract_owner_repo(repo_url)
    if owner_repo is None:
        return False

    async with httpx.AsyncClient(timeout=10) as client:
        # Try as commit SHA or tag (GitHub resolves tags here too)
        resp = await client.get(
            f"https://api.github.com/repos/{owner_repo}/commits/{ref}",
            headers={"Accept": "application/vnd.github+json"},
        )
        if resp.status_code == 200:
            return True

        # Try as git ref (tags/xxx or heads/xxx)
        resp = await client.get(
            f"https://api.github.com/repos/{owner_repo}/git/ref/tags/{ref}",
            headers={"Accept": "application/vnd.github+json"},
        )
        return resp.status_code == 200


def parse_repo_url(repo_url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL.

    Raises ValueError if the URL cannot be parsed.
    """
    result = _extract_owner_repo(repo_url)
    if result is None:
        raise ValueError(f"cannot parse GitHub repo URL: {repo_url!r}")
    owner, repo = result.split("/", 1)
    return owner, repo


def _extract_owner_repo(repo_url: str) -> str | None:
    """Extract 'owner/repo' from a GitHub URL.

    Handles:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - git@github.com:owner/repo.git
    """
    repo_url = repo_url.strip().rstrip("/")
    if repo_url.endswith(".git"):
        repo_url = repo_url[:-4]

    # SSH format: git@github.com:owner/repo
    if repo_url.startswith("git@"):
        colon_idx = repo_url.find(":")
        if colon_idx == -1:
            return None
        path = repo_url[colon_idx + 1 :]
        parts = path.split("/")
        if len(parts) == 2 and all(parts):
            return f"{parts[0]}/{parts[1]}"
        return None

    # HTTPS format: https://github.com/owner/repo
    parts = repo_url.split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return None
