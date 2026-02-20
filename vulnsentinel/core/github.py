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


def _extract_owner_repo(repo_url: str) -> str | None:
    """Extract 'owner/repo' from a GitHub URL.

    Handles:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
    """
    repo_url = repo_url.rstrip("/")
    if repo_url.endswith(".git"):
        repo_url = repo_url[:-4]
    parts = repo_url.split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return None
