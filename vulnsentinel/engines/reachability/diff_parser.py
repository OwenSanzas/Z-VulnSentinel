"""Diff fallback — extract modified C/C++ function names from a commit diff."""

from __future__ import annotations

import re

import structlog

from vulnsentinel.engines.event_collector.github_client import GitHubClient

log = structlog.get_logger("vulnsentinel.engine.reachability")

_HUNK_HEADER_RE = re.compile(r"^@@.*@@[ \t]+(.+)$", re.MULTILINE)

_C_CPP_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
    }
)


def _is_c_cpp_file(filename: str) -> bool:
    """Return True if filename looks like a C/C++ source or header."""
    for ext in _C_CPP_EXTENSIONS:
        if filename.endswith(ext):
            return True
    return False


def _parse_functions_from_patch(patch: str) -> list[str]:
    """Extract function context labels from unified diff ``@@`` hunk headers.

    GitHub includes the enclosing function name after the ``@@`` range, e.g.::

        @@ -123,4 +123,5 @@ static int parse_url(...)

    We extract ``static int parse_url(...)`` and reduce it to the bare
    function name ``parse_url``.
    """
    funcs: list[str] = []
    for match in _HUNK_HEADER_RE.finditer(patch):
        ctx = match.group(1).strip()
        if not ctx:
            continue
        # Try to extract the function name from the context line.
        # Typical patterns:
        #   "static int parse_url(const char *url)"  → "parse_url"
        #   "void *Curl_disconnect(struct ..."        → "Curl_disconnect"
        #   "parse_url"                               → "parse_url"
        func_match = re.search(r"(\w+)\s*\(", ctx)
        if func_match:
            funcs.append(func_match.group(1))
        else:
            # Bare word — use as-is if it looks like an identifier
            bare = ctx.split()[-1]
            if re.fullmatch(r"[A-Za-z_]\w*", bare):
                funcs.append(bare)
    return funcs


async def extract_functions_from_diff(
    github_client: GitHubClient,
    owner: str,
    repo: str,
    commit_sha: str,
) -> list[str]:
    """Fetch a commit diff from GitHub and extract modified C/C++ function names.

    Uses the ``files[].patch`` field returned by
    ``GET /repos/{owner}/{repo}/commits/{sha}``.

    Returns a deduplicated list of function names, or an empty list if the
    commit has no C/C++ file changes.
    """
    try:
        data = await github_client.get(f"/repos/{owner}/{repo}/commits/{commit_sha}")
    except Exception:
        log.warning(
            "diff_parser.fetch_failed",
            owner=owner,
            repo=repo,
            commit_sha=commit_sha,
            exc_info=True,
        )
        return []

    files = data.get("files", [])
    seen: set[str] = set()
    result: list[str] = []

    for file_entry in files:
        filename = file_entry.get("filename", "")
        if not _is_c_cpp_file(filename):
            continue

        patch = file_entry.get("patch", "")
        if not patch:
            continue

        for func_name in _parse_functions_from_patch(patch):
            if func_name not in seen:
                seen.add(func_name)
                result.append(func_name)

    return result
