"""GitHub read-only MCP tools for LLM agents."""

from __future__ import annotations

import base64
from typing import Any

from mcp.server.fastmcp import FastMCP

from vulnsentinel.engines.event_collector.github_client import GitHubClient

_MAX_CHARS = 15_000


def _truncate(text: str) -> str:
    if len(text) <= _MAX_CHARS:
        return text
    return text[:_MAX_CHARS] + f"\n\n[truncated — {len(text)} chars total]"


def _diffstat(files: list[dict[str, Any]]) -> str:
    """Build a concise diffstat from the GitHub files array."""
    lines: list[str] = []
    for f in files:
        name = f.get("filename", "?")
        adds = f.get("additions", 0)
        dels = f.get("deletions", 0)
        status = f.get("status", "modified")
        lines.append(f"  {status:10s} +{adds}/-{dels}  {name}")
    return "\n".join(lines)


def create_github_mcp(client: GitHubClient, owner: str, repo: str) -> FastMCP:
    """Create a FastMCP server with GitHub read-only tools.

    *client*, *owner*, and *repo* are captured by closure — MCP tool
    parameters only expose the parts the LLM should control.
    """
    mcp = FastMCP("github-tools")
    prefix = f"/repos/{owner}/{repo}"

    @mcp.tool()
    async def fetch_commit_diff(sha: str, file_path: str = "") -> str:
        """Fetch commit diff.

        Without file_path returns a diffstat summary;
        with file_path returns the full patch for that file.
        """
        data = await client.get(f"{prefix}/commits/{sha}")
        files: list[dict[str, Any]] = data.get("files", [])
        if not files:
            return "No files changed in this commit."

        if not file_path:
            header = f"Commit {sha[:12]} — {len(files)} file(s) changed\n"
            return _truncate(header + _diffstat(files))

        for f in files:
            if f.get("filename") == file_path:
                patch = f.get("patch", "(binary or too large)")
                return _truncate(f"--- {file_path} ---\n{patch}")
        return f"File '{file_path}' not found in commit {sha[:12]}."

    @mcp.tool()
    async def fetch_pr_diff(pr_number: int, file_path: str = "") -> str:
        """Fetch PR diff.

        Without file_path returns a diffstat summary;
        with file_path returns the full patch for that file.
        """
        files: list[dict[str, Any]] = []
        async for item in client.get_paginated(
            f"{prefix}/pulls/{pr_number}/files", max_pages=3
        ):
            files.append(item)

        if not files:
            return "No files changed in this PR."

        if not file_path:
            header = f"PR #{pr_number} — {len(files)} file(s) changed\n"
            return _truncate(header + _diffstat(files))

        for f in files:
            if f.get("filename") == file_path:
                patch = f.get("patch", "(binary or too large)")
                return _truncate(f"--- {file_path} ---\n{patch}")
        return f"File '{file_path}' not found in PR #{pr_number}."

    @mcp.tool()
    async def fetch_file_content(
        path: str, ref: str = "HEAD", start_line: int = 0, end_line: int = 0
    ) -> str:
        """Fetch a file's content at a given ref (branch, tag, or SHA).

        Use start_line/end_line to fetch a specific line range (1-indexed).
        If both are 0, returns the full file (may be truncated if large).
        """
        data = await client.get(f"{prefix}/contents/{path}", params={"ref": ref})
        encoding = data.get("encoding", "")
        if encoding == "base64":
            content = base64.b64decode(data.get("content", "")).decode(
                "utf-8", errors="replace"
            )
        else:
            content = data.get("content", "(unable to decode)")

        if start_line > 0 or end_line > 0:
            lines = content.splitlines()
            s = max(start_line - 1, 0)
            e = end_line if end_line > 0 else len(lines)
            selected = lines[s:e]
            numbered = [f"{s + i + 1:5d} | {line}" for i, line in enumerate(selected)]
            return _truncate("\n".join(numbered))

        return _truncate(content)

    @mcp.tool()
    async def fetch_issue_body(issue_number: int) -> str:
        """Fetch an issue's title, body, and labels."""
        data = await client.get(f"{prefix}/issues/{issue_number}")
        title = data.get("title", "")
        body = data.get("body", "") or ""
        labels = [lb.get("name", "") for lb in data.get("labels", [])]
        parts = [f"# {title}"]
        if labels:
            parts.append(f"Labels: {', '.join(labels)}")
        parts.append(body)
        return _truncate("\n\n".join(parts))

    @mcp.tool()
    async def fetch_pr_body(pr_number: int) -> str:
        """Fetch a pull request's title, body, and labels."""
        data = await client.get(f"{prefix}/pulls/{pr_number}")
        title = data.get("title", "")
        body = data.get("body", "") or ""
        labels = [lb.get("name", "") for lb in data.get("labels", [])]
        parts = [f"# {title}"]
        if labels:
            parts.append(f"Labels: {', '.join(labels)}")
        parts.append(body)
        return _truncate("\n\n".join(parts))

    return mcp
