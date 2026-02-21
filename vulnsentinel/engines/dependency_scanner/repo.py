"""Git clone helper for the dependency scanner."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path


async def shallow_clone(repo_url: str, ref: str | None, workdir: Path) -> Path:
    """Clone a repo into *workdir*, checkout *ref*, and return the clone path.

    *ref* can be a branch name, tag name, or commit SHA.
    If *ref* is None, the remote's default branch is used.

    The caller is responsible for cleaning up the directory (e.g. via
    ``tempfile.TemporaryDirectory`` or ``try/finally``).

    Raises ``RuntimeError`` on non-zero exit code.
    """
    target = workdir / f"repo-{uuid.uuid4().hex[:8]}"

    # Clone the repo (full history so any ref — branch, tag, SHA — works)
    clone_cmd = ["git", "clone", "--", repo_url, str(target)]
    await _run(clone_cmd)

    # Checkout the requested ref if specified
    if ref:
        checkout_cmd = ["git", "-C", str(target), "checkout", ref]
        await _run(checkout_cmd)

    return target


async def _run(cmd: list[str]) -> None:
    """Run a git command, raising RuntimeError on failure."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(
            f"git command failed (exit {proc.returncode}): {stderr.decode().strip()}"
        )
