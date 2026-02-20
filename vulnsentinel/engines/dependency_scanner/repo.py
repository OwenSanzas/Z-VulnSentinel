"""Git clone helper for the dependency scanner."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path


async def shallow_clone(repo_url: str, ref: str | None, workdir: Path) -> Path:
    """Clone a repo with depth 1 into *workdir* and return the clone path.

    If *ref* is None, the remote's default branch is used.
    The caller is responsible for cleaning up the directory (e.g. via
    ``tempfile.TemporaryDirectory`` or ``try/finally``).

    Raises ``RuntimeError`` on non-zero exit code.
    """
    target = workdir / f"repo-{uuid.uuid4().hex[:8]}"
    cmd = ["git", "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref, "--single-branch"]
    cmd += [repo_url, str(target)]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(
            f"git clone failed (exit {proc.returncode}): {stderr.decode().strip()}"
        )
    return target
