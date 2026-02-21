#!/usr/bin/env python3
"""Standalone dependency scanner — no DB required.

Usage:
    python scan_deps.py /path/to/repo
    python scan_deps.py .                                        # scan current directory
    python scan_deps.py https://github.com/org/repo              # clone and scan
    python scan_deps.py https://github.com/org/repo --ref v1.0   # specific branch/tag
    python scan_deps.py /path/to/repo --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.repo import shallow_clone
from vulnsentinel.engines.dependency_scanner.scanner import scan


def _is_url(target: str) -> bool:
    return target.startswith(("https://", "http://", "git@", "ssh://"))


def _print_deps(deps: list, as_json: bool) -> None:
    if not deps:
        print("No dependencies found.")
        return

    if as_json:
        rows = [
            {
                "library_name": d.library_name,
                "library_repo_url": d.library_repo_url,
                "constraint_expr": d.constraint_expr,
                "resolved_version": d.resolved_version,
                "source_file": d.source_file,
                "detection_method": d.detection_method,
            }
            for d in deps
        ]
        print(json.dumps(rows, indent=2))
        return

    # Group by source file
    by_file: dict[str, list] = {}
    for d in deps:
        by_file.setdefault(d.source_file, []).append(d)

    print(f"Found {len(deps)} dependencies in {len(by_file)} manifest(s)\n")

    for source_file, file_deps in sorted(by_file.items()):
        print(f"  {source_file}  ({file_deps[0].detection_method})")
        for d in file_deps:
            version = d.constraint_expr or ""
            url = f"  -> {d.library_repo_url}" if d.library_repo_url else ""
            print(f"    {d.library_name} {version}{url}")
        print()


async def _scan_url(repo_url: str, ref: str | None, as_json: bool) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        ref_label = ref or "default branch"
        print(f"Cloning {repo_url} ({ref_label}) ...", file=sys.stderr)
        repo_path = await shallow_clone(repo_url, ref, Path(tmpdir))
        deps = scan(repo_path)
    _print_deps(deps, as_json)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan a repo for dependencies")
    parser.add_argument("target", help="Local path or git URL to scan")
    parser.add_argument("--ref", default=None, help="Branch or tag to clone (default: remote default)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")
    args = parser.parse_args()

    if _is_url(args.target):
        asyncio.run(_scan_url(args.target, args.ref, args.as_json))
    else:
        repo = Path(args.target).resolve()
        if not repo.is_dir():
            print(f"Error: {repo} is not a directory", file=sys.stderr)
            sys.exit(1)
        deps = scan(repo)
        _print_deps(deps, args.as_json)


if __name__ == "__main__":
    main()
