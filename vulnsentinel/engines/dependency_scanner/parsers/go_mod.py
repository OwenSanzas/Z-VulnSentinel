"""Parser for Go go.mod files."""

from __future__ import annotations

import re
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

# Single require: require github.com/foo/bar v1.2.3
_SINGLE_RE = re.compile(r"^require\s+(\S+)\s+(\S+)")

# Inside require block: github.com/foo/bar v1.2.3
_BLOCK_RE = re.compile(r"^\s+(\S+)\s+(v\S+)")

# Module paths that map to browsable repo URLs
_HOST_PREFIXES = ("github.com/", "gitlab.com/", "bitbucket.org/")


def _repo_url_from_module(module_path: str) -> str | None:
    """Derive a repo URL from a Go module path.

    Only works for well-known hosts (github, gitlab, bitbucket).
    Returns None for other module paths.
    """
    for prefix in _HOST_PREFIXES:
        if module_path.startswith(prefix):
            # Take first 3 segments: host/org/repo
            parts = module_path.split("/")
            if len(parts) >= 3:
                return "https://" + "/".join(parts[:3])
    return None


class GoModParser:
    detection_method = "go-mod"
    file_patterns = ["go.mod"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        deps: list[ScannedDependency] = []
        in_require_block = False

        for raw_line in content.splitlines():
            line = raw_line.strip()

            # Skip comments and indirect deps
            if line.startswith("//") or "// indirect" in line:
                continue

            # Detect require block boundaries
            if line.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and line == ")":
                in_require_block = False
                continue

            module: str | None = None
            version: str | None = None

            if in_require_block:
                m = _BLOCK_RE.match(raw_line)
                if m:
                    module, version = m.group(1), m.group(2)
            else:
                m = _SINGLE_RE.match(line)
                if m:
                    module, version = m.group(1), m.group(2)

            if module and version:
                deps.append(
                    ScannedDependency(
                        library_name=module,
                        library_repo_url=_repo_url_from_module(module),
                        constraint_expr=version,
                        resolved_version=(
                            version.lstrip("v") if version.startswith("v") else version
                        ),
                        source_file=file_path.name,
                        detection_method=self.detection_method,
                    )
                )

        return deps


register_parser(GoModParser())
