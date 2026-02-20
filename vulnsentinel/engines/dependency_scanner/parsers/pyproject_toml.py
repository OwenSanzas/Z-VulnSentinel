"""Parser for Python pyproject.toml [project].dependencies."""

from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

# PEP 508 simplified: name followed by optional extras and version specifiers
_PEP508_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"(\[[^\]]*\])?"  # optional extras [extra1,extra2]
    r"\s*"
    r"(.*)?$",  # version specifiers
)

_EXACT_VERSION_RE = re.compile(r"^==\s*([^\s,;]+)$")


class PyprojectTomlParser:
    detection_method = "pyproject-toml"
    file_patterns = ["pyproject.toml"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        try:
            data = tomllib.loads(content)
        except Exception:
            return []

        dep_strings: list[str] = data.get("project", {}).get("dependencies", [])
        deps: list[ScannedDependency] = []

        for raw in dep_strings:
            line = raw.strip()
            if not line:
                continue

            # Strip environment markers (everything after ";")
            marker_pos = line.find(";")
            if marker_pos != -1:
                line = line[:marker_pos].strip()

            m = _PEP508_RE.match(line)
            if not m:
                continue

            name = m.group(1)
            constraint = (m.group(4) or "").strip() or None

            resolved: str | None = None
            if constraint:
                exact = _EXACT_VERSION_RE.match(constraint)
                if exact:
                    resolved = exact.group(1)

            deps.append(
                ScannedDependency(
                    library_name=name,
                    library_repo_url=None,
                    constraint_expr=constraint,
                    resolved_version=resolved,
                    source_file=file_path.name,
                    detection_method=self.detection_method,
                )
            )

        return deps


register_parser(PyprojectTomlParser())
