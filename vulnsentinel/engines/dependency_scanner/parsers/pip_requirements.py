"""Parser for pip requirements.txt files."""

from __future__ import annotations

import re
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

# Matches: package_name followed by optional version specifier(s)
_REQ_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"\s*"
    r"(.*)?$",  # everything after name = constraint_expr
)

_EXACT_VERSION_RE = re.compile(r"^==\s*([^\s,]+)$")


class PipRequirementsParser:
    detection_method = "pip-requirements"
    file_patterns = ["requirements.txt", "requirements/*.txt"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        deps: list[ScannedDependency] = []
        rel_path = file_path.name

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "-c", "-e", "--")):
                continue

            m = _REQ_RE.match(line)
            if not m:
                continue

            name = m.group(1)
            constraint = (m.group(3) or "").strip() or None

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
                    source_file=rel_path,
                    detection_method=self.detection_method,
                )
            )

        return deps


register_parser(PipRequirementsParser())
