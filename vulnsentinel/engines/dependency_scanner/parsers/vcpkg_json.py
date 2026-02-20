"""Parser for vcpkg.json manifest files (C/C++)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser


class VcpkgJsonParser:
    detection_method = "vcpkg"
    file_patterns = ["vcpkg.json"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        deps: list[ScannedDependency] = []
        for entry in data.get("dependencies", []):
            if isinstance(entry, str):
                name = entry
                version = None
            elif isinstance(entry, dict):
                name = entry.get("name")
                if not name:
                    continue
                version = entry.get("version>=") or entry.get("version")
            else:
                continue

            deps.append(
                ScannedDependency(
                    library_name=name,
                    library_repo_url=None,
                    constraint_expr=f">={version}" if version else None,
                    resolved_version=None,
                    source_file=file_path.name,
                    detection_method=self.detection_method,
                )
            )

        return deps


register_parser(VcpkgJsonParser())
