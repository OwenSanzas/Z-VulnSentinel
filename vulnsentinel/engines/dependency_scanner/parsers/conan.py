"""Parser for Conan conanfile.txt files (C/C++)."""

from __future__ import annotations

import re
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

# Matches: name/version[@user/channel]
_CONAN_REF_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.\-+]*)/(\S+?)(?:@\S+)?$")


class ConanParser:
    detection_method = "conan"
    file_patterns = ["conanfile.txt"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        deps: list[ScannedDependency] = []
        in_requires = False

        for raw_line in content.splitlines():
            line = raw_line.strip()

            if line.lower() == "[requires]":
                in_requires = True
                continue

            # Any other section header ends [requires]
            if line.startswith("[") and line.endswith("]"):
                in_requires = False
                continue

            if not in_requires or not line or line.startswith("#"):
                continue

            m = _CONAN_REF_RE.match(line)
            if not m:
                continue

            name = m.group(1)
            version = m.group(2)

            deps.append(
                ScannedDependency(
                    library_name=name,
                    library_repo_url=None,
                    constraint_expr=f"=={version}",
                    resolved_version=version,
                    source_file=file_path.name,
                    detection_method=self.detection_method,
                )
            )

        return deps


register_parser(ConanParser())
