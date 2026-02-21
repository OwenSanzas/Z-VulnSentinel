"""Parser for Foundry/Soldeer dependencies in foundry.toml.

Extracts dependencies from the [dependencies] section of foundry.toml,
which is the native package manager for Foundry (Solidity) projects.

Formats:
  [dependencies]
  forge-std = "1.9.1"
  "@openzeppelin-contracts" = "5.0.2"
  solmate = { version = "6.7.0", url = "https://github.com/transmissions11/solmate" }
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover
        import tomli as tomllib  # type: ignore[no-redef]

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser


class FoundryTomlParser:
    detection_method = "foundry-soldeer"
    file_patterns = ["foundry.toml"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        try:
            data = tomllib.loads(content)
        except Exception:
            return []

        dep_section = data.get("dependencies")
        if not dep_section or not isinstance(dep_section, dict):
            return []

        deps: list[ScannedDependency] = []

        for name, value in dep_section.items():
            version: str | None = None
            repo_url: str | None = None

            if isinstance(value, str):
                # forge-std = "1.9.1"
                version = value
            elif isinstance(value, dict):
                # solmate = { version = "6.7.0", url = "..." }
                version = value.get("version")
                repo_url = value.get("url")

            deps.append(
                ScannedDependency(
                    library_name=name,
                    library_repo_url=repo_url,
                    constraint_expr=version,
                    resolved_version=version,
                    source_file=file_path.name,
                    detection_method=self.detection_method,
                )
            )

        return deps


register_parser(FoundryTomlParser())
