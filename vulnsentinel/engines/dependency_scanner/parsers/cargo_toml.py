"""Parser for Rust Cargo.toml files."""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

_DEP_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def _parse_version(spec: str | dict) -> str | None:
    """Extract version constraint from a dependency spec."""
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return spec.get("version")
    return None


class CargoTomlParser:
    detection_method = "cargo-toml"
    file_patterns = ["**/Cargo.toml"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        try:
            data = tomllib.loads(content)
        except Exception:
            return []

        deps: list[ScannedDependency] = []

        for section in _DEP_SECTIONS:
            dep_table = data.get(section, {})
            for name, spec in dep_table.items():
                version = _parse_version(spec)

                # Extract git repo if specified in table form
                repo_url: str | None = None
                if isinstance(spec, dict):
                    repo_url = spec.get("git")

                deps.append(
                    ScannedDependency(
                        library_name=name,
                        library_repo_url=repo_url,
                        constraint_expr=version,
                        resolved_version=None,
                        source_file=file_path.name,
                        detection_method=self.detection_method,
                    )
                )

        return deps


register_parser(CargoTomlParser())
