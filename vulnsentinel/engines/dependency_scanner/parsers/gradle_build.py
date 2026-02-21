"""Parser for Gradle build files (build.gradle / build.gradle.kts).

Extracts dependencies declared with standard Gradle configurations like
implementation, api, compileOnly, runtimeOnly, etc.

Handles both Groovy DSL and Kotlin DSL syntax:
  - implementation "group:artifact:version"
  - implementation("group:artifact:version")
  - api(project(":submodule"))          → skipped (internal)
"""

from __future__ import annotations

import re
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

# Gradle configuration names (not exhaustive, but covers the common ones)
_CONFIGS = (
    r"(?:implementation|api|compileOnly|compileOnlyApi|runtimeOnly|"
    r"annotationProcessor|kapt|ksp|"
    r"testImplementation|testCompileOnly|testRuntimeOnly|"
    r"androidTestImplementation|debugImplementation|releaseImplementation|"
    r"optional|provided|compile|runtime|testCompile|testRuntime|"
    r"\w+Implementation|\w+Api|\w+CompileOnly|\w+RuntimeOnly)"
)

# Match: configuration("group:artifact:version") or configuration "group:artifact:version"
# Captures group:artifact and optional :version
_DEP_RE = re.compile(
    rf"{_CONFIGS}"
    r"\s*\(?\s*"
    r"""["']"""                          # opening quote
    r"([A-Za-z0-9._-]+)"                # group
    r":"
    r"([A-Za-z0-9._-]+)"                # artifact
    r"(?::([A-Za-z0-9._+\-]+))?"        # optional version
    r"""["']"""                          # closing quote
)


class GradleBuildParser:
    detection_method = "gradle"
    file_patterns = ["**/build.gradle", "**/build.gradle.kts"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        seen: set[str] = set()
        deps: list[ScannedDependency] = []

        for m in _DEP_RE.finditer(content):
            group = m.group(1)
            artifact = m.group(2)
            version = m.group(3)  # may be None

            name = f"{group}:{artifact}"

            # Dedup
            if name in seen:
                continue
            seen.add(name)

            deps.append(
                ScannedDependency(
                    library_name=name,
                    library_repo_url=None,
                    constraint_expr=version,
                    resolved_version=version,
                    source_file=file_path.name,
                    detection_method=self.detection_method,
                )
            )

        return deps


register_parser(GradleBuildParser())
