"""Parser for CMake find_package() calls — best-effort, not a proper manifest.

Extracts dependency names from find_package() in CMakeLists.txt.
Precision ~70-80%: may include build tools (Perl, Threads, PkgConfig)
and mutually exclusive options. Results should be treated as hints
requiring human review.
"""

from __future__ import annotations

import re
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

# Matches: find_package(Name ...) — capture the first argument (package name)
_FIND_PKG_RE = re.compile(r"find_package\s*\(\s*([A-Za-z0-9_][A-Za-z0-9_+-]*)", re.IGNORECASE)

# CMake built-in / tool modules that are not real library dependencies
_SKIP_PACKAGES = frozenset({
    "perl",
    "python",
    "python2",
    "python3",
    "threads",
    "pkgconfig",
    "pkg-config",
    "git",
    "doxygen",
    "latex",
    "java",
    "jni",
    "swig",
    "bison",
    "flex",
    "gperf",
    "gettext",
    "intl",
    "patch",
    "backtrace",
})


class CMakeFindPackageParser:
    detection_method = "cmake-find-package"
    file_patterns = ["CMakeLists.txt"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        seen: set[str] = set()
        deps: list[ScannedDependency] = []

        for m in _FIND_PKG_RE.finditer(content):
            name = m.group(1)

            # Skip known non-library packages
            if name.lower() in _SKIP_PACKAGES:
                continue

            # Dedup (same package may appear multiple times with different COMPONENTS)
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)

            deps.append(
                ScannedDependency(
                    library_name=name,
                    library_repo_url=None,
                    constraint_expr=None,
                    resolved_version=None,
                    source_file=file_path.name,
                    detection_method=self.detection_method,
                )
            )

        return deps


register_parser(CMakeFindPackageParser())
