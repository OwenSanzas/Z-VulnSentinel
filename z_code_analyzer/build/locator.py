"""Locate oss-fuzz build.sh in a cloned fuzz tooling repository."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class BuildScriptLocator:
    """Find build.sh inside a cloned fuzz tooling repo (e.g. oss-fuzz)."""

    def locate(self, fuzz_tooling_path: str, project_name: str) -> str | None:
        """Search for build.sh in the fuzz tooling repo.

        Search order:
          1. projects/<project_name>/build.sh  (standard oss-fuzz layout)
          2. projects/<variant>/build.sh where variant matches project_name
             case-insensitively or with common suffixes stripped
          3. build.sh at repo root (single-project repos like AIXCC)

        Returns:
            Absolute path to build.sh, or None if not found.
        """
        root = Path(fuzz_tooling_path)
        name_lower = project_name.lower()

        # 1. Exact match: projects/<project_name>/build.sh
        exact = root / "projects" / project_name / "build.sh"
        if exact.is_file():
            logger.info("Found build.sh (exact match): %s", exact)
            return str(exact)

        # 2. Case-insensitive scan of projects/ directory
        projects_dir = root / "projects"
        if projects_dir.is_dir():
            for entry in sorted(projects_dir.iterdir()):
                if not entry.is_dir():
                    continue
                candidate = entry / "build.sh"
                if not candidate.is_file():
                    continue
                if entry.name.lower() == name_lower:
                    logger.info("Found build.sh (case-insensitive): %s", candidate)
                    return str(candidate)

        # 3. Repo-root build.sh (single-project repos, AIXCC style)
        root_build = root / "build.sh"
        if root_build.is_file():
            logger.info("Found build.sh (repo root): %s", root_build)
            return str(root_build)

        logger.warning(
            "No build.sh found for project '%s' in %s", project_name, fuzz_tooling_path
        )
        return None
