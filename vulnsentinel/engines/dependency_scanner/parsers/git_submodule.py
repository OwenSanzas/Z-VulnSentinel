"""Parser for .gitmodules files."""

from __future__ import annotations

import configparser
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser


def _name_from_url(url: str) -> str:
    """Extract library name from a git URL.

    Examples:
        https://github.com/org/repo.git  -> repo
        git@github.com:org/repo          -> repo
    """
    last = url.rstrip("/").rsplit("/", 1)[-1]
    if last.endswith(".git"):
        last = last[:-4]
    return last


class GitSubmoduleParser:
    detection_method = "git-submodule"
    file_patterns = [".gitmodules"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        cfg = configparser.ConfigParser()
        cfg.read_string(content)

        deps: list[ScannedDependency] = []
        for section in cfg.sections():
            url = cfg.get(section, "url", fallback=None)
            if not url:
                continue

            deps.append(
                ScannedDependency(
                    library_name=_name_from_url(url),
                    library_repo_url=url,
                    constraint_expr=None,
                    resolved_version=None,
                    source_file=file_path.name,
                    detection_method=self.detection_method,
                )
            )

        return deps


register_parser(GitSubmoduleParser())
