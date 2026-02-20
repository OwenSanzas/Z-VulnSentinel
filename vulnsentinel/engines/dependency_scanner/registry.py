"""Parser registry — discover manifest files and match them to parsers."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency


@runtime_checkable
class ManifestParser(Protocol):
    """Interface that every manifest parser must satisfy."""

    detection_method: str
    file_patterns: list[str]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]: ...


PARSER_REGISTRY: dict[str, ManifestParser] = {}


def register_parser(parser: ManifestParser) -> None:
    """Register a parser instance by its detection_method."""
    PARSER_REGISTRY[parser.detection_method] = parser


def discover_manifests(repo_path: Path) -> list[tuple[ManifestParser, Path]]:
    """Walk the repo and match manifest files to registered parsers.

    Returns a list of (parser, matched_file) pairs.
    """
    matches: list[tuple[ManifestParser, Path]] = []
    for parser in PARSER_REGISTRY.values():
        for pattern in parser.file_patterns:
            for hit in sorted(repo_path.glob(pattern)):
                if hit.is_file():
                    matches.append((parser, hit))
    return matches
