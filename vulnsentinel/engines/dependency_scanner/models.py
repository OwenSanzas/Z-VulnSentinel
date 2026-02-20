"""Data models for the dependency scanner engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScannedDependency:
    """A single dependency detected from a manifest file."""

    library_name: str
    library_repo_url: str | None
    constraint_expr: str | None
    resolved_version: str | None
    source_file: str
    detection_method: str


@dataclass
class ScanResult:
    """Result of a full scan + sync pipeline run."""

    scanned: list[ScannedDependency]
    synced_count: int
    deleted_count: int
    unresolved: list[ScannedDependency] = field(default_factory=list)
    skipped: bool = False
