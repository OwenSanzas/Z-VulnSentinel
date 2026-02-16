"""Snapshot data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SnapshotInfo:
    """Snapshot metadata (mirrors MongoDB document structure)."""

    snapshot_id: str
    repo_url: str
    repo_name: str
    version: str
    backend: str
    status: str  # "building" | "completed" | "failed"
    created_at: datetime | None = None
    last_accessed_at: datetime | None = None
    access_count: int = 0
    node_count: int = 0
    edge_count: int = 0
    fuzzer_names: list[str] = field(default_factory=list)
    analysis_duration_sec: float = 0.0
    language: str = ""
    size_bytes: int = 0
    error: str | None = None
