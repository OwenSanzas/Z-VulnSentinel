"""Log storage abstract interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import IO


class LogStore(ABC):
    """Log storage abstraction. v1 uses local files, future: S3."""

    @abstractmethod
    def get_writer(self, snapshot_id: str, phase: str) -> IO:
        """Get a write handle for a phase log."""
        ...

    @abstractmethod
    def read_log(self, snapshot_id: str, phase: str) -> str:
        """Read log content for debugging."""
        ...

    @abstractmethod
    def delete_logs(self, snapshot_id: str) -> None:
        """Delete all logs for a snapshot (called during eviction)."""
        ...
