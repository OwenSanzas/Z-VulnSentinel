"""Local file log storage implementation."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import IO

from z_code_analyzer.logging.base import LogStore


class LocalLogStore(LogStore):
    """Local file log storage (v1 default)."""

    def __init__(self, base_dir: str = "logs/snapshots") -> None:
        self.base_dir = Path(base_dir)

    def get_writer(self, snapshot_id: str, phase: str) -> IO:
        log_dir = self.base_dir / snapshot_id
        log_dir.mkdir(parents=True, exist_ok=True)
        return open(log_dir / f"{phase}.log", "a")

    def read_log(self, snapshot_id: str, phase: str) -> str:
        log_file = self.base_dir / snapshot_id / f"{phase}.log"
        if log_file.exists():
            return log_file.read_text()
        return ""

    def delete_logs(self, snapshot_id: str) -> None:
        log_dir = self.base_dir / snapshot_id
        if log_dir.exists():
            shutil.rmtree(log_dir)
