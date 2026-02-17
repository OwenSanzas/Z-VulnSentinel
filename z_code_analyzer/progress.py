"""Progress tracking for the analysis pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class PhaseProgress:
    phase: str
    status: str = "pending"  # "pending" | "running" | "completed" | "failed" | "skipped"
    start_time: float | None = None
    end_time: float | None = None
    detail: str = ""
    error: str | None = None

    @property
    def duration(self) -> float | None:
        if self.start_time and self.end_time:
            return round(self.end_time - self.start_time, 2)
        return None


class ProgressTracker:
    """Track progress of analysis pipeline phases."""

    def __init__(self) -> None:
        self.phases: list[PhaseProgress] = []
        self._by_name: dict[str, PhaseProgress] = {}
        self.callbacks: list[Callable[[PhaseProgress], None]] = []

    def start_phase(self, phase: str) -> None:
        p = PhaseProgress(phase=phase, status="running", start_time=time.monotonic())
        self.phases.append(p)
        self._by_name[phase] = p
        self._notify(p)

    def complete_phase(self, phase: str, detail: str = "") -> None:
        p = self._by_name.get(phase)
        if p:
            p.status = "completed"
            p.end_time = time.monotonic()
            p.detail = detail
            self._notify(p)

    def fail_phase(self, phase: str, error: str) -> None:
        p = self._by_name.get(phase)
        if p:
            p.status = "failed"
            p.end_time = time.monotonic()
            p.error = error
            self._notify(p)

    def skip_phase(self, phase: str, reason: str) -> None:
        p = PhaseProgress(phase=phase, status="skipped", detail=reason)
        self.phases.append(p)
        self._by_name[phase] = p
        self._notify(p)

    def get_summary(self) -> dict[str, Any]:
        total_duration = sum(p.duration or 0 for p in self.phases)
        return {
            "phases": [
                {
                    "phase": p.phase,
                    "status": p.status,
                    "duration": p.duration,
                    "detail": p.detail,
                    "error": p.error,
                }
                for p in self.phases
            ],
            "total_duration": round(total_duration, 2),
        }

    def _notify(self, p: PhaseProgress) -> None:
        for cb in self.callbacks:
            try:
                cb(p)
            except Exception:
                logger.debug("Progress callback error for phase %s", p.phase, exc_info=True)
