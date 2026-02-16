"""Tests for ProgressTracker."""

from __future__ import annotations

import time

from z_code_analyzer.progress import ProgressTracker


class TestProgressTracker:
    def test_basic_flow(self):
        tracker = ProgressTracker()
        tracker.start_phase("probe")
        tracker.complete_phase("probe", detail="found 100 files")

        summary = tracker.get_summary()
        assert len(summary["phases"]) == 1
        assert summary["phases"][0]["status"] == "completed"
        assert summary["phases"][0]["detail"] == "found 100 files"

    def test_fail_phase(self):
        tracker = ProgressTracker()
        tracker.start_phase("build")
        tracker.fail_phase("build", "compile error")

        summary = tracker.get_summary()
        assert summary["phases"][0]["status"] == "failed"
        assert summary["phases"][0]["error"] == "compile error"

    def test_skip_phase(self):
        tracker = ProgressTracker()
        tracker.skip_phase("ai_refine", "v1: not implemented")

        summary = tracker.get_summary()
        assert summary["phases"][0]["status"] == "skipped"

    def test_duration(self):
        tracker = ProgressTracker()
        tracker.start_phase("test")
        time.sleep(0.01)
        tracker.complete_phase("test")

        p = tracker.phases[0]
        assert p.duration is not None
        assert p.duration >= 0.01

    def test_callback(self):
        events = []
        tracker = ProgressTracker()
        tracker.callbacks.append(lambda p: events.append(p.phase))

        tracker.start_phase("a")
        tracker.complete_phase("a")

        assert events == ["a", "a"]

    def test_multiple_phases(self):
        tracker = ProgressTracker()
        tracker.start_phase("phase1")
        tracker.complete_phase("phase1")
        tracker.start_phase("phase2")
        tracker.complete_phase("phase2")

        summary = tracker.get_summary()
        assert len(summary["phases"]) == 2
        assert summary["total_duration"] >= 0
