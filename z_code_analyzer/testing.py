"""Test doubles for z_code_analyzer — use in E2E / integration tests.

Usage::

    from z_code_analyzer.testing import FakeCodeAnalyzer

    analyzer = FakeCodeAnalyzer()                    # random results
    analyzer = FakeCodeAnalyzer(reachable=True)      # always reachable
    analyzer = FakeCodeAnalyzer(reachable=False)     # always not reachable
"""

from __future__ import annotations

import random

from z_code_analyzer.api import (
    CodeAnalyzer,
    SeedTreeRequest,
    SeedTreeResult,
    SnapshotRequest,
    VulnImpactRequest,
    VulnImpactResult,
)
from z_code_analyzer.orchestrator import AnalysisOutput


class FakeCodeAnalyzer(CodeAnalyzer):
    """Drop-in replacement for CodeAnalyzer that returns fake results.

    Parameters
    ----------
    reachable:
        If ``True``, ``investigate_vuln`` always returns reachable.
        If ``False``, always not reachable.
        If ``None`` (default), randomly picks each call.
    """

    def __init__(self, *, reachable: bool | None = None) -> None:
        # Skip real __init__ — no snapshot_manager / graph_store needed.
        self._fixed_reachable = reachable
        self._calls: list[VulnImpactRequest] = []

    @property
    def calls(self) -> list[VulnImpactRequest]:
        """Requests received — useful for assertions in tests."""
        return self._calls

    async def analyze_snapshot(self, request: SnapshotRequest) -> AnalysisOutput:
        return AnalysisOutput(
            snapshot_id="fake-snapshot-id",
            repo_url=request.repo_url,
            version=request.version,
            backend="fake",
            function_count=0,
            edge_count=0,
            fuzzer_names=[],
            cached=True,
        )

    async def investigate_vuln(self, request: VulnImpactRequest) -> VulnImpactResult:
        self._calls.append(request)

        if self._fixed_reachable is not None:
            reachable = self._fixed_reachable
        else:
            reachable = random.choice([True, False])

        depth = random.randint(1, 10) if reachable else None
        strategy = random.choice(["fuzzer_reaches", "shortest_path"]) if reachable else "exhausted"
        return VulnImpactResult(
            is_reachable=reachable,
            searched_functions=request.affected_functions,
            client_snapshot_id="e2e-fake-client",
            library_snapshot_id="e2e-fake-library",
            depth=depth,
            strategy=strategy,
        )

    async def generate_seed_tree(self, request: SeedTreeRequest) -> SeedTreeResult:
        return SeedTreeResult(
            snapshot_id="fake-snapshot-id",
            trees=[],
            target_functions=request.target_functions,
        )
