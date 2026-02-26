"""Reachability facade — high-level interface for VulnSentinel."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import structlog

from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.snapshot_manager import SnapshotManager

log = structlog.get_logger("z_code_analyzer.reachability")


@dataclass
class ReachabilityResult:
    """Outcome of a reachability check."""

    is_reachable: bool
    searched_functions: list[str]
    snapshot_id: str | None = None
    depth: int | None = None
    paths: list[dict] | None = None
    strategy: str = ""
    error: str | None = None


def _error_result(
    error: str, searched: list[str] | None = None
) -> ReachabilityResult:
    return ReachabilityResult(
        is_reachable=False,
        searched_functions=searched or [],
        error=error,
    )


def _extract_target_functions(vuln: dict) -> list[str]:
    """Extract target function names from vuln dict."""
    funcs = vuln.get("affected_functions")
    if not funcs or not isinstance(funcs, list):
        return []
    return [f for f in funcs if isinstance(f, str) and f.strip()]


class ReachabilityChecker:
    """Facade — wraps GraphStore + SnapshotManager for VulnSentinel.

    Callers only need::

        result = await checker.check(repo_url, version, vuln_dict)

    Internal details of zca (Neo4j, snapshot lookup, fuzzer edges) are hidden.
    """

    def __init__(
        self,
        graph_store: GraphStore,
        snapshot_manager: SnapshotManager,
    ) -> None:
        self._gs = graph_store
        self._sm = snapshot_manager

    async def check(
        self,
        repo_url: str,
        version: str,
        vuln: dict,
    ) -> ReachabilityResult:
        """Check whether *vuln*'s affected functions are reachable in the call graph.

        Parameters
        ----------
        repo_url:
            Repository URL of the client project (must match a snapshot).
        version:
            Version / tag / commit of the client project.
        vuln:
            Dict with at least ``affected_functions: list[str]``.

        Returns
        -------
        ReachabilityResult
        """
        # 1. Find snapshot
        snapshot = await asyncio.to_thread(
            self._sm.find_snapshot, repo_url, version
        )
        if snapshot is None:
            return _error_result("snapshot_not_found")

        sid = str(snapshot.id)

        # 2. Extract target functions
        targets = _extract_target_functions(vuln)
        if not targets:
            return _error_result("no_affected_functions")

        # 3. Try fuzzer reachability first
        result = await self._check_fuzzer_reaches(sid, targets)
        if result is not None:
            return result

        # 4. Fallback to shortest_path from "main"
        result = await self._check_shortest_path(sid, targets)
        if result is not None:
            return result

        # 5. Not reachable
        return ReachabilityResult(
            is_reachable=False,
            searched_functions=targets,
            snapshot_id=sid,
            strategy="exhausted",
        )

    async def _check_fuzzer_reaches(
        self, snapshot_id: str, targets: list[str]
    ) -> ReachabilityResult | None:
        """Check if any fuzzer can reach any target function."""
        try:
            fuzzers = await asyncio.to_thread(
                self._gs.list_fuzzer_info_no_code, snapshot_id
            )
        except Exception:
            log.debug("reachability.fuzzer_list_failed", exc_info=True)
            return None

        if not fuzzers:
            return None

        for fuzzer in fuzzers:
            fuzzer_name = fuzzer.get("name", "")
            if not fuzzer_name:
                continue

            try:
                reachable = await asyncio.to_thread(
                    self._gs.reachable_functions_by_one_fuzzer,
                    snapshot_id,
                    fuzzer_name,
                )
            except Exception:
                log.debug(
                    "reachability.fuzzer_reach_failed",
                    fuzzer=fuzzer_name,
                    exc_info=True,
                )
                continue

            reachable_names = {r.get("name", "") for r in reachable}
            for target in targets:
                if target in reachable_names:
                    matched = next(
                        (r for r in reachable if r.get("name") == target),
                        {},
                    )
                    return ReachabilityResult(
                        is_reachable=True,
                        searched_functions=targets,
                        snapshot_id=snapshot_id,
                        depth=matched.get("depth"),
                        strategy="fuzzer_reaches",
                    )

        return None

    async def _check_shortest_path(
        self, snapshot_id: str, targets: list[str]
    ) -> ReachabilityResult | None:
        """Check reachability from 'main' to each target via shortest_path."""
        for target in targets:
            try:
                result = await asyncio.to_thread(
                    self._gs.shortest_path,
                    snapshot_id,
                    "main",
                    target,
                )
            except Exception:
                log.debug(
                    "reachability.shortest_path_failed",
                    target=target,
                    exc_info=True,
                )
                continue

            if result is not None and result.get("paths_found", 0) > 0:
                return ReachabilityResult(
                    is_reachable=True,
                    searched_functions=targets,
                    snapshot_id=snapshot_id,
                    depth=result.get("length"),
                    paths=result.get("paths"),
                    strategy="shortest_path",
                )

        return None
