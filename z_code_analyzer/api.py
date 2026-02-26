"""Unified CodeAnalyzer facade — single entry point for all analysis scenarios.

Scenarios:
    1. Single snapshot analysis (no fuzzers)
    2. Snapshot analysis with fuzzer sources
    3. Vulnerability impact investigation (ensure two snapshots + reachability)
    4. Seed tree generation (interface only, not yet implemented)
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.logging.base import LogStore
from z_code_analyzer.orchestrator import AnalysisOutput, StaticAnalysisOrchestrator
from z_code_analyzer.reachability import ReachabilityChecker, ReachabilityResult
from z_code_analyzer.snapshot_manager import SnapshotManager

logger = logging.getLogger(__name__)


# ── Request / Response dataclasses ────────────────────────────────────────


@dataclass
class SnapshotRequest:
    """Input for scenarios 1 (no fuzzers) and 2 (with fuzzers)."""

    repo_url: str
    version: str
    project_path: str | None = None
    fuzzer_sources: dict[str, list[str]] = field(default_factory=dict)
    build_script: str | None = None
    language: str | None = None
    backend: str | None = None
    diff_files: list[str] | None = None
    svf_case_config: str | None = None
    svf_docker_image: str | None = None
    fuzz_tooling_url: str | None = None
    fuzz_tooling_ref: str | None = None


@dataclass
class VulnImpactRequest:
    """Input for scenario 3: vulnerability impact investigation."""

    client_repo_url: str
    client_version: str
    library_repo_url: str
    library_version: str
    affected_functions: list[str]
    commit_sha: str | None = None
    client_project_path: str | None = None
    library_project_path: str | None = None


@dataclass
class VulnImpactResult:
    """Output for scenario 3."""

    is_reachable: bool
    searched_functions: list[str]
    client_snapshot_id: str | None = None
    library_snapshot_id: str | None = None
    depth: int | None = None
    paths: list[dict] | None = None
    strategy: str = ""
    error: str | None = None


@dataclass
class SeedTreeRequest:
    """Input for scenario 4: seed tree generation (not yet implemented)."""

    repo_url: str
    version: str
    target_functions: list[str]
    max_depth: int = 10


@dataclass
class SeedTreeResult:
    """Output for scenario 4."""

    snapshot_id: str
    trees: list[dict]
    target_functions: list[str]


# ── CodeAnalyzer facade ──────────────────────────────────────────────────


class CodeAnalyzer:
    """Unified facade coordinating orchestrator + snapshot_manager + graph_store.

    Usage::

        analyzer = CodeAnalyzer(snapshot_manager, graph_store)

        # Scenario 1/2: build a snapshot
        output = await analyzer.analyze_snapshot(SnapshotRequest(...))

        # Scenario 3: investigate vulnerability impact
        result = await analyzer.investigate_vuln(VulnImpactRequest(...))
    """

    def __init__(
        self,
        snapshot_manager: SnapshotManager,
        graph_store: GraphStore,
        log_store: LogStore | None = None,
        workspace_dir: str | None = None,
    ) -> None:
        self._sm = snapshot_manager
        self._gs = graph_store
        self._log_store = log_store
        self._workspace_dir = workspace_dir
        self._orchestrator = StaticAnalysisOrchestrator(
            snapshot_manager=snapshot_manager,
            graph_store=graph_store,
            log_store=log_store,
        )
        self._checker = ReachabilityChecker(
            graph_store=graph_store,
            snapshot_manager=snapshot_manager,
        )

    # ── Scenario 1 & 2: snapshot analysis ────────────────────────────────

    async def analyze_snapshot(self, request: SnapshotRequest) -> AnalysisOutput:
        """Build (or retrieve cached) a call-graph snapshot.

        If ``request.project_path`` is None, the repository is auto-cloned
        to a temporary directory.
        """
        project_path = request.project_path
        cloned_dir: str | None = None

        if not project_path or not Path(project_path).is_dir():
            project_path = _auto_clone(
                request.repo_url, request.version, self._workspace_dir
            )
            cloned_dir = project_path

        try:
            return await self._orchestrator.analyze(
                project_path=project_path,
                repo_url=request.repo_url,
                version=request.version,
                fuzzer_sources=request.fuzzer_sources,
                build_script=request.build_script,
                language=request.language,
                backend=request.backend,
                diff_files=request.diff_files,
                svf_case_config=request.svf_case_config,
                svf_docker_image=request.svf_docker_image,
                fuzz_tooling_url=request.fuzz_tooling_url,
                fuzz_tooling_ref=request.fuzz_tooling_ref,
            )
        finally:
            if cloned_dir:
                shutil.rmtree(cloned_dir, ignore_errors=True)

    # ── Scenario 3: vulnerability impact investigation ───────────────────

    async def investigate_vuln(self, request: VulnImpactRequest) -> VulnImpactResult:
        """Ensure both snapshots exist, then check reachability.

        Steps:
            1. ``_ensure_snapshot()`` for the client repo.
            2. ``_ensure_snapshot()`` for the library repo.
            3. ``ReachabilityChecker.check()`` — both snapshots now exist.

        """
        if not request.affected_functions:
            return VulnImpactResult(
                is_reachable=False,
                searched_functions=[],
                error="no_affected_functions",
            )

        # 1. Ensure client snapshot
        client_sid, client_err = await self._ensure_snapshot(
            request.client_repo_url,
            request.client_version,
            project_path=request.client_project_path,
        )
        if client_err:
            return VulnImpactResult(
                is_reachable=False,
                searched_functions=request.affected_functions,
                error=f"client_snapshot_build_failed: {client_err}",
            )

        # 2. Ensure library snapshot
        library_sid, library_err = await self._ensure_snapshot(
            request.library_repo_url,
            request.library_version,
            project_path=request.library_project_path,
        )
        if library_err:
            return VulnImpactResult(
                is_reachable=False,
                searched_functions=request.affected_functions,
                client_snapshot_id=client_sid,
                error=f"library_snapshot_build_failed: {library_err}",
            )

        # 3. Run reachability check — snapshots are guaranteed to exist
        vuln_dict = {
            "affected_functions": request.affected_functions,
            "commit_sha": request.commit_sha,
        }
        rr: ReachabilityResult = await self._checker.check(
            client_repo_url=request.client_repo_url,
            client_version=request.client_version,
            library_repo_url=request.library_repo_url,
            library_version=request.library_version,
            vuln=vuln_dict,
        )
        return VulnImpactResult(
            is_reachable=rr.is_reachable,
            searched_functions=rr.searched_functions,
            client_snapshot_id=rr.client_snapshot_id,
            library_snapshot_id=rr.library_snapshot_id,
            depth=rr.depth,
            paths=rr.paths,
            strategy=rr.strategy,
            error=rr.error,
        )

    # ── Scenario 4: seed tree generation (stub) ──────────────────────────

    async def generate_seed_tree(self, request: SeedTreeRequest) -> SeedTreeResult:
        """Generate seed trees for target functions.

        .. warning:: Not yet implemented.
        """
        raise NotImplementedError("generate_seed_tree is not yet implemented")

    # ── Internal: find-or-build snapshot ──────────────────────────────────

    async def _ensure_snapshot(
        self,
        repo_url: str,
        version: str,
        project_path: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Find an existing snapshot or build one.

        Returns ``(snapshot_id, None)`` on success,
        or ``(None, error_message)`` on failure.
        """
        # Fast path: snapshot already exists
        snap = await asyncio.to_thread(self._sm.find_snapshot, repo_url, version)
        if snap is not None:
            logger.info("Snapshot cache hit: %s@%s → %s", repo_url, version, snap.id)
            return str(snap.id), None

        # Slow path: build the snapshot
        logger.info("Snapshot cache miss: %s@%s — building", repo_url, version)
        try:
            output = await self.analyze_snapshot(
                SnapshotRequest(
                    repo_url=repo_url,
                    version=version,
                    project_path=project_path,
                    fuzzer_sources={},
                )
            )
            return output.snapshot_id, None
        except Exception as exc:
            logger.warning(
                "Failed to build snapshot for %s@%s: %s",
                repo_url,
                version,
                exc,
                exc_info=True,
            )
            return None, str(exc)


# ── Utility: auto-clone ──────────────────────────────────────────────────


def _auto_clone(
    repo_url: str, version: str, workspace_dir: str | None = None
) -> str:
    """Clone a repo and checkout the given version.

    Raises ``RuntimeError`` on failure (unlike the CLI version which returns None).
    """
    base = Path(workspace_dir) if workspace_dir else Path.cwd() / "workspace"
    base.mkdir(parents=True, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix="clone-", dir=base)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", version, repo_url, tmpdir],
            check=True,
            capture_output=True,
            text=True,
        )
        return tmpdir
    except subprocess.CalledProcessError:
        # --branch may fail for commit hashes; try full clone + checkout
        shutil.rmtree(tmpdir, ignore_errors=True)
        os.makedirs(tmpdir, exist_ok=True)
        try:
            subprocess.run(
                ["git", "clone", repo_url, tmpdir],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "checkout", version],
                check=True,
                capture_output=True,
                text=True,
            )
            return tmpdir
        except subprocess.CalledProcessError as e:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise RuntimeError(
                f"Git clone/checkout failed for {repo_url}@{version}: {e.stderr}"
            ) from e
