"""Static analysis orchestrator — 6-phase pipeline."""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass, field
from typing import Any

from z_code_analyzer.backends.base import FuzzerInfo
from z_code_analyzer.build.bitcode import BitcodeGenerator
from z_code_analyzer.build.detector import BuildCommandDetector
from z_code_analyzer.build.fuzzer_parser import FuzzerEntryParser
from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.logging.base import LogStore
from z_code_analyzer.probe import ProjectProbe
from z_code_analyzer.progress import PhaseProgress, ProgressTracker
from z_code_analyzer.snapshot_manager import SnapshotManager

logger = logging.getLogger(__name__)


@dataclass
class AnalysisOutput:
    """Orchestrator return value."""

    snapshot_id: str
    repo_url: str
    version: str
    backend: str
    function_count: int
    edge_count: int
    fuzzer_names: list[str]
    cached: bool


class StaticAnalysisOrchestrator:
    """
    Orchestrate the 6-phase static analysis pipeline.

    Phase 1: ProjectProbe.probe()
    Phase 2: BuildCommandDetector.detect()
    Phase 3: BitcodeGenerator.generate() (library-only)
    Phase 4a: SVFBackend.analyze()
    Phase 4b: FuzzerEntryParser.parse()
    Phase 5: (skip, AI reserved)
    Phase 6: GraphStore import + REACHES computation
    """

    def __init__(
        self,
        snapshot_manager: SnapshotManager,
        graph_store: GraphStore,
        log_store: LogStore | None = None,
    ) -> None:
        self.snapshot_manager = snapshot_manager
        self.graph_store = graph_store
        self.log_store = log_store
        self.progress = ProgressTracker()
        self._snapshot_id_for_log: str | None = None
        if log_store:
            self.progress.callbacks.append(self._log_phase_callback)

    def _log_phase_callback(self, phase: PhaseProgress) -> None:
        """Write phase status transitions to LogStore."""
        if not self.log_store or not self._snapshot_id_for_log:
            return
        try:
            writer = self.log_store.get_writer(self._snapshot_id_for_log, phase.phase)
            duration_str = f" ({phase.duration}s)" if phase.duration is not None else ""
            detail_str = f" — {phase.detail}" if phase.detail else ""
            error_str = f" ERROR: {phase.error}" if phase.error else ""
            writer.write(f"[{phase.status}]{duration_str}{detail_str}{error_str}\n")
            writer.close()
        except Exception:
            logger.debug("Failed to write phase log for %s", phase.phase, exc_info=True)

    async def analyze(
        self,
        project_path: str,
        repo_url: str,
        version: str,
        fuzzer_sources: dict[str, list[str]],
        build_script: str | None = None,
        language: str | None = None,
        backend: str | None = None,
        diff_files: list[str] | None = None,
    ) -> AnalysisOutput:
        """Full analysis pipeline entry point."""
        snapshot_id: str | None = None
        analysis_committed = False

        # v1: only SVF backend is supported
        if backend and backend not in ("svf", "auto"):
            logger.warning(
                "Backend '%s' not supported in v1, falling back to 'svf'", backend
            )
        actual_backend = "svf"

        # Check snapshot cache
        snapshot_doc = await self.snapshot_manager.acquire_or_wait(
            repo_url, version, actual_backend
        )

        if snapshot_doc and snapshot_doc["status"] == "completed":
            return AnalysisOutput(
                snapshot_id=str(snapshot_doc["_id"]),
                repo_url=repo_url,
                version=version,
                backend=snapshot_doc.get("backend", "svf"),
                function_count=snapshot_doc.get("node_count", 0),
                edge_count=snapshot_doc.get("edge_count", 0),
                fuzzer_names=snapshot_doc.get("fuzzer_names", []),
                cached=True,
            )

        if not snapshot_doc:
            raise RuntimeError(
                "Failed to acquire snapshot lock — another worker may be processing "
                f"({repo_url}@{version})"
            )
        snapshot_id = str(snapshot_doc["_id"])
        self._snapshot_id_for_log = snapshot_id

        try:
            # Phase 1: Project probe
            self.progress.start_phase("probe")
            info = ProjectProbe().probe(project_path, diff_files=diff_files)
            detected_lang = language or info.language_profile.primary_language
            self.progress.complete_phase(
                "probe",
                detail=f"lang={detected_lang}, build={info.build_system}, "
                f"files={len(info.source_files)}",
            )

            # Phase 2: Build command detection
            self.progress.start_phase("build_cmd")
            build_cmd = BuildCommandDetector().detect(project_path, build_script=build_script)
            if build_cmd:
                self.progress.complete_phase(
                    "build_cmd",
                    detail=f"{build_cmd.build_system} (source: {build_cmd.source})",
                )
            else:
                self.progress.fail_phase("build_cmd", "No build system detected")
                raise RuntimeError("No build system detected and no build_script provided")

            # Phase 3: Bitcode generation (in Docker via svf-pipeline.sh)
            self.progress.start_phase("bitcode")
            all_fuzzer_files = [f for files in fuzzer_sources.values() for f in files]
            bitcode_gen = BitcodeGenerator()
            output_dir = tempfile.mkdtemp(prefix="z-analyze-")

            # Determine case config from build system
            case_config = self._resolve_case_config(
                build_cmd.build_system, project_path
            )

            if case_config:
                # Full Docker pipeline: build + extract bitcode
                bc_output = bitcode_gen.generate_via_docker(
                    project_path=project_path,
                    case_config=case_config,
                    fuzzer_source_files=all_fuzzer_files,
                    output_dir=output_dir,
                )
            else:
                # No case config — try to use pre-existing bitcode
                bc_output = bitcode_gen.generate(
                    project_path=project_path,
                    build_cmd=build_cmd,
                    fuzzer_source_files=all_fuzzer_files,
                    output_dir=output_dir,
                )
            self.progress.complete_phase(
                "bitcode",
                detail=f"bc={bc_output.bc_path}, metas={len(bc_output.function_metas)}, "
                f"excluded={len(all_fuzzer_files)}",
            )

            # Phase 4a: SVF analysis
            self.progress.start_phase("svf")
            from z_code_analyzer.backends.svf_backend import SVFBackend

            svf = SVFBackend()
            function_metas_dicts = [
                {
                    "ir_name": m.ir_name,
                    "original_name": m.original_name,
                    "file_path": m.file_path,
                    "line": m.line,
                    "end_line": m.end_line,
                    "content": m.content,
                }
                for m in bc_output.function_metas
            ]
            result = svf.analyze(
                project_path,
                detected_lang,
                bc_path=bc_output.bc_path,
                function_metas=function_metas_dicts,
            )
            self.progress.complete_phase(
                "svf",
                detail=f"functions={len(result.functions)}, edges={len(result.edges)}, "
                f"fptr={result.metadata.get('fptr_edge_count', 0)}",
            )

            # Phase 4b: Fuzzer entry parsing
            self.progress.start_phase("fuzzer_parse")
            library_func_names = {f.name for f in result.functions}
            fuzzer_calls = FuzzerEntryParser().parse(
                fuzzer_sources, library_func_names, project_path
            )
            self.progress.complete_phase(
                "fuzzer_parse",
                detail=f"{len(fuzzer_sources)} fuzzers, "
                f"lib_calls={sum(len(v) for v in fuzzer_calls.values())}",
            )

            # Phase 5: AI refinement (skipped in v1)
            self.progress.skip_phase("ai_refine", "v1: not implemented")

            # Phase 6: Neo4j import + REACHES computation
            self.progress.start_phase("import")
            self.graph_store.create_snapshot_node(
                snapshot_id, repo_url, version, result.backend
            )
            func_count = self.graph_store.import_functions(
                snapshot_id, result.functions
            )
            edge_count = self.graph_store.import_edges(snapshot_id, result.edges)

            fuzzer_infos = self._assemble_fuzzer_infos(fuzzer_sources, fuzzer_calls)
            self.graph_store.import_fuzzers(snapshot_id, fuzzer_infos)

            reaches = self._compute_reaches(snapshot_id, fuzzer_infos)
            self.graph_store.import_reaches(snapshot_id, reaches)

            fuzzer_names = [f.name for f in fuzzer_infos]
            self.snapshot_manager.mark_completed(
                snapshot_id,
                func_count,
                edge_count,
                fuzzer_names,
                analysis_duration_sec=result.analysis_duration_seconds,
                language=detected_lang,
            )
            analysis_committed = True
            self.progress.complete_phase(
                "import",
                detail=f"functions={func_count}, edges={edge_count}, "
                f"reaches={len(reaches)}, fuzzers={len(fuzzer_names)}",
            )

            # Eviction runs after mark_completed — failures must not affect the result
            try:
                self._run_eviction(repo_url)
            except Exception:
                logger.warning("Eviction failed (non-fatal)", exc_info=True)

            return AnalysisOutput(
                snapshot_id=snapshot_id,
                repo_url=repo_url,
                version=version,
                backend=result.backend,
                function_count=func_count,
                edge_count=edge_count,
                fuzzer_names=fuzzer_names,
                cached=False,
            )

        except Exception as e:
            if snapshot_id and not analysis_committed:
                self.snapshot_manager.mark_failed(snapshot_id, str(e))
                try:
                    self.graph_store.delete_snapshot(snapshot_id)
                except Exception:
                    logger.warning("Failed to clean up partial Neo4j data for %s", snapshot_id, exc_info=True)
            raise

    def analyze_full(
        self,
        project_path: str,
        repo_url: str,
        version: str,
        fuzzer_sources: dict[str, list[str]],
        result: Any,
        snapshot_id: str,
    ) -> AnalysisOutput:
        """
        Run Phase 4b + Phase 6 with an already-computed AnalysisResult.
        Used when SVF has already been run externally.
        """
        self._snapshot_id_for_log = snapshot_id
        analysis_committed = False
        try:
            # Phase 4b: Fuzzer entry parsing
            library_func_names = {f.name for f in result.functions}
            fuzzer_calls = FuzzerEntryParser().parse(
                fuzzer_sources, library_func_names, project_path
            )

            # Phase 6: Neo4j import
            self.graph_store.create_snapshot_node(snapshot_id, repo_url, version, result.backend)
            func_count = self.graph_store.import_functions(snapshot_id, result.functions)
            edge_count = self.graph_store.import_edges(snapshot_id, result.edges)

            fuzzer_infos = self._assemble_fuzzer_infos(fuzzer_sources, fuzzer_calls)
            self.graph_store.import_fuzzers(snapshot_id, fuzzer_infos)

            reaches = self._compute_reaches(snapshot_id, fuzzer_infos)
            self.graph_store.import_reaches(snapshot_id, reaches)

            fuzzer_names = [f.name for f in fuzzer_infos]
            self.snapshot_manager.mark_completed(
                snapshot_id,
                func_count,
                edge_count,
                fuzzer_names,
                analysis_duration_sec=result.analysis_duration_seconds,
                language=result.language,
            )
            analysis_committed = True

            # Eviction runs after mark_completed — failures must not affect the result
            try:
                self._run_eviction(repo_url)
            except Exception:
                logger.warning("Eviction failed (non-fatal)", exc_info=True)

            return AnalysisOutput(
                snapshot_id=snapshot_id,
                repo_url=repo_url,
                version=version,
                backend=result.backend,
                function_count=func_count,
                edge_count=edge_count,
                fuzzer_names=fuzzer_names,
                cached=False,
            )

        except Exception as e:
            if not analysis_committed:
                self.snapshot_manager.mark_failed(snapshot_id, str(e))
                try:
                    self.graph_store.delete_snapshot(snapshot_id)
                except Exception:
                    logger.warning("Failed to clean up partial Neo4j data for %s", snapshot_id, exc_info=True)
            raise

    @staticmethod
    def _resolve_case_config(build_system: str, project_path: str) -> str | None:
        """Find a matching SVF case config for the project, or None."""
        from pathlib import Path

        cases_dir = Path(__file__).parent / "svf" / "cases"
        if not cases_dir.is_dir():
            return None

        # Try project name match first
        project_name = Path(project_path).name.lower()
        for case_file in cases_dir.glob("*.sh"):
            if case_file.stem.lower() == project_name:
                return str(case_file)

        return None

    @staticmethod
    def _assemble_fuzzer_infos(
        fuzzer_sources: dict[str, list[str]],
        fuzzer_calls: dict[str, list[str]],
    ) -> list[FuzzerInfo]:
        """Merge work order fuzzer_sources with FuzzerEntryParser results."""
        infos = []
        for fuzzer_name, source_files in fuzzer_sources.items():
            infos.append(
                FuzzerInfo(
                    name=fuzzer_name,
                    entry_function="LLVMFuzzerTestOneInput",
                    files=[{"path": f, "source": "user"} for f in source_files],
                    called_library_functions=fuzzer_calls.get(fuzzer_name, []),
                )
            )
        return infos

    def _run_eviction(self, repo_url: str) -> None:
        """Run eviction strategies in priority order (doc §1.7.4)."""
        # 1. Disk pressure (highest priority)
        evicted = self.snapshot_manager.evict_by_disk_pressure()
        if evicted:
            logger.info("Evicted %d snapshot(s) due to disk pressure", evicted)

        # 2. Version limit per repo
        evicted = self.snapshot_manager.evict_by_version_limit(repo_url)
        if evicted:
            logger.info("Evicted %d old snapshot(s) for %s", evicted, repo_url)

        # 3. TTL expiry
        evicted = self.snapshot_manager.evict_by_ttl()
        if evicted:
            logger.info("Evicted %d expired snapshot(s)", evicted)

    def _compute_reaches(
        self,
        snapshot_id: str,
        fuzzer_infos: list[FuzzerInfo],
    ) -> list[dict]:
        """BFS from each fuzzer's entry to compute REACHES edges + depth."""
        reaches = []
        max_reach_depth = 50  # upper bound to prevent Neo4j memory exhaustion
        for fuzzer in fuzzer_infos:
            main_file = fuzzer.files[0]["path"] if fuzzer.files else None
            # Neo4j null != "" — use different queries depending on whether file_path is known
            if main_file:
                entry_match = (
                    f'MATCH path = (entry:Function {{snapshot_id: $sid, '
                    f'name: "LLVMFuzzerTestOneInput", file_path: $fpath}})'
                )
            else:
                entry_match = (
                    f'MATCH path = (entry:Function {{snapshot_id: $sid, '
                    f'name: "LLVMFuzzerTestOneInput"}})'
                )
            bfs_result = self.graph_store.raw_query(
                f"""
                {entry_match}
                             -[:CALLS*1..{max_reach_depth}]->(f:Function {{snapshot_id: $sid}})
                WITH f.name AS func_name, f.file_path AS file_path, min(length(path)) AS depth
                RETURN func_name, file_path, depth
                """,
                {"sid": snapshot_id, "fpath": main_file},
            )
            for row in bfs_result:
                reaches.append(
                    {
                        "fuzzer_name": fuzzer.name,
                        "function_name": row["func_name"],
                        "file_path": row["file_path"],
                        "depth": row["depth"],
                    }
                )
        return reaches
