"""Static analysis orchestrator — 6-phase pipeline."""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from z_code_analyzer.backends.base import AnalysisResult, FuzzerInfo
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
        self._snapshot_id_for_log: str | None = None

    def _new_progress(self) -> ProgressTracker:
        """Create a fresh ProgressTracker for each analysis call."""
        tracker = ProgressTracker()
        if self.log_store:
            tracker.callbacks.append(self._log_phase_callback)
        return tracker

    def _log_phase_callback(self, phase: PhaseProgress) -> None:
        """Write phase status transitions to LogStore."""
        if not self.log_store or not self._snapshot_id_for_log:
            return
        try:
            with self.log_store.get_writer(self._snapshot_id_for_log, phase.phase) as writer:
                duration_str = f" ({phase.duration}s)" if phase.duration is not None else ""
                detail_str = f" — {phase.detail}" if phase.detail else ""
                error_str = f" ERROR: {phase.error}" if phase.error else ""
                writer.write(f"[{phase.status}]{duration_str}{detail_str}{error_str}\n")
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
        svf_case_config: str | None = None,
        svf_docker_image: str | None = None,
        fuzz_tooling_url: str | None = None,
        fuzz_tooling_ref: str | None = None,
    ) -> AnalysisOutput:
        """Full analysis pipeline entry point.

        Note: Only acquire_or_wait is truly async. Phases 1-6 run synchronously
        and will block the event loop. For web contexts, run in a thread pool
        via asyncio.to_thread() or use ProcessPoolExecutor.
        """
        progress = self._new_progress()
        self.progress = progress  # expose last run's progress for callers
        snapshot_id: str | None = None
        analysis_committed = False

        # v1: only SVF backend is supported
        if backend and backend not in ("svf", "auto"):
            logger.warning("Backend '%s' not supported in v1, falling back to 'svf'", backend)
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

        output_dir_obj = None
        try:
            # Phase 1: Project probe
            progress.start_phase("probe")
            info = ProjectProbe().probe(project_path, diff_files=diff_files)
            detected_lang = language or info.language_profile.primary_language
            progress.complete_phase(
                "probe",
                detail=f"lang={detected_lang}, build={info.build_system}, "
                f"files={len(info.source_files)}",
            )

            # Phase 2: Build command detection
            progress.start_phase("build_cmd")
            build_cmd = BuildCommandDetector().detect(project_path, build_script=build_script)
            if build_cmd:
                progress.complete_phase(
                    "build_cmd",
                    detail=f"{build_cmd.build_system} (source: {build_cmd.source})",
                )
            else:
                progress.fail_phase("build_cmd", "No build system detected")
                raise RuntimeError("No build system detected and no build_script provided")

            # Phase 3: Bitcode generation (in Docker via svf-pipeline.sh)
            progress.start_phase("bitcode")
            all_fuzzer_files = [f for files in fuzzer_sources.values() for f in files]
            bitcode_gen = BitcodeGenerator()
            ws = Path(project_path).resolve().parent
            if not (ws / "workspace").exists():
                ws = Path.cwd()
            ws_dir = ws / "workspace"
            ws_dir.mkdir(exist_ok=True)
            output_dir_obj = tempfile.TemporaryDirectory(prefix="analyze-", dir=ws_dir)
            output_dir = output_dir_obj.name

            # Determine case config from build system
            case_config = self._resolve_case_config(
                build_cmd.build_system, project_path, svf_case_config
            )

            # Build Docker kwargs shared by both paths
            docker_kwargs: dict = {}
            if svf_docker_image:
                docker_kwargs["docker_image"] = svf_docker_image
            if fuzz_tooling_url:
                docker_kwargs["fuzz_tooling_url"] = fuzz_tooling_url
                if fuzz_tooling_ref:
                    docker_kwargs["fuzz_tooling_ref"] = fuzz_tooling_ref

            if case_config or fuzz_tooling_url:
                # Docker pipeline: hand-written case config or auto-locate
                # via fuzz_tooling (case_config may be None — bitcode.py
                # will auto-generate an ossfuzz-native config)
                bc_output = bitcode_gen.generate_via_docker(
                    project_path=project_path,
                    case_config=case_config,
                    fuzzer_source_files=all_fuzzer_files,
                    output_dir=output_dir,
                    **docker_kwargs,
                )
            else:
                # No case config and no fuzz_tooling — try pre-existing bitcode
                bc_output = bitcode_gen.generate(
                    project_path=project_path,
                    build_cmd=build_cmd,
                    fuzzer_source_files=all_fuzzer_files,
                    output_dir=output_dir,
                )
            progress.complete_phase(
                "bitcode",
                detail=f"bc={bc_output.bc_path}, metas={len(bc_output.function_metas)}, "
                f"excluded={len(all_fuzzer_files)}",
            )

            # Phase 4a: SVF analysis
            progress.start_phase("svf")
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
            progress.complete_phase(
                "svf",
                detail=f"functions={len(result.functions)}, edges={len(result.edges)}, "
                f"fptr={result.metadata.get('fptr_edge_count', 0)}",
            )

            # Phase 4b: Fuzzer entry parsing
            progress.start_phase("fuzzer_parse")
            library_func_names = {f.name for f in result.functions}

            # For external harness repos (e.g. curl_fuzzer in Docker image),
            # svf-pipeline.sh copies sources to output_dir/fuzzer_sources/.
            extracted_fuzzer_dir = Path(output_dir) / "fuzzer_sources"
            if extracted_fuzzer_dir.is_dir():
                self._fuzzer_search_paths = [project_path, str(extracted_fuzzer_dir)]
                logger.info("Found extracted fuzzer sources at %s", extracted_fuzzer_dir)
            else:
                self._fuzzer_search_paths = None

            fuzzer_calls = FuzzerEntryParser().parse(
                fuzzer_sources,
                library_func_names,
                project_path,
                extra_search_paths=self._fuzzer_search_paths,
            )
            progress.complete_phase(
                "fuzzer_parse",
                detail=f"{len(fuzzer_sources)} fuzzers, "
                f"lib_calls={sum(len(v) for v in fuzzer_calls.values())}",
            )

            # Phase 5: AI refinement (skipped in v1)
            progress.skip_phase("ai_refine", "v1: not implemented")

            # Phase 6: Neo4j import + REACHES computation
            progress.start_phase("import")
            # Clean slate: remove any partial data from previous failed attempts
            self.graph_store.delete_snapshot(snapshot_id)
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
                language=detected_lang,
            )
            analysis_committed = True
            progress.complete_phase(
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
                try:
                    self.snapshot_manager.mark_failed(snapshot_id, str(e))
                except Exception:
                    logger.warning(
                        "Failed to mark snapshot %s as failed", snapshot_id, exc_info=True
                    )
                try:
                    self.graph_store.delete_snapshot(snapshot_id)
                except Exception:
                    logger.warning(
                        "Failed to clean up partial Neo4j data for %s", snapshot_id, exc_info=True
                    )
            raise
        finally:
            # Clean up temp directory (bitcode, DOT files, etc.)
            if output_dir_obj is not None:
                try:
                    output_dir_obj.cleanup()
                except Exception:
                    logger.debug("Failed to clean up temp dir", exc_info=True)

    def analyze_full(
        self,
        project_path: str,
        repo_url: str,
        version: str,
        fuzzer_sources: dict[str, list[str]],
        result: AnalysisResult,
        snapshot_id: str,
    ) -> AnalysisOutput:
        """
        Run Phase 4b + Phase 6 with an already-computed AnalysisResult.
        Used when SVF has already been run externally.
        """
        progress = self._new_progress()
        self.progress = progress  # expose last run's progress for callers
        self._snapshot_id_for_log = snapshot_id
        analysis_committed = False
        try:
            # Phase 4b: Fuzzer entry parsing
            progress.start_phase("fuzzer_parse")
            library_func_names = {f.name for f in result.functions}
            fuzzer_calls = FuzzerEntryParser().parse(
                fuzzer_sources,
                library_func_names,
                project_path,
                extra_search_paths=getattr(self, "_fuzzer_search_paths", None),
            )
            progress.complete_phase(
                "fuzzer_parse",
                detail=f"{len(fuzzer_sources)} fuzzers parsed",
            )

            # Phase 5: AI refinement (skipped in v1)
            progress.skip_phase("ai_refine", "v1: not implemented")

            # Phase 6: Neo4j import
            # Clean slate: remove any partial data from previous failed attempts
            progress.start_phase("import")
            self.graph_store.delete_snapshot(snapshot_id)
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
            progress.complete_phase(
                "import",
                detail=f"{func_count} functions, {edge_count} edges",
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
            if not analysis_committed:
                try:
                    self.snapshot_manager.mark_failed(snapshot_id, str(e))
                except Exception:
                    logger.warning(
                        "Failed to mark snapshot %s as failed", snapshot_id, exc_info=True
                    )
                try:
                    self.graph_store.delete_snapshot(snapshot_id)
                except Exception:
                    logger.warning(
                        "Failed to clean up partial Neo4j data for %s", snapshot_id, exc_info=True
                    )
            raise

    @staticmethod
    def _resolve_case_config(
        build_system: str, project_path: str, svf_case_config: str | None = None
    ) -> str | None:
        """Find a matching SVF case config for the project, or None."""

        cases_dir = Path(__file__).parent / "svf" / "cases"
        if not cases_dir.is_dir():
            return None

        # Priority 1: explicit case config from work order
        if svf_case_config:
            case_file = cases_dir / f"{svf_case_config}.sh"
            if case_file.exists():
                return str(case_file)
            logger.warning("SVF case config '%s' not found at %s", svf_case_config, case_file)

        # Priority 2: project name match
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

    _MAX_REACH_DEPTH = 50  # upper bound to prevent Neo4j memory exhaustion

    def _compute_reaches(
        self,
        snapshot_id: str,
        fuzzer_infos: list[FuzzerInfo],
    ) -> list[dict]:
        """BFS from each fuzzer's entry to compute REACHES edges + depth.

        Uses shortestPath (BFS-optimized) instead of enumerating all paths,
        which would be O(exponential) on large call graphs.
        """
        reaches = []
        for fuzzer in fuzzer_infos:
            main_file = fuzzer.files[0]["path"] if fuzzer.files else ""
            # Use a dedicated session instead of raw_query to avoid the
            # write-keyword check and to keep depth parameterized.
            with self.graph_store._session() as session:
                result = session.run(
                    f"""
                    MATCH (entry:Function {{snapshot_id: $sid,
                        name: "LLVMFuzzerTestOneInput", file_path: $fpath}})
                    MATCH (f:Function {{snapshot_id: $sid}})
                    WHERE f <> entry
                    MATCH p = shortestPath(
                        (entry)-[:CALLS*..{self._MAX_REACH_DEPTH}]->(f)
                    )
                    RETURN f.name AS func_name, f.file_path AS file_path,
                           length(p) AS depth
                    """,
                    sid=snapshot_id,
                    fpath=main_file,
                )
                for row in result:
                    reaches.append(
                        {
                            "fuzzer_name": fuzzer.name,
                            "function_name": row["func_name"],
                            "file_path": row["file_path"],
                            "depth": row["depth"],
                        }
                    )
        return reaches
