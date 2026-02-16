"""Static analysis orchestrator — 6-phase pipeline."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from z_code_analyzer.backends.base import FuzzerInfo
from z_code_analyzer.build.detector import BuildCommandDetector
from z_code_analyzer.build.fuzzer_parser import FuzzerEntryParser
from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.probe import ProjectProbe
from z_code_analyzer.progress import ProgressTracker
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
    ) -> None:
        self.snapshot_manager = snapshot_manager
        self.graph_store = graph_store
        self.progress = ProgressTracker()

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

        # Check snapshot cache
        snapshot_doc = await self.snapshot_manager.acquire_or_wait(
            repo_url, version, backend or "svf"
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
            # In production, this calls BitcodeGenerator.generate_via_docker()
            # For now, we note that the bitcode step requires Docker
            all_fuzzer_files = [f for files in fuzzer_sources.values() for f in files]
            self.progress.complete_phase(
                "bitcode",
                detail=f"fuzzer_files_excluded={len(all_fuzzer_files)}",
            )

            # Phase 4a: SVF analysis
            self.progress.start_phase("svf")
            from z_code_analyzer.backends.svf_backend import SVFBackend

            svf = SVFBackend()
            # In production: result = svf.analyze(project_path, detected_lang, bc_path=..., function_metas=...)
            # For now this is a placeholder that will be wired up when Docker is available
            self.progress.complete_phase("svf")

            # Phase 4b: Fuzzer entry parsing
            self.progress.start_phase("fuzzer_parse")
            # library_func_names = {f.name for f in result.functions}
            # fuzzer_calls = FuzzerEntryParser().parse(fuzzer_sources, library_func_names, project_path)
            self.progress.complete_phase(
                "fuzzer_parse",
                detail=f"{len(fuzzer_sources)} fuzzers",
            )

            # Phase 5: AI refinement (skipped in v1)
            self.progress.skip_phase("ai_refine", "v1: not implemented")

            # Phase 6: Neo4j import
            self.progress.start_phase("import")
            # self.graph_store.create_snapshot_node(snapshot_id, repo_url, version, "svf")
            # func_count = self.graph_store.import_functions(snapshot_id, result.functions)
            # edge_count = self.graph_store.import_edges(snapshot_id, result.edges)
            # fuzzer_infos = self._assemble_fuzzer_infos(fuzzer_sources, fuzzer_calls)
            # self.graph_store.import_fuzzers(snapshot_id, fuzzer_infos)
            # reaches = self._compute_reaches(snapshot_id, fuzzer_infos)
            # self.graph_store.import_reaches(snapshot_id, reaches)
            # fuzzer_names = [f.name for f in fuzzer_infos]
            # self.snapshot_manager.mark_completed(snapshot_id, func_count, edge_count, fuzzer_names)
            self.progress.complete_phase("import")

            # Placeholder return until full pipeline is wired
            return AnalysisOutput(
                snapshot_id=snapshot_id,
                repo_url=repo_url,
                version=version,
                backend="svf",
                function_count=0,
                edge_count=0,
                fuzzer_names=list(fuzzer_sources.keys()),
                cached=False,
            )

        except Exception as e:
            if snapshot_id:
                self.snapshot_manager.mark_failed(snapshot_id, str(e))
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
        )

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
            bfs_result = self.graph_store.raw_query(
                f"""
                MATCH path = (entry:Function {{snapshot_id: $sid,
                                              name: "LLVMFuzzerTestOneInput",
                                              file_path: $fpath}})
                             -[:CALLS*0..{max_reach_depth}]->(f:Function {{snapshot_id: $sid}})
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
