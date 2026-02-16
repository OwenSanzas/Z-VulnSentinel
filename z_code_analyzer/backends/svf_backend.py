"""SVF analysis backend — LLVM IR Andersen pointer analysis for C/C++.

Requires Docker with svftools/svf image.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from z_code_analyzer.backends.base import (
    AnalysisBackend,
    AnalysisResult,
    CallEdge,
    CallType,
    FunctionRecord,
)
from z_code_analyzer.exceptions import SVFError
from z_code_analyzer.svf.svf_dot_parser import (
    get_all_function_names,
    get_typed_edge_list,
    parse_svf_dot,
)

logger = logging.getLogger(__name__)

SVF_DOCKER_IMAGE = "svftools/svf"
SVF_TIMEOUT = 600  # 10 minutes max for SVF analysis


class SVFBackend(AnalysisBackend):
    """
    SVF-based static analysis backend for C/C++.

    Workflow:
        BitcodeOutput.bc_path -> docker run svftools/svf wpa -ander -dump-callgraph
            -> callgraph_final.dot -> svf_dot_parser.parse() -> {functions, edges}
            -> merge with BitcodeOutput.function_metas (file_path, content)
            -> AnalysisResult
    """

    def __init__(self, docker_image: str = SVF_DOCKER_IMAGE) -> None:
        self._docker_image = docker_image

    @property
    def name(self) -> str:
        return "svf"

    @property
    def supported_languages(self) -> set[str]:
        return {"c", "cpp"}

    def get_descriptor(self):
        """Return SVF backend descriptor."""
        from z_code_analyzer.backends.registry import (
            BackendCapability,
            BackendDescriptor,
        )

        return BackendDescriptor(
            name="svf",
            supported_languages={"c", "cpp"},
            capabilities={
                BackendCapability.FUNCTION_EXTRACTION,
                BackendCapability.DIRECT_CALLS,
                BackendCapability.VIRTUAL_DISPATCH,
                BackendCapability.FUNCTION_POINTERS,
            },
            precision_score=0.98,
            speed_score=0.60,
            prerequisites=["Docker", "svftools/svf image"],
            factory=SVFBackend,
        )

    def analyze(
        self,
        project_path: str,
        language: str,
        **kwargs: Any,
    ) -> AnalysisResult:
        """
        Run SVF analysis on library-only bitcode.

        Required kwargs:
            bc_path: str — path to library.bc
            function_metas: list[dict] — from BitcodeOutput, with keys:
                ir_name, original_name, file_path, line, content
        """
        bc_path = kwargs.get("bc_path")
        function_metas = kwargs.get("function_metas", [])

        if not bc_path:
            raise SVFError("bc_path is required for SVF backend")
        if not Path(bc_path).exists():
            raise SVFError(f"Bitcode file not found: {bc_path}")

        start = time.monotonic()

        # Run SVF in Docker — returns both initial and final DOT content
        final_dot, initial_dot = self._run_svf_docker(bc_path)

        # Parse both DOT files for call type classification
        nodes, final_adj = parse_svf_dot(final_dot)
        all_func_names = get_all_function_names(nodes)

        if initial_dot:
            _, initial_adj = parse_svf_dot(initial_dot)
            typed_edges = get_typed_edge_list(initial_adj, final_adj)
        else:
            # Fallback: if initial.dot not available, treat all as direct
            logger.warning("callgraph_initial.dot not found — all edges marked as DIRECT")
            typed_edges = [(c, e, "direct") for c, es in final_adj.items() for e in es]

        # Build function metadata lookup from BitcodeOutput
        # Index by both ir_name (mangled, e.g. _Z3foov) and original_name (demangled, e.g. foo)
        # so SVF DOT names (which use IR/mangled names) can find their metadata
        meta_by_name: dict[str, dict] = {}
        for meta in function_metas:
            ir = meta.get("ir_name", "")
            original = meta.get("original_name", "")
            if ir:
                meta_by_name[ir] = meta
            if original and original != ir:
                meta_by_name[original] = meta

        # Build FunctionRecord list
        functions = []
        for func_name in sorted(all_func_names):
            meta = meta_by_name.get(func_name)
            if meta:
                functions.append(
                    FunctionRecord(
                        name=func_name,
                        file_path=meta.get("file_path", ""),
                        start_line=meta.get("line", 0),
                        end_line=meta.get("end_line", 0),
                        content=meta.get("content", ""),
                        language=language,
                        source_backend="svf",
                    )
                )
            else:
                # External function (no debug info)
                functions.append(
                    FunctionRecord(
                        name=func_name,
                        file_path="",
                        start_line=0,
                        end_line=0,
                        content="",
                        language=language,
                        source_backend="svf",
                    )
                )

        # Build CallEdge list with call type from initial/final DOT diff
        edges = []
        for caller, callee, ctype in typed_edges:
            caller_meta = meta_by_name.get(caller)
            callee_meta = meta_by_name.get(callee)
            edges.append(
                CallEdge(
                    caller=caller,
                    callee=callee,
                    call_type=CallType.FPTR if ctype == "fptr" else CallType.DIRECT,
                    caller_file=caller_meta.get("file_path", "") if caller_meta else "",
                    callee_file=callee_meta.get("file_path", "") if callee_meta else "",
                    source_backend="svf",
                )
            )

        duration = time.monotonic() - start

        return AnalysisResult(
            functions=functions,
            edges=edges,
            language=language,
            backend="svf",
            analysis_duration_seconds=round(duration, 2),
            metadata={
                "node_count": len(all_func_names),
                "edge_count": len(typed_edges),
                "fptr_edge_count": sum(1 for _, _, ct in typed_edges if ct == "fptr"),
                "bc_path": bc_path,
            },
        )

    def _run_svf_docker(self, bc_path: str) -> tuple[str, str | None]:
        """Run SVF in Docker container.

        Returns:
            (final_dot_content, initial_dot_content_or_None)
        """
        bc_path = str(Path(bc_path).resolve())
        bc_dir = str(Path(bc_path).parent)
        bc_name = Path(bc_path).name

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{bc_dir}:/input:ro",
                "-v",
                f"{tmpdir}:/output",
                self._docker_image,
                "bash",
                "-c",
                f"cd /output && wpa -ander -dump-callgraph /input/{bc_name} 2>&1",
            ]

            logger.info("Running SVF: %s", " ".join(cmd))
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=SVF_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                raise SVFError(f"SVF analysis timed out after {SVF_TIMEOUT}s")

            if result.returncode != 0:
                logger.warning("SVF stderr: %s", result.stderr[-2000:] if result.stderr else "")

            dot_final = Path(tmpdir) / "callgraph_final.dot"
            if not dot_final.exists():
                raise SVFError(
                    f"SVF did not produce callgraph_final.dot. "
                    f"stdout: {result.stdout[-500:]}, stderr: {result.stderr[-500:]}"
                )

            dot_initial = Path(tmpdir) / "callgraph_initial.dot"
            initial_content = dot_initial.read_text() if dot_initial.exists() else None

            return dot_final.read_text(), initial_content

    def check_prerequisites(self, project_path: str) -> list[str]:
        missing = []
        # Check Docker
        try:
            subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=10,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            missing.append("Docker is not available")

        # Check SVF image
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", self._docker_image],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                missing.append(f"Docker image '{self._docker_image}' not found (docker pull {self._docker_image})")
        except (subprocess.SubprocessError, FileNotFoundError):
            pass  # Docker not available already reported

        return missing
