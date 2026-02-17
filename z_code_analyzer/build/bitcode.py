"""Bitcode generation — orchestrates wllvm injection + library-only llvm-link.

The actual build runs inside Docker (via svf-pipeline.sh).
This module provides the Python-side orchestration logic.
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from pathlib import Path

from z_code_analyzer.exceptions import BitcodeError
from z_code_analyzer.models.build import BitcodeOutput, BuildCommand, FunctionMeta

logger = logging.getLogger(__name__)

# Field extractors applied within a single DISubprogram entry
_DI_NAME_RE = re.compile(r'name:\s*"([^"]+)"')
_DI_LINK_RE = re.compile(r'linkageName:\s*"([^"]+)"')
_DI_FILE_REF_RE = re.compile(r"file:\s*!(\d+)")
_DI_LINE_RE = re.compile(r"(?<![a-zA-Z])line:\s*(\d+)")

# Marker for entry boundary
_DI_SUBPROGRAM_START_RE = re.compile(r"!DISubprogram\(")


def _extract_di_subprogram_entries(content: str) -> list[str]:
    """Extract complete DISubprogram(...) entries, handling nested parens."""
    entries = []
    for m in _DI_SUBPROGRAM_START_RE.finditer(content):
        depth = 1
        i = m.end()
        while i < len(content) and depth > 0:
            if content[i] == "(":
                depth += 1
            elif content[i] == ")":
                depth -= 1
            i += 1
        entries.append(content[m.start() : i])
    return entries


# Regex to extract DIFile
# Example: !56 = !DIFile(filename: "lib/ftp.c", directory: "/src/curl")
_DI_FILE_RE = re.compile(
    r"!(\d+)\s*=\s*!DIFile\("
    r'filename:\s*"([^"]+)"'
    r'(?:,\s*directory:\s*"([^"]*)")?'
)


class BitcodeGenerator:
    """
    Orchestrate bitcode generation:
    1. Set CC=z-wllvm, CXX=z-wllvm++, LLVM_COMPILER=clang
    2. Execute build commands
    3. Collect all .bc files, exclude fuzzer source .bc
    4. llvm-link library .bc -> library.bc
    5. llvm-dis -> .ll -> parse DISubprogram -> FunctionMeta list
    6. Return BitcodeOutput
    """

    def generate(
        self,
        project_path: str,
        build_cmd: BuildCommand,
        fuzzer_source_files: list[str],
        output_dir: str | None = None,
    ) -> BitcodeOutput:
        """
        Read pre-generated library-only bitcode and extract function metadata.

        v1 only supports Docker-based bitcode generation via generate_via_docker().
        This method handles the post-generation step: reading library.bc/.ll
        and extracting DISubprogram metadata. The build_cmd and
        fuzzer_source_files params are accepted for API compatibility but
        not used — actual build + llvm-link happens inside Docker.

        Args:
            project_path: Project source root (for source content enrichment).
            build_cmd: (unused in v1) Build commands.
            fuzzer_source_files: (unused in v1) Files to exclude.
            output_dir: Directory containing library.bc (default: temp dir).

        Returns:
            BitcodeOutput with bc_path and function_metas.
        """
        if output_dir is None:
            ws = Path.cwd() / "workspace"
            ws.mkdir(exist_ok=True)
            output_dir = tempfile.mkdtemp(prefix="bitcode-", dir=ws)

        output_path = Path(output_dir)
        bc_path = output_path / "library.bc"
        ll_path = output_path / "library.ll"

        # The actual bitcode generation is done by svf-pipeline.sh in Docker.
        # This is the fallback for local execution (when tools are available).
        if not bc_path.exists():
            raise BitcodeError(
                f"library.bc not found at {bc_path}. "
                "Bitcode generation must be run through svf-pipeline.sh in Docker first."
            )

        # Parse .ll for function metadata if available
        function_metas = []
        if ll_path.exists():
            function_metas = self._parse_ll_debug_info(ll_path, project_path)
            logger.info("Extracted %d function metas from %s", len(function_metas), ll_path)

        # Enrich with source content and end_line from actual source files
        self._enrich_from_source(function_metas, project_path)

        return BitcodeOutput(
            bc_path=str(bc_path),
            function_metas=function_metas,
        )

    def generate_via_docker(
        self,
        project_path: str,
        case_config: str,
        fuzzer_source_files: list[str],
        output_dir: str,
        docker_image: str = "svftools/svf",
        fuzz_tooling_url: str | None = None,
        fuzz_tooling_ref: str | None = None,
    ) -> BitcodeOutput:
        """
        Run the full pipeline in Docker.

        Args:
            project_path: Project source root.
            case_config: Path to case config .sh file.
            fuzzer_source_files: Files to exclude.
            output_dir: Where to write output.
            docker_image: Docker image with build tools.
            fuzz_tooling_url: Git URL for external fuzzer harness repo (e.g. oss-fuzz).
            fuzz_tooling_ref: Branch/tag/commit for fuzz_tooling_url.
        """
        svf_dir = Path(__file__).parent.parent / "svf"
        pipeline_script = svf_dir / "svf-pipeline.sh"

        if not pipeline_script.exists():
            raise BitcodeError(f"Pipeline script not found: {pipeline_script}")

        # Parse PROJECT_NAME from case config for correct mount point
        mount_name = Path(project_path).name  # fallback
        try:
            case_text = Path(case_config).read_text()
            for line in case_text.splitlines():
                line = line.strip()
                if line.startswith("PROJECT_NAME="):
                    mount_name = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
        except OSError:
            pass

        # Clone external fuzz tooling repo if specified (e.g. oss-fuzz harness)
        fuzz_tooling_path = None
        if fuzz_tooling_url:
            fuzz_tooling_path = self._clone_fuzz_tooling(
                fuzz_tooling_url, fuzz_tooling_ref, output_dir
            )

        # Use newline as delimiter to handle paths with spaces
        fuzzer_env = "\n".join(fuzzer_source_files)
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{project_path}:/src/{mount_name}",
            "-v",
            f"{str(svf_dir)}:/pipeline:ro",
            "-v",
            f"{output_dir}:/output",
            "-e",
            "SRC=/src",
            "-e",
            f"FUZZER_SOURCE_FILES={fuzzer_env}",
        ]

        # Mount fuzz tooling repo if available (e.g. $SRC/curl_fuzzer)
        if fuzz_tooling_path:
            tooling_name = Path(fuzz_tooling_path).name
            cmd.extend(["-v", f"{fuzz_tooling_path}:/src/{tooling_name}"])

        cmd.extend([
            docker_image,
            "bash",
            "/pipeline/svf-pipeline.sh",
            f"/pipeline/cases/{Path(case_config).name}",
        ])

        logger.info("Running bitcode pipeline: %s", " ".join(cmd[:10]))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            raise BitcodeError("Bitcode generation timed out")

        if result.returncode != 0:
            output = result.stderr or result.stdout or "(no output)"
            raise BitcodeError(
                f"Bitcode generation failed (rc={result.returncode}):\n{output[-2000:]}"
            )

        bc_path = Path(output_dir) / "library.bc"
        ll_path = Path(output_dir) / "library.ll"

        if not bc_path.exists():
            raise BitcodeError(f"library.bc not produced in {output_dir}")

        function_metas = []
        if ll_path.exists():
            function_metas = self._parse_ll_debug_info(
                ll_path, project_path, docker_mount_name=mount_name
            )

        # Enrich with source content and end_line from actual source files
        self._enrich_from_source(function_metas, project_path)

        return BitcodeOutput(
            bc_path=str(bc_path),
            function_metas=function_metas,
        )

    @staticmethod
    def _clone_fuzz_tooling(
        url: str, ref: str | None, output_dir: str
    ) -> str:
        """Clone external fuzz tooling repo (e.g. oss-fuzz harness) into output_dir.

        Returns the cloned directory path.
        """
        tooling_dir = Path(output_dir) / "fuzz_tooling"
        if tooling_dir.exists():
            return str(tooling_dir)

        clone_cmd = ["git", "clone", "--depth", "1"]
        if ref:
            clone_cmd.extend(["--branch", ref])
        clone_cmd.extend([url, str(tooling_dir)])

        logger.info("Cloning fuzz tooling: %s @ %s", url, ref or "HEAD")
        try:
            result = subprocess.run(
                clone_cmd, capture_output=True, text=True, timeout=120
            )
        except subprocess.TimeoutExpired:
            raise BitcodeError(f"Fuzz tooling clone timed out: {url}")

        if result.returncode != 0:
            # --branch may fail for commit hashes; retry without --depth
            if ref:
                clone_cmd2 = ["git", "clone", url, str(tooling_dir)]
                try:
                    result2 = subprocess.run(
                        clone_cmd2, capture_output=True, text=True, timeout=300
                    )
                except subprocess.TimeoutExpired:
                    raise BitcodeError(f"Fuzz tooling clone timed out: {url}")
                if result2.returncode != 0:
                    raise BitcodeError(
                        f"Fuzz tooling clone failed: {result2.stderr or result2.stdout}"
                    )
                # Checkout specific ref
                subprocess.run(
                    ["git", "checkout", ref],
                    cwd=str(tooling_dir),
                    capture_output=True,
                    text=True,
                )
            else:
                raise BitcodeError(
                    f"Fuzz tooling clone failed: {result.stderr or result.stdout}"
                )

        return str(tooling_dir)

    # Maximum .ll file size to read into memory (500 MB).
    # Larger files (e.g., full Chromium) need a streaming parser.
    _MAX_LL_SIZE = 500 * 1024 * 1024

    @staticmethod
    def _parse_ll_debug_info(
        ll_path: Path, project_path: str, docker_mount_name: str | None = None
    ) -> list[FunctionMeta]:
        """Parse LLVM IR .ll file to extract DISubprogram metadata."""
        file_size = ll_path.stat().st_size
        if file_size > BitcodeGenerator._MAX_LL_SIZE:
            logger.warning(
                "Skipping .ll parsing: %s is %d MB (limit %d MB). "
                "Function metadata will be unavailable.",
                ll_path.name,
                file_size // (1024 * 1024),
                BitcodeGenerator._MAX_LL_SIZE // (1024 * 1024),
            )
            return []
        content = ll_path.read_text(errors="replace")

        # First pass: build file reference table
        file_refs: dict[str, tuple[str, str]] = {}  # {ref_id: (filename, directory)}
        for m in _DI_FILE_RE.finditer(content):
            file_refs[m.group(1)] = (m.group(2), m.group(3) or "")

        # Second pass: extract DISubprogram entries (depth-aware paren matching)
        metas = []
        for entry in _extract_di_subprogram_entries(content):
            name_m = _DI_NAME_RE.search(entry)
            if not name_m:
                continue
            file_m = _DI_FILE_REF_RE.search(entry)
            line_m = _DI_LINE_RE.search(entry)
            if not file_m or not line_m:
                continue
            name = name_m.group(1)
            link_m = _DI_LINK_RE.search(entry)
            link_name = link_m.group(1) if link_m else name
            file_ref = file_m.group(1)
            line = int(line_m.group(1))

            file_info = file_refs.get(file_ref)
            if file_info:
                filename, directory = file_info
                # Make path relative to project
                if directory:
                    file_path = f"{directory}/{filename}"
                else:
                    file_path = filename
                # Strip Docker container prefix (e.g. /src/libpng/ → relative)
                if file_path.startswith("/"):
                    # Try docker mount name first (from case config PROJECT_NAME)
                    # then fall back to project_path basename
                    candidates = []
                    if docker_mount_name:
                        candidates.append(f"/src/{docker_mount_name}/")
                    candidates.append(f"/src/{Path(project_path).name}/")
                    stripped = False
                    for prefix in candidates:
                        if file_path.startswith(prefix):
                            file_path = file_path[len(prefix):]
                            stripped = True
                            break
                    if not stripped and file_path.startswith("/src/"):
                        # Generic fallback: /src/<anything>/ → strip first two segments
                        parts = file_path.split("/")
                        if len(parts) > 3:  # ['', 'src', 'project', 'file.c', ...]
                            file_path = "/".join(parts[3:])
            else:
                file_path = ""

            metas.append(
                FunctionMeta(
                    ir_name=link_name,
                    original_name=name,
                    file_path=file_path,
                    line=line,
                )
            )

        return metas

    @staticmethod
    def _enrich_from_source(metas: list[FunctionMeta], project_path: str) -> None:
        """Read actual source files to populate end_line and content.

        Groups metas by file_path to avoid re-reading the same file.
        Uses brace-counting to find function end lines for C/C++ sources.
        """
        root = Path(project_path)

        # Group by file for efficient I/O
        by_file: dict[str, list[FunctionMeta]] = {}
        for m in metas:
            if m.file_path and m.line > 0:
                by_file.setdefault(m.file_path, []).append(m)

        for file_path, file_metas in by_file.items():
            src_path = root / file_path
            if not src_path.is_file():
                continue
            try:
                lines = src_path.read_text(errors="replace").splitlines()
            except OSError:
                continue

            # Sort by start line so we process top-to-bottom
            file_metas.sort(key=lambda m: m.line)

            for m in file_metas:
                start_idx = m.line - 1  # 0-based
                if start_idx >= len(lines):
                    continue

                end_idx = BitcodeGenerator._find_function_end(lines, start_idx)
                m.end_line = end_idx + 1  # back to 1-based
                m.content = "\n".join(lines[start_idx : end_idx + 1])

        enriched = sum(1 for m in metas if m.content)
        if metas:
            logger.info("Enriched %d/%d functions with source content", enriched, len(metas))
            if enriched == 0 and by_file:
                sample_paths = list(by_file.keys())[:5]
                logger.warning(
                    "No functions enriched! Sample file_paths from .ll: %s  "
                    "project_path: %s — check if paths match actual source tree",
                    sample_paths,
                    root,
                )

    @staticmethod
    def _find_function_end(lines: list[str], start_idx: int) -> int:
        """Find the closing brace of a C/C++ function using brace counting.

        Starts scanning from start_idx. Once the first '{' is found,
        counts braces until depth returns to 0.

        Skips braces inside // comments, /* */ block comments, and string
        literals to avoid miscounting.

        Returns the 0-based line index of the closing '}'.
        Falls back to start_idx if no braces found within 2000 lines.
        """
        depth = 0
        found_open = False
        in_block_comment = False
        max_scan = min(start_idx + 2000, len(lines))

        for i in range(start_idx, max_scan):
            line = lines[i]
            j = 0
            while j < len(line):
                # Inside block comment — look for */
                if in_block_comment:
                    close = line.find("*/", j)
                    if close == -1:
                        break  # rest of line is comment
                    j = close + 2
                    in_block_comment = False
                    continue

                ch = line[j]
                # Start of block comment
                if ch == "/" and j + 1 < len(line) and line[j + 1] == "*":
                    in_block_comment = True
                    j += 2
                    continue
                # Line comment — skip rest of line
                if ch == "/" and j + 1 < len(line) and line[j + 1] == "/":
                    break
                # String literal — skip to closing quote
                if ch in ('"', "'"):
                    quote = ch
                    j += 1
                    while j < len(line):
                        if line[j] == "\\" and j + 1 < len(line):
                            j += 2  # skip escaped char
                            continue
                        if line[j] == quote:
                            break
                        j += 1
                    j += 1
                    continue
                # Count braces
                if ch == "{":
                    depth += 1
                    found_open = True
                elif ch == "}":
                    depth -= 1
                    if found_open and depth == 0:
                        return i
                j += 1

        # Fallback: couldn't find matching brace, return start
        return start_idx
