"""Project probe — language detection and build system identification."""

from __future__ import annotations

import logging
import os
import subprocess
from collections import Counter
from pathlib import Path

from z_code_analyzer.models.project import LanguageProfile, ProjectInfo

logger = logging.getLogger(__name__)

# Language detection by file extension
_EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".c": "c",
    ".h": "c",  # Ambiguous, could be C or C++
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
}

# Build system marker files, ordered by priority
_BUILD_SYSTEM_MARKERS: list[tuple[str, str]] = [
    ("CMakeLists.txt", "cmake"),
    ("configure", "autotools"),
    ("configure.ac", "autotools"),
    ("configure.in", "autotools"),
    ("meson.build", "meson"),
    ("Makefile", "make"),
    ("build.sh", "custom"),
]

# Feature indicator files (doc §6.1)
_FEATURE_INDICATORS: dict[str, str] = {
    "compile_commands.json": "has_compile_commands",
    ".clang-format": "uses_clang_tools",
    "compile_flags.txt": "has_compile_flags",
}

# Directories to skip during scanning
_SKIP_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".tox",
    ".venv",
    "venv",
    "build",
    "dist",
    ".eggs",
    "third_party",
    "vendor",
}


class ProjectProbe:
    """Probe project for language, build system, and source files."""

    def probe(
        self,
        project_path: str,
        diff_files: list[str] | None = None,
    ) -> ProjectInfo:
        root = Path(project_path)
        if not root.is_dir():
            raise FileNotFoundError(f"Project path not found: {project_path}")

        # Collect source files
        source_files = self._collect_source_files(root)

        # Language detection
        language_profile = self._detect_language(source_files)

        # Feature indicators (compile_commands.json, .clang-format, etc.)
        language_profile.detected_features = self._detect_features(root)

        # Build system
        build_system = self._detect_build_system(root)

        # LOC estimate
        estimated_loc = self._estimate_loc(root, source_files)

        # Git root
        git_root = self._find_git_root(root)

        return ProjectInfo(
            project_path=str(root.resolve()),
            language_profile=language_profile,
            source_files=[str(f) for f in source_files],
            build_system=build_system,
            estimated_loc=estimated_loc,
            diff_files=diff_files,
            git_root=git_root,
        )

    def _collect_source_files(self, root: Path) -> list[Path]:
        """Collect all source files, skipping common non-source directories."""
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip unwanted directories
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for f in filenames:
                ext = Path(f).suffix.lower()
                if ext in _EXTENSION_TO_LANGUAGE:
                    files.append(Path(dirpath) / f)
        return files

    def _detect_language(self, source_files: list[Path]) -> LanguageProfile:
        """Detect primary language from file extension statistics."""
        ext_counter: Counter[str] = Counter()
        for f in source_files:
            ext_counter[f.suffix.lower()] += 1

        if not ext_counter:
            return LanguageProfile(primary_language="unknown", file_counts={}, confidence=0.0)

        # Map extensions to languages and count
        lang_counter: Counter[str] = Counter()
        for ext, count in ext_counter.items():
            lang = _EXTENSION_TO_LANGUAGE.get(ext)
            if lang:
                lang_counter[lang] += count

        # .h files: if there are .cpp/.cc files, re-attribute .h from c to cpp
        if "cpp" in lang_counter and "c" in lang_counter:
            h_count = ext_counter.get(".h", 0)
            if h_count > 0:
                cpp_source_count = sum(
                    ext_counter.get(e, 0) for e in (".cc", ".cpp", ".cxx")
                )
                c_source_count = ext_counter.get(".c", 0)
                if cpp_source_count > c_source_count:
                    # Only move the .h count that was attributed to "c"
                    move = min(h_count, lang_counter["c"])
                    lang_counter["cpp"] += move
                    lang_counter["c"] -= move

        if not lang_counter:
            return LanguageProfile(
                primary_language="unknown",
                file_counts=dict(ext_counter),
                confidence=0.0,
            )

        primary = lang_counter.most_common(1)[0][0]
        total = sum(lang_counter.values())
        confidence = lang_counter[primary] / total if total > 0 else 0

        return LanguageProfile(
            primary_language=primary,
            file_counts=dict(ext_counter),
            confidence=round(confidence, 2),
        )

    def _detect_features(self, root: Path) -> list[str]:
        """Detect feature indicator files (doc §6.1)."""
        features = []
        for filename, feature_name in _FEATURE_INDICATORS.items():
            if (root / filename).exists():
                features.append(feature_name)
        return features

    def _detect_build_system(self, root: Path) -> str:
        """Detect build system from marker files."""
        for marker, system in _BUILD_SYSTEM_MARKERS:
            if (root / marker).exists():
                return system
        return "unknown"

    def _estimate_loc(self, root: Path, source_files: list[Path]) -> int:
        """Rough LOC estimate by counting lines in source files."""
        total = 0
        for f in source_files[:1000]:  # Cap at 1000 files for speed
            try:
                with f.open() as fh:
                    total += sum(1 for _ in fh)
            except (OSError, UnicodeDecodeError):
                pass
        return total

    def _find_git_root(self, root: Path) -> str | None:
        """Find git root directory."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                cwd=str(root),
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return None
