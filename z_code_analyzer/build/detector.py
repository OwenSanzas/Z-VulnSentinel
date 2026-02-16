"""Build command detection — Layer 1 (user provided) + Layer 2 (auto detect).

v1 does not implement Layer 3 (LLM inference).
"""

from __future__ import annotations

import logging
from pathlib import Path

from z_code_analyzer.models.build import BuildCommand

logger = logging.getLogger(__name__)

# Detection rules: (marker_file, build_system, default_commands)
# Ordered by priority
DETECTION_RULES: list[tuple[str, str, list[str]]] = [
    ("CMakeLists.txt", "cmake", ["cmake -B build", "cmake --build build"]),
    ("configure.ac", "autotools", ["autoreconf -fi && ./configure && make"]),
    ("configure.in", "autotools", ["autoreconf -fi && ./configure && make"]),
    ("configure", "autotools", ["./configure && make"]),
    ("meson.build", "meson", ["meson setup build", "ninja -C build"]),
    ("Makefile", "make", ["make"]),
]


class BuildCommandDetector:
    """
    Detect build commands from project structure.

    Layer 1: User provides build_script -> use directly.
    Layer 2: Auto-detect build system from marker files.
    v1 does not implement Layer 3 (LLM).
    """

    def detect(
        self,
        project_path: str,
        build_script: str | None = None,
    ) -> BuildCommand | None:
        """
        Detect build command.

        Args:
            project_path: Project root directory.
            build_script: User-provided build script path (Layer 1).

        Returns:
            BuildCommand if detected, None if nothing found.
        """
        # Layer 1: User-provided build script
        if build_script:
            script_path = Path(project_path) / build_script
            if script_path.exists():
                logger.info("Using user-provided build script: %s", build_script)
                return BuildCommand(
                    commands=[str(script_path)],
                    source="user",
                    build_system="custom",
                    confidence=1.0,
                )
            # Try as absolute path
            if Path(build_script).exists():
                logger.info("Using user-provided build script (absolute): %s", build_script)
                return BuildCommand(
                    commands=[build_script],
                    source="user",
                    build_system="custom",
                    confidence=1.0,
                )
            logger.warning("User build script not found: %s", build_script)

        # Layer 2: Auto-detect from project structure
        return self._auto_detect(project_path)

    def _auto_detect(self, project_path: str) -> BuildCommand | None:
        """Detect build system from marker files."""
        root = Path(project_path)

        for marker_file, build_system, default_commands in DETECTION_RULES:
            if (root / marker_file).exists():
                logger.info("Auto-detected build system: %s (found %s)", build_system, marker_file)
                return BuildCommand(
                    commands=default_commands,
                    source="auto_detect",
                    build_system=build_system,
                    confidence=0.8,
                )

        logger.warning("No build system detected in %s", project_path)
        return None

    def detect_build_system(self, project_path: str) -> str:
        """Just detect the build system type, without generating commands."""
        root = Path(project_path)
        for marker_file, build_system, _ in DETECTION_RULES:
            if (root / marker_file).exists():
                return build_system
        return "unknown"
