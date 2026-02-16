"""Data models for project info and language detection."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LanguageProfile:
    """Language detection result."""

    primary_language: str  # "c", "cpp", "java", "go", "rust", ...
    file_counts: dict[str, int] = field(default_factory=dict)  # {".c": 150, ".h": 80, ...}
    confidence: float = 1.0
    detected_features: list[str] = field(default_factory=list)  # e.g. ["has_compile_commands"]


@dataclass
class ProjectInfo:
    """Project probe result."""

    project_path: str
    language_profile: LanguageProfile
    source_files: list[str] = field(default_factory=list)
    build_system: str = "unknown"  # "cmake" | "autotools" | "meson" | "make" | "custom" | "unknown"
    estimated_loc: int = 0
    diff_files: list[str] | None = None
    git_root: str | None = None
