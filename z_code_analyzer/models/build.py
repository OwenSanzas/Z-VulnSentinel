"""Data models for build system and bitcode generation."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BuildCommand:
    """Detected or provided build command."""

    commands: list[str]  # e.g. ["cmake -B build", "cmake --build build"]
    source: str  # "user" | "auto_detect" | "llm"
    build_system: str  # "cmake" | "autotools" | "meson" | "make" | "custom"
    confidence: float = 1.0  # 1.0 (user) / 0.8 (auto) / 0.5 (llm)


@dataclass
class FunctionMeta:
    """Function metadata extracted from LLVM IR debug info (DISubprogram)."""

    ir_name: str  # LLVM IR name (may be mangled, e.g. init.1)
    original_name: str  # source name (e.g. init)
    file_path: str  # source file path (e.g. lib/ftp.c)
    line: int  # start line number
    end_line: int = 0
    content: str = ""  # source code read from file


@dataclass
class BitcodeOutput:
    """Result of bitcode generation (library-only)."""

    bc_path: str  # path to library.bc
    function_metas: list[FunctionMeta] = field(default_factory=list)
