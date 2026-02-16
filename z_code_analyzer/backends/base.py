"""Core data types and abstract base class for analysis backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CallType(Enum):
    """Function call type. v1 only has DIRECT and FPTR."""

    DIRECT = "direct"
    FPTR = "fptr"


@dataclass
class FunctionRecord:
    """
    Function record produced by an analysis backend.
    This is the backend output format, not the storage model.
    GraphStore handles FunctionRecord -> Neo4j :Function node writing.
    """

    name: str
    file_path: str  # relative to project root
    start_line: int
    end_line: int
    content: str
    language: str  # "c", "cpp", "java", "go", "rust", ...
    cyclomatic_complexity: int = 0
    return_type: str = ""
    parameters: list[str] = field(default_factory=list)
    is_entry_point: bool = False
    confidence: float = 1.0
    source_backend: str = ""


@dataclass
class CallEdge:
    """
    Call relationship between two functions.
    Carries call type and confidence for ResultMerger decisions.
    """

    caller: str
    callee: str
    call_type: CallType = CallType.DIRECT
    call_site_file: str = ""
    call_site_line: int = 0
    caller_file: str = ""
    callee_file: str = ""
    confidence: float = 1.0
    source_backend: str = ""


@dataclass
class AnalysisResult:
    """
    Complete output from a static analysis backend.
    All backends produce this structure.
    Note: backends only analyze library code, no fuzzer entry info.
    """

    functions: list[FunctionRecord]
    edges: list[CallEdge]
    language: str
    backend: str
    analysis_duration_seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzerInfo:
    """Complete info for writing a Neo4j :Fuzzer node."""

    name: str
    entry_function: str = "LLVMFuzzerTestOneInput"
    files: list[dict[str, str]] = field(default_factory=list)  # [{path, source}]
    called_library_functions: list[str] = field(default_factory=list)
    focus: str | None = None


class AnalysisBackend(ABC):
    """
    Abstract base class for static analysis backends.
    Each backend knows how to extract function metadata and call graphs.
    All backends produce AnalysisResult.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend identifier, e.g. 'svf', 'joern', 'introspector'."""
        ...

    @property
    @abstractmethod
    def supported_languages(self) -> set[str]:
        """Supported language set, e.g. {'c', 'cpp'}."""
        ...

    @abstractmethod
    def analyze(
        self,
        project_path: str,
        language: str,
        **kwargs: Any,
    ) -> AnalysisResult:
        """
        Run static analysis on a project (library code only).

        Args:
            project_path: Project source root directory.
            language: Target language.
            **kwargs: Backend-specific options.

        Returns:
            AnalysisResult (library code only, no fuzzer entries).
        """
        ...

    def get_descriptor(self) -> Any:
        """
        Return this backend's capability descriptor (BackendDescriptor).
        Subclasses should override to return their registered descriptor.
        Default returns None for backends not yet registered.
        """
        return None

    def check_prerequisites(self, project_path: str) -> list[str]:
        """
        Check prerequisites.
        Returns list of missing items (empty = can run).
        """
        return []
