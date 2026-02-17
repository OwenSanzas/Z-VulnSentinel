"""Backend registry — plugin-style backend discovery and management."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from z_code_analyzer.backends.base import AnalysisBackend

logger = logging.getLogger(__name__)


class BackendCapability(Enum):
    """Analysis capabilities."""

    FUNCTION_EXTRACTION = "function_extraction"
    DIRECT_CALLS = "direct_calls"
    VIRTUAL_DISPATCH = "virtual_dispatch"
    FUNCTION_POINTERS = "function_pointers"
    MACRO_EXPANSION = "macro_expansion"
    TEMPLATE_INSTANTIATION = "template_instantiation"
    TYPE_RESOLUTION = "type_resolution"
    COMPLEXITY_METRICS = "complexity_metrics"
    DATA_FLOW = "data_flow"


@dataclass
class BackendDescriptor:
    """Backend capability declaration."""

    name: str
    supported_languages: set[str]
    capabilities: set[BackendCapability]
    precision_score: float  # 0.0-1.0
    speed_score: float  # 0.0-1.0 (higher = faster)
    prerequisites: list[str]
    factory: Callable[[], AnalysisBackend]


class BackendRegistry:
    """Backend registration center."""

    def __init__(self) -> None:
        self._backends: dict[str, BackendDescriptor] = {}

    def register(self, descriptor: BackendDescriptor) -> None:
        self._backends[descriptor.name] = descriptor
        logger.info("Registered backend: %s", descriptor.name)

    def get(self, name: str) -> BackendDescriptor | None:
        return self._backends.get(name)

    def list_all(self) -> list[BackendDescriptor]:
        return list(self._backends.values())

    def find_by_language(self, language: str) -> list[BackendDescriptor]:
        """Filter by language, sorted by precision_score descending."""
        return sorted(
            [d for d in self._backends.values() if language in d.supported_languages],
            key=lambda d: d.precision_score,
            reverse=True,
        )

    def find_by_capability(self, cap: BackendCapability) -> list[BackendDescriptor]:
        return [d for d in self._backends.values() if cap in d.capabilities]

    def find_best_backend(
        self,
        language: str,
        project_path: str,
    ) -> AnalysisBackend | None:
        """
        Find the best available backend for a language.
        Tries backends in precision order, checking prerequisites.
        """
        candidates = self.find_by_language(language)
        for desc in candidates:
            backend = desc.factory()
            missing = backend.check_prerequisites(project_path)
            if not missing:
                logger.info(
                    "Selected backend: %s (precision=%.2f)", desc.name, desc.precision_score
                )
                return backend
            logger.info(
                "Backend %s prerequisites not met: %s",
                desc.name,
                missing,
            )
        return None


def create_default_registry() -> BackendRegistry:
    """Create registry with SVF registered (v1 default)."""
    from z_code_analyzer.backends.svf_backend import SVFBackend

    registry = BackendRegistry()
    registry.register(
        BackendDescriptor(
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
    )
    return registry
