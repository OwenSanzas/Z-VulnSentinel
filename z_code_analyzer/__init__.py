"""Z-Code-Analyzer-Station: Multi-backend static analysis engine."""

__version__ = "0.1.0"

from z_code_analyzer.api import (
    CodeAnalyzer,
    SeedTreeRequest,
    SeedTreeResult,
    SnapshotRequest,
    VulnImpactRequest,
    VulnImpactResult,
)
from z_code_analyzer.backends.base import (
    AnalysisBackend,
    AnalysisResult,
    CallEdge,
    CallType,
    FunctionRecord,
)
from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.orchestrator import StaticAnalysisOrchestrator
from z_code_analyzer.reachability import ReachabilityChecker, ReachabilityResult
from z_code_analyzer.snapshot_manager import SnapshotManager

__all__ = [
    "AnalysisBackend",
    "AnalysisResult",
    "CallEdge",
    "CallType",
    "CodeAnalyzer",
    "FunctionRecord",
    "GraphStore",
    "ReachabilityChecker",
    "ReachabilityResult",
    "SeedTreeRequest",
    "SeedTreeResult",
    "SnapshotManager",
    "SnapshotRequest",
    "StaticAnalysisOrchestrator",
    "VulnImpactRequest",
    "VulnImpactResult",
]
