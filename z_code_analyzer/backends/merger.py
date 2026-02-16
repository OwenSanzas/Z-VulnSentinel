"""Result merger — v1 only implements single-backend passthrough."""

from __future__ import annotations

from z_code_analyzer.backends.base import AnalysisResult


class ResultMerger:
    """
    Merge results from multiple backends.
    v1: single backend passthrough (no actual merging needed).
    v2: will merge SVF + Joern results with conflict resolution.
    """

    @staticmethod
    def merge(
        results: list[AnalysisResult],
        priority_order: list[str] | None = None,
    ) -> AnalysisResult:
        """Merge multiple AnalysisResults into one.

        Args:
            results: Analysis results to merge.
            priority_order: Backend priority (highest precision first).
                v1 ignores this (single backend passthrough).
        """
        if not results:
            raise ValueError("No results to merge")

        if len(results) == 1:
            return results[0]

        # v2: implement proper merging with confidence-based conflict resolution
        # For now, just use the first (highest precision) result
        primary = results[0]
        return AnalysisResult(
            functions=primary.functions,
            edges=primary.edges,
            language=primary.language,
            backend="+".join(r.backend for r in results),
            analysis_duration_seconds=sum(r.analysis_duration_seconds for r in results),
            warnings=sum((r.warnings for r in results), []),
            metadata={"merged_from": [r.backend for r in results]},
        )
