"""Tests for BackendRegistry."""

from __future__ import annotations

from z_code_analyzer.backends.base import AnalysisResult, CallEdge, FunctionRecord
from z_code_analyzer.backends.merger import ResultMerger
from z_code_analyzer.backends.registry import (
    BackendCapability,
    BackendDescriptor,
    BackendRegistry,
    create_default_registry,
)
from z_code_analyzer.backends.svf_backend import SVFBackend


class TestBackendRegistry:
    def test_register_and_get(self):
        registry = BackendRegistry()
        desc = BackendDescriptor(
            name="test",
            supported_languages={"c"},
            capabilities={BackendCapability.DIRECT_CALLS},
            precision_score=0.5,
            speed_score=0.5,
            prerequisites=[],
            factory=SVFBackend,
        )
        registry.register(desc)
        assert registry.get("test") is not None
        assert registry.get("nonexistent") is None

    def test_find_by_language(self):
        registry = create_default_registry()
        results = registry.find_by_language("c")
        assert len(results) >= 1
        assert results[0].name == "svf"

    def test_find_by_language_no_match(self):
        registry = create_default_registry()
        results = registry.find_by_language("java")
        assert len(results) == 0

    def test_find_by_capability(self):
        registry = create_default_registry()
        results = registry.find_by_capability(BackendCapability.FUNCTION_POINTERS)
        assert len(results) >= 1
        assert any(d.name == "svf" for d in results)

    def test_precision_ordering(self):
        registry = BackendRegistry()
        registry.register(
            BackendDescriptor(
                name="low",
                supported_languages={"c"},
                capabilities=set(),
                precision_score=0.5,
                speed_score=0.9,
                prerequisites=[],
                factory=SVFBackend,
            )
        )
        registry.register(
            BackendDescriptor(
                name="high",
                supported_languages={"c"},
                capabilities=set(),
                precision_score=0.95,
                speed_score=0.3,
                prerequisites=[],
                factory=SVFBackend,
            )
        )
        results = registry.find_by_language("c")
        assert results[0].name == "high"
        assert results[1].name == "low"

    def test_list_all(self):
        registry = create_default_registry()
        all_backends = registry.list_all()
        assert len(all_backends) >= 1

    def test_default_registry_has_svf(self):
        registry = create_default_registry()
        svf = registry.get("svf")
        assert svf is not None
        assert svf.precision_score == 0.98
        assert "c" in svf.supported_languages
        assert "cpp" in svf.supported_languages


class TestResultMerger:
    def test_single_result_passthrough(self):
        result = AnalysisResult(
            functions=[
                FunctionRecord(name="foo", file_path="a.c", start_line=1, end_line=10, content="", language="c")
            ],
            edges=[],
            language="c",
            backend="svf",
        )
        merger = ResultMerger()
        merged = merger.merge([result])
        assert merged is result

    def test_empty_raises(self):
        merger = ResultMerger()
        import pytest

        with pytest.raises(ValueError):
            merger.merge([])
