"""Tests for StaticAnalysisOrchestrator.

Integration tests that exercise analyze_full() path:
  mock AnalysisResult -> orchestrator -> Neo4j -> verify graph data.
Requires Neo4j and MongoDB running.
"""

from __future__ import annotations

import os

import pytest
from bson import ObjectId

from z_code_analyzer.backends.base import (
    AnalysisResult,
    CallEdge,
    CallType,
    FunctionRecord,
)
from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.orchestrator import AnalysisOutput, StaticAnalysisOrchestrator
from z_code_analyzer.snapshot_manager import SnapshotManager

needs_neo4j = pytest.mark.skipif(
    os.environ.get("SKIP_NEO4J", "0") == "1",
    reason="Neo4j not available",
)


def _make_graph_store(neo4j_uri, neo4j_auth):
    """Create and connect a GraphStore."""
    gs = GraphStore()
    gs.connect(neo4j_uri, neo4j_auth)
    return gs


def _make_mock_result() -> AnalysisResult:
    """Create a realistic mock AnalysisResult (simulates SVF output)."""
    return AnalysisResult(
        functions=[
            FunctionRecord(
                name="main", file_path="src/main.c", start_line=10, end_line=30,
                content="int main() { parse_input(); }", language="c",
            ),
            FunctionRecord(
                name="parse_input", file_path="src/parser.c", start_line=5, end_line=50,
                content="void parse_input() { lex(); validate(); }", language="c",
            ),
            FunctionRecord(
                name="lex", file_path="src/lexer.c", start_line=1, end_line=20,
                content="Token lex() { ... }", language="c",
            ),
            FunctionRecord(
                name="validate", file_path="src/validator.c", start_line=1, end_line=15,
                content="bool validate() { ... }", language="c",
            ),
            FunctionRecord(
                name="callback_handler", file_path="src/handler.c", start_line=1, end_line=10,
                content="void callback_handler() { ... }", language="c",
            ),
            # External function (no file_path)
            FunctionRecord(
                name="malloc", file_path="", start_line=0, end_line=0,
                content="", language="c",
            ),
        ],
        edges=[
            CallEdge(caller="main", callee="parse_input", call_type=CallType.DIRECT,
                     caller_file="src/main.c", callee_file="src/parser.c"),
            CallEdge(caller="parse_input", callee="lex", call_type=CallType.DIRECT,
                     caller_file="src/parser.c", callee_file="src/lexer.c"),
            CallEdge(caller="parse_input", callee="validate", call_type=CallType.DIRECT,
                     caller_file="src/parser.c", callee_file="src/validator.c"),
            # Function pointer resolved by SVF
            CallEdge(caller="parse_input", callee="callback_handler", call_type=CallType.FPTR,
                     caller_file="src/parser.c", callee_file="src/handler.c"),
            CallEdge(caller="lex", callee="malloc", call_type=CallType.DIRECT,
                     caller_file="src/lexer.c", callee_file=""),
        ],
        language="c",
        backend="svf",
        analysis_duration_seconds=1.5,
        metadata={"fptr_edge_count": 1},
    )


@needs_neo4j
class TestOrchestratorAnalyzeFull:
    """Test analyze_full() — the path where SVF has already been run externally."""

    @pytest.fixture(autouse=True)
    def setup(self, neo4j_uri, neo4j_auth, mongo_uri):
        self.snapshot_id = str(ObjectId())
        self.gs = _make_graph_store(neo4j_uri, neo4j_auth)
        self.sm = SnapshotManager(mongo_uri=mongo_uri, graph_store=self.gs)
        self.orch = StaticAnalysisOrchestrator(
            snapshot_manager=self.sm, graph_store=self.gs
        )
        yield
        # Cleanup
        self.gs.delete_snapshot(self.snapshot_id)
        self.gs.close()
        # Clean up MongoDB snapshot document
        self.sm._snapshots.delete_many({"_id": ObjectId(self.snapshot_id)})
        self.sm.close()

    def test_analyze_full_end_to_end(self, tmp_path):
        """Full pipeline: mock result -> Neo4j import -> verify graph."""
        # Create a fuzzer source file
        fuzz_dir = tmp_path / "fuzz"
        fuzz_dir.mkdir()
        fuzz_file = fuzz_dir / "fuzz_parse.c"
        fuzz_file.write_text(
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
            '    parse_input();\n'
            '    return 0;\n'
            '}\n'
        )

        result = _make_mock_result()
        fuzzer_sources = {"fuzz_parse": ["fuzz/fuzz_parse.c"]}

        output = self.orch.analyze_full(
            project_path=str(tmp_path),
            repo_url="https://github.com/test/project",
            version="v1.0",
            fuzzer_sources=fuzzer_sources,
            result=result,
            snapshot_id=self.snapshot_id,
        )

        # Verify output
        assert isinstance(output, AnalysisOutput)
        assert output.snapshot_id == self.snapshot_id
        assert output.backend == "svf"
        assert output.function_count == 6  # 5 library + 1 external
        assert output.edge_count == 5
        assert output.fuzzer_names == ["fuzz_parse"]
        assert output.cached is False

    def test_functions_in_neo4j(self, tmp_path):
        """Verify function nodes are correctly stored in Neo4j."""
        fuzz_dir = tmp_path / "fuzz"
        fuzz_dir.mkdir()
        (fuzz_dir / "fuzz_parse.c").write_text(
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
            '    parse_input();\n'
            '    return 0;\n'
            '}\n'
        )

        self.orch.analyze_full(
            project_path=str(tmp_path),
            repo_url="https://github.com/test/project",
            version="v1.0",
            fuzzer_sources={"fuzz_parse": ["fuzz/fuzz_parse.c"]},
            result=_make_mock_result(),
            snapshot_id=self.snapshot_id,
        )

        # Query functions
        meta = self.gs.get_function_metadata(self.snapshot_id, "parse_input")
        assert meta is not None
        assert meta["file_path"] == "src/parser.c"
        assert meta["start_line"] == 5

        # External function
        ext = self.gs.get_function_metadata(self.snapshot_id, "malloc")
        assert ext is not None
        assert ext["is_external"] is True

        # External function list
        externals = self.gs.list_external_function_names(self.snapshot_id)
        assert "malloc" in externals

    def test_call_edges_in_neo4j(self, tmp_path):
        """Verify call edges including FPTR type."""
        fuzz_dir = tmp_path / "fuzz"
        fuzz_dir.mkdir()
        (fuzz_dir / "fuzz_parse.c").write_text(
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
            '    parse_input();\n'
            '    return 0;\n'
            '}\n'
        )

        self.orch.analyze_full(
            project_path=str(tmp_path),
            repo_url="https://github.com/test/project",
            version="v1.0",
            fuzzer_sources={"fuzz_parse": ["fuzz/fuzz_parse.c"]},
            result=_make_mock_result(),
            snapshot_id=self.snapshot_id,
        )

        # Check callees of parse_input
        callees = self.gs.get_callees(self.snapshot_id, "parse_input")
        callee_names = {c["name"] for c in callees}
        assert "lex" in callee_names
        assert "validate" in callee_names
        assert "callback_handler" in callee_names

        # Verify FPTR edge
        fptr_edges = [c for c in callees if c["call_type"] == "fptr"]
        assert len(fptr_edges) == 1
        assert fptr_edges[0]["name"] == "callback_handler"

    def test_fuzzer_and_reaches(self, tmp_path):
        """Verify fuzzer node, ENTRY edge, and REACHES computation."""
        fuzz_dir = tmp_path / "fuzz"
        fuzz_dir.mkdir()
        (fuzz_dir / "fuzz_parse.c").write_text(
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
            '    parse_input();\n'
            '    return 0;\n'
            '}\n'
        )

        self.orch.analyze_full(
            project_path=str(tmp_path),
            repo_url="https://github.com/test/project",
            version="v1.0",
            fuzzer_sources={"fuzz_parse": ["fuzz/fuzz_parse.c"]},
            result=_make_mock_result(),
            snapshot_id=self.snapshot_id,
        )

        # Check fuzzer metadata
        fz = self.gs.get_fuzzer_metadata(self.snapshot_id, "fuzz_parse")
        assert fz is not None
        assert fz["entry_function"] == "LLVMFuzzerTestOneInput"

        # Check REACHES edges
        reached = self.gs.reachable_functions_by_one_fuzzer(
            self.snapshot_id, "fuzz_parse"
        )
        reached_names = {r["name"] for r in reached}

        # LLVMFuzzerTestOneInput calls parse_input (depth 1)
        assert "parse_input" in reached_names
        # parse_input calls lex, validate, callback_handler (depth 2)
        assert "lex" in reached_names
        assert "validate" in reached_names
        assert "callback_handler" in reached_names
        # lex calls malloc (depth 3)
        assert "malloc" in reached_names

        # Verify depths
        depth_map = {r["name"]: r["depth"] for r in reached}
        assert depth_map["parse_input"] == 1
        assert depth_map["lex"] == 2
        assert depth_map["malloc"] == 3

    def test_shortest_path(self, tmp_path):
        """Verify shortest_path query works through the graph."""
        fuzz_dir = tmp_path / "fuzz"
        fuzz_dir.mkdir()
        (fuzz_dir / "fuzz_parse.c").write_text(
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
            '    parse_input();\n'
            '    return 0;\n'
            '}\n'
        )

        self.orch.analyze_full(
            project_path=str(tmp_path),
            repo_url="https://github.com/test/project",
            version="v1.0",
            fuzzer_sources={"fuzz_parse": ["fuzz/fuzz_parse.c"]},
            result=_make_mock_result(),
            snapshot_id=self.snapshot_id,
        )

        # main -> parse_input -> lex -> malloc (length 3)
        path = self.gs.shortest_path(self.snapshot_id, "main", "malloc")
        assert path is not None
        assert path["length"] == 3

    def test_snapshot_statistics(self, tmp_path):
        """Verify snapshot statistics are computed correctly."""
        fuzz_dir = tmp_path / "fuzz"
        fuzz_dir.mkdir()
        (fuzz_dir / "fuzz_parse.c").write_text(
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
            '    parse_input();\n'
            '    return 0;\n'
            '}\n'
        )

        self.orch.analyze_full(
            project_path=str(tmp_path),
            repo_url="https://github.com/test/project",
            version="v1.0",
            fuzzer_sources={"fuzz_parse": ["fuzz/fuzz_parse.c"]},
            result=_make_mock_result(),
            snapshot_id=self.snapshot_id,
        )

        stats = self.gs.get_snapshot_statistics(self.snapshot_id)
        # 6 library functions + 1 LLVMFuzzerTestOneInput entry = 7
        assert stats["function_count"] == 7
        assert stats["edge_count"] >= 5
        assert stats["fuzzer_count"] == 1
        assert stats["external_function_count"] == 1
        # REACHES edges: 5 reachable functions from fuzz_parse
        assert stats["reach_count"] >= 5
        assert stats["max_depth"] >= 3  # main->parse_input->lex->malloc
