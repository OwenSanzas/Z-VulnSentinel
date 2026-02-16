"""Tests for GraphStore — requires a running Neo4j instance.

Run: docker compose up -d neo4j
     pytest tests/test_graph_store.py -v
"""

from __future__ import annotations

import os
import uuid

import pytest

from z_code_analyzer.backends.base import CallEdge, CallType, FunctionRecord, FuzzerInfo
from z_code_analyzer.exceptions import AmbiguousFunctionError
from z_code_analyzer.graph_store import GraphStore

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
# Default: no auth (matches docker-compose.yml NEO4J_AUTH=none)
_neo4j_auth_env = os.environ.get("NEO4J_AUTH", "none")
if _neo4j_auth_env.lower() == "none":
    NEO4J_AUTH = None
elif ":" in _neo4j_auth_env:
    NEO4J_AUTH = tuple(_neo4j_auth_env.split(":", 1))
else:
    NEO4J_AUTH = (
        os.environ.get("NEO4J_USER", "neo4j"),
        os.environ.get("NEO4J_PASSWORD", "testpassword"),
    )

needs_neo4j = pytest.mark.skipif(
    os.environ.get("SKIP_NEO4J", "0") == "1",
    reason="Neo4j not available (set SKIP_NEO4J=0 to run)",
)


@pytest.fixture
def store():
    gs = GraphStore()
    gs.connect(NEO4J_URI, NEO4J_AUTH)
    yield gs
    gs.close()


@pytest.fixture
def snapshot_id(store: GraphStore):
    """Create a unique snapshot for each test, clean up after."""
    sid = f"test-{uuid.uuid4().hex[:12]}"
    yield sid
    store.delete_snapshot(sid)


def _make_functions() -> list[FunctionRecord]:
    return [
        FunctionRecord(
            name="main_func",
            file_path="src/main.c",
            start_line=10,
            end_line=50,
            content="void main_func() { ... }",
            language="c",
            cyclomatic_complexity=5,
        ),
        FunctionRecord(
            name="helper_a",
            file_path="src/helper.c",
            start_line=1,
            end_line=20,
            content="int helper_a() { ... }",
            language="c",
            cyclomatic_complexity=3,
        ),
        FunctionRecord(
            name="helper_b",
            file_path="src/helper.c",
            start_line=25,
            end_line=40,
            content="int helper_b() { ... }",
            language="c",
            cyclomatic_complexity=2,
        ),
        FunctionRecord(
            name="deep_func",
            file_path="src/deep.c",
            start_line=1,
            end_line=10,
            content="void deep_func() { ... }",
            language="c",
        ),
        # External function (no file_path, no content)
        FunctionRecord(
            name="malloc",
            file_path="",
            start_line=0,
            end_line=0,
            content="",
            language="c",
        ),
    ]


def _make_edges() -> list[CallEdge]:
    return [
        CallEdge(caller="main_func", callee="helper_a", call_type=CallType.DIRECT, source_backend="svf"),
        CallEdge(caller="main_func", callee="helper_b", call_type=CallType.FPTR, source_backend="svf"),
        CallEdge(caller="helper_a", callee="deep_func", call_type=CallType.DIRECT, source_backend="svf"),
        CallEdge(caller="helper_b", callee="malloc", call_type=CallType.DIRECT, source_backend="svf"),
    ]


def _make_fuzzer() -> FuzzerInfo:
    return FuzzerInfo(
        name="test_fuzzer",
        entry_function="LLVMFuzzerTestOneInput",
        files=[{"path": "fuzz/fuzz_test.c", "source": "user"}],
        called_library_functions=["main_func"],
        focus="test",
    )


def _populate(store: GraphStore, sid: str):
    """Create a standard test graph."""
    store.create_snapshot_node(sid, "https://github.com/test/repo", "v1.0", "svf")
    store.import_functions(sid, _make_functions())
    store.import_edges(sid, _make_edges())
    store.import_fuzzers(sid, [_make_fuzzer()])
    # Compute reaches: fuzzer -> main_func (depth 1), main_func -> helper_a (depth 2),
    #                  main_func -> helper_b (depth 2), helper_a -> deep_func (depth 3),
    #                  helper_b -> malloc (depth 3)
    reaches = [
        {"fuzzer_name": "test_fuzzer", "function_name": "main_func", "depth": 1},
        {"fuzzer_name": "test_fuzzer", "function_name": "helper_a", "depth": 2},
        {"fuzzer_name": "test_fuzzer", "function_name": "helper_b", "depth": 2},
        {"fuzzer_name": "test_fuzzer", "function_name": "deep_func", "depth": 3},
        {"fuzzer_name": "test_fuzzer", "function_name": "malloc", "depth": 3},
    ]
    store.import_reaches(sid, reaches)


# ── Write + Read Tests ──


@needs_neo4j
class TestWriteAndQuery:
    def test_import_functions(self, store: GraphStore, snapshot_id: str):
        store.create_snapshot_node(snapshot_id, "https://github.com/t/r", "v1", "svf")
        count = store.import_functions(snapshot_id, _make_functions())
        assert count == 5

    def test_import_edges(self, store: GraphStore, snapshot_id: str):
        store.create_snapshot_node(snapshot_id, "https://github.com/t/r", "v1", "svf")
        store.import_functions(snapshot_id, _make_functions())
        count = store.import_edges(snapshot_id, _make_edges())
        assert count == 4

    def test_get_function_metadata(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        meta = store.get_function_metadata(snapshot_id, "main_func")
        assert meta is not None
        assert meta["name"] == "main_func"
        assert meta["file_path"] == "src/main.c"
        assert meta["start_line"] == 10
        assert meta["cyclomatic_complexity"] == 5

    def test_get_function_metadata_not_found(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        assert store.get_function_metadata(snapshot_id, "nonexistent") is None

    def test_list_function_info_by_file(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        funcs = store.list_function_info_by_file(snapshot_id, "src/helper.c")
        assert len(funcs) == 2
        names = {f["name"] for f in funcs}
        assert names == {"helper_a", "helper_b"}

    def test_search_functions(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        results = store.search_functions(snapshot_id, "helper_*")
        assert len(results) == 2
        names = {r["name"] for r in results}
        assert names == {"helper_a", "helper_b"}

    def test_search_functions_wildcard(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        results = store.search_functions(snapshot_id, "*func*")
        names = {r["name"] for r in results}
        assert "main_func" in names
        assert "deep_func" in names

    def test_external_functions(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        externals = store.list_external_function_names(snapshot_id)
        assert "malloc" in externals

    def test_get_function_metadata_external(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        meta = store.get_function_metadata(snapshot_id, "malloc")
        assert meta is not None
        assert meta["is_external"] is True


# ── Call Relation Tests ──


@needs_neo4j
class TestCallRelations:
    def test_get_callees(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        callees = store.get_callees(snapshot_id, "main_func")
        names = {c["name"] for c in callees}
        assert "helper_a" in names
        assert "helper_b" in names

    def test_get_callees_with_call_type(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        callees = store.get_callees(snapshot_id, "main_func")
        by_name = {c["name"]: c for c in callees}
        assert by_name["helper_a"]["call_type"] == "direct"
        assert by_name["helper_b"]["call_type"] == "fptr"

    def test_get_callers(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        callers = store.get_callers(snapshot_id, "helper_a")
        names = {c["name"] for c in callers}
        assert "main_func" in names

    def test_shortest_path(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        # main_func -> helper_a -> deep_func (length 2)
        result = store.shortest_path(snapshot_id, "main_func", "deep_func")
        assert result is not None
        assert result["length"] == 2
        assert len(result["paths"]) >= 1
        path_names = [n["name"] for n in result["paths"][0]["path"]]
        assert path_names == ["main_func", "helper_a", "deep_func"]

    def test_shortest_path_not_reachable(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        result = store.shortest_path(snapshot_id, "deep_func", "main_func")
        assert result is None

    def test_get_all_paths(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        result = store.get_all_paths(snapshot_id, "main_func", "malloc")
        assert result is not None
        assert result["paths_found"] >= 1
        # main_func -> helper_b -> malloc (length 2)
        shortest = result["paths"][0]
        assert shortest["length"] == 2

    def test_get_subtree(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        subtree = store.get_subtree(snapshot_id, "main_func", depth=2)
        node_names = {n["name"] for n in subtree["nodes"]}
        assert "main_func" in node_names
        assert "helper_a" in node_names
        assert "helper_b" in node_names
        assert "deep_func" in node_names
        assert len(subtree["edges"]) >= 3

    def test_get_subtree_depth_boundary(self, store: GraphStore, snapshot_id: str):
        """depth=1 should exclude nodes at depth 2 (deep_func, malloc)."""
        _populate(store, snapshot_id)
        subtree = store.get_subtree(snapshot_id, "main_func", depth=1)
        node_names = {n["name"] for n in subtree["nodes"]}
        assert "main_func" in node_names
        assert "helper_a" in node_names
        assert "helper_b" in node_names
        # deep_func and malloc are at depth 2 — should be excluded
        assert "deep_func" not in node_names
        assert "malloc" not in node_names


# ── Fuzzer Tests ──


@needs_neo4j
class TestFuzzer:
    def test_import_fuzzers(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        fuzzers = store.list_fuzzer_info_no_code(snapshot_id)
        assert len(fuzzers) == 1
        assert fuzzers[0]["name"] == "test_fuzzer"
        # files must be a parsed list of dicts, not a JSON string
        files = fuzzers[0]["files"]
        assert isinstance(files, list), f"files should be list, got {type(files)}"
        assert len(files) == 1
        assert isinstance(files[0], dict)
        assert files[0]["path"] == "fuzz/fuzz_test.c"

    def test_get_fuzzer_metadata(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        meta = store.get_fuzzer_metadata(snapshot_id, "test_fuzzer")
        assert meta is not None
        assert meta["name"] == "test_fuzzer"
        assert meta["entry_function"] == "LLVMFuzzerTestOneInput"
        # files must be a parsed list of dicts, not a JSON string
        files = meta["files"]
        assert isinstance(files, list), f"files should be list, got {type(files)}"

    def test_entry_function_has_parameters(self, store: GraphStore, snapshot_id: str):
        """LLVMFuzzerTestOneInput nodes created by import_fuzzers should have parameters."""
        _populate(store, snapshot_id)
        meta = store.get_function_metadata(
            snapshot_id, "LLVMFuzzerTestOneInput", file_path="fuzz/fuzz_test.c"
        )
        assert meta is not None
        assert meta["return_type"] == "int"
        assert isinstance(meta["parameters"], list)
        assert len(meta["parameters"]) == 2

    def test_reachable_functions(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        reachable = store.reachable_functions_by_one_fuzzer(snapshot_id, "test_fuzzer")
        names = {r["name"] for r in reachable}
        assert "main_func" in names
        assert "helper_a" in names
        assert "deep_func" in names

    def test_reachable_by_depth(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        reachable = store.reachable_functions_by_one_fuzzer(
            snapshot_id, "test_fuzzer", max_depth=2
        )
        names = {r["name"] for r in reachable}
        assert "main_func" in names  # depth 1
        assert "helper_a" in names  # depth 2
        assert "deep_func" not in names  # depth 3

    def test_unreached_functions(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        unreached = store.unreached_functions_by_all_fuzzers(snapshot_id)
        unreached_names = {u["name"] for u in unreached}
        # All non-external, non-entry functions are reached in our test graph
        assert "LLVMFuzzerTestOneInput" not in unreached_names
        # The unreached set should be empty (all library functions are reachable)
        assert len(unreached) == 0


# ── Snapshot Tests ──


@needs_neo4j
class TestSnapshot:
    def test_snapshot_statistics(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        stats = store.get_snapshot_statistics(snapshot_id)
        # 5 original functions + 1 LLVMFuzzerTestOneInput = 6
        assert stats["function_count"] == 6
        assert stats["external_function_count"] == 1
        assert stats["edge_count"] >= 4
        assert stats["fuzzer_count"] == 1
        assert stats["reach_count"] >= 3  # at least main_func, helper_a, deep_func
        assert stats["max_depth"] == 3

    def test_delete_snapshot(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        store.delete_snapshot(snapshot_id)
        # Verify nothing remains
        assert store.get_function_metadata(snapshot_id, "main_func") is None
        stats = store.get_snapshot_statistics(snapshot_id)
        assert stats.get("function_count", 0) == 0


# ── Disambiguation Tests ──


@needs_neo4j
class TestDisambiguation:
    def test_ambiguous_function_error(self, store: GraphStore, snapshot_id: str):
        """Two functions with the same name in different files should raise error without file_path."""
        store.create_snapshot_node(snapshot_id, "https://github.com/t/r", "v1", "svf")
        funcs = [
            FunctionRecord(
                name="init", file_path="src/a.c", start_line=1, end_line=10,
                content="void init() {}", language="c",
            ),
            FunctionRecord(
                name="init", file_path="src/b.c", start_line=1, end_line=10,
                content="void init() {}", language="c",
            ),
        ]
        store.import_functions(snapshot_id, funcs)

        with pytest.raises(AmbiguousFunctionError) as exc_info:
            store.get_function_metadata(snapshot_id, "init")
        assert "src/a.c" in str(exc_info.value) or "src/b.c" in str(exc_info.value)

    def test_disambiguate_with_file_path(self, store: GraphStore, snapshot_id: str):
        store.create_snapshot_node(snapshot_id, "https://github.com/t/r", "v1", "svf")
        funcs = [
            FunctionRecord(
                name="init", file_path="src/a.c", start_line=1, end_line=10,
                content="void init() { /* a */ }", language="c",
            ),
            FunctionRecord(
                name="init", file_path="src/b.c", start_line=1, end_line=10,
                content="void init() { /* b */ }", language="c",
            ),
        ]
        store.import_functions(snapshot_id, funcs)

        meta = store.get_function_metadata(snapshot_id, "init", file_path="src/a.c")
        assert meta is not None
        assert "a" in meta["content"]


# ── Health Check ──


@needs_neo4j
class TestHealthCheck:
    def test_health_check(self, store: GraphStore):
        assert store.health_check() is True

    def test_health_check_disconnected(self):
        gs = GraphStore()
        assert gs.health_check() is False


# ── Raw Query ──


@needs_neo4j
class TestRawQuery:
    def test_raw_query(self, store: GraphStore, snapshot_id: str):
        _populate(store, snapshot_id)
        results = store.raw_query(
            "MATCH (f:Function {snapshot_id: $sid}) RETURN f.name AS name LIMIT 3",
            {"sid": snapshot_id},
        )
        assert len(results) > 0
        assert "name" in results[0]
