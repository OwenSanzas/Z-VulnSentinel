"""Tests for SVF backend.

Unit tests (DOT parser) run without Docker.
Integration tests require Docker + svftools/svf image.
"""

from __future__ import annotations

import os

import pytest

from z_code_analyzer.backends.svf_backend import SVFBackend
from z_code_analyzer.svf.svf_dot_parser import (
    get_all_function_names,
    get_edge_list,
    get_typed_edge_list,
    parse_svf_dot,
)

# Sample SVF DOT content (simplified from real libpng output)
SAMPLE_DOT = """
digraph "Call Graph" {
    label="Call Graph";

    Node0x1001 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 1 \\{fun: main\\}|{<s0>CallSite0}}"];
    Node0x1002 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 2 \\{fun: png_read_data\\}|{<s0>CallSite0}}"];
    Node0x1003 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 3 \\{fun: user_read_data\\}|{<s0>CallSite0}}"];
    Node0x1004 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 4 \\{fun: malloc\\}|{<s0>CallSite0}}"];
    Node0x1005 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 5 \\{fun: helper\\}|{<s0>CallSite0}}"];

    Node0x1001:s0 -> Node0x1002
    Node0x1001:s0 -> Node0x1005
    Node0x1002:s0 -> Node0x1003
    Node0x1002:s0 -> Node0x1004
    Node0x1005:s0 -> Node0x1004
}
"""

# Same graph but without the fptr-resolved edge (png_read_data -> user_read_data)
SAMPLE_INITIAL_DOT = """
digraph "Call Graph" {
    label="Call Graph";

    Node0x1001 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 1 \\{fun: main\\}|{<s0>CallSite0}}"];
    Node0x1002 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 2 \\{fun: png_read_data\\}|{<s0>CallSite0}}"];
    Node0x1003 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 3 \\{fun: user_read_data\\}|{<s0>CallSite0}}"];
    Node0x1004 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 4 \\{fun: malloc\\}|{<s0>CallSite0}}"];
    Node0x1005 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 5 \\{fun: helper\\}|{<s0>CallSite0}}"];

    Node0x1001:s0 -> Node0x1002
    Node0x1001:s0 -> Node0x1005
    Node0x1002:s0 -> Node0x1004
    Node0x1005:s0 -> Node0x1004
}
"""

needs_docker = pytest.mark.skipif(
    os.environ.get("SKIP_DOCKER", "1") == "1",
    reason="Docker not available (set SKIP_DOCKER=0 to run)",
)


class TestSVFDotParser:
    """Unit tests for DOT parser — no Docker needed."""

    def test_parse_nodes(self):
        nodes, adj = parse_svf_dot(SAMPLE_DOT)
        names = set(nodes.values())
        assert "main" in names
        assert "png_read_data" in names
        assert "user_read_data" in names
        assert "malloc" in names
        assert "helper" in names
        assert len(names) == 5

    def test_parse_edges(self):
        nodes, adj = parse_svf_dot(SAMPLE_DOT)
        assert "png_read_data" in adj["main"]
        assert "helper" in adj["main"]
        assert "user_read_data" in adj["png_read_data"]
        assert "malloc" in adj["png_read_data"]
        assert "malloc" in adj["helper"]

    def test_no_self_loops(self):
        dot = """
        digraph "Call Graph" {
            Node0x1 [shape=record,shape=Mrecord, label="{CallGraphNode ID: 1 \\{fun: foo\\}|{<s0>}}"];
            Node0x1:s0 -> Node0x1
        }
        """
        nodes, adj = parse_svf_dot(dot)
        assert "foo" not in adj.get("foo", set())

    def test_get_all_function_names(self):
        nodes, _ = parse_svf_dot(SAMPLE_DOT)
        names = get_all_function_names(nodes)
        assert len(names) == 5

    def test_get_edge_list(self):
        _, adj = parse_svf_dot(SAMPLE_DOT)
        edges = get_edge_list(adj)
        assert len(edges) == 5
        assert ("main", "png_read_data") in edges
        assert ("png_read_data", "user_read_data") in edges

    def test_empty_dot(self):
        nodes, adj = parse_svf_dot("")
        assert len(nodes) == 0
        assert len(adj) == 0

    def test_typed_edge_list_direct_vs_fptr(self):
        """Edges in final but not initial should be classified as fptr."""
        _, initial_adj = parse_svf_dot(SAMPLE_INITIAL_DOT)
        _, final_adj = parse_svf_dot(SAMPLE_DOT)

        typed = get_typed_edge_list(initial_adj, final_adj)

        # Build lookup: (caller, callee) -> call_type
        type_map = {(c, e): ct for c, e, ct in typed}

        # png_read_data -> user_read_data is only in final (fptr)
        assert type_map[("png_read_data", "user_read_data")] == "fptr"
        # main -> png_read_data is in both (direct)
        assert type_map[("main", "png_read_data")] == "direct"
        # main -> helper is in both (direct)
        assert type_map[("main", "helper")] == "direct"
        # png_read_data -> malloc is in both (direct)
        assert type_map[("png_read_data", "malloc")] == "direct"

    def test_typed_edge_list_all_direct_when_same(self):
        """When initial == final, all edges should be direct."""
        _, adj = parse_svf_dot(SAMPLE_DOT)
        typed = get_typed_edge_list(adj, adj)
        assert all(ct == "direct" for _, _, ct in typed)


class TestSVFBackend:
    """Unit tests for SVFBackend methods that don't require Docker."""

    def test_name_and_languages(self):
        backend = SVFBackend()
        assert backend.name == "svf"
        assert "c" in backend.supported_languages
        assert "cpp" in backend.supported_languages

    def test_analyze_missing_bc_path(self):
        backend = SVFBackend()
        from z_code_analyzer.exceptions import SVFError

        with pytest.raises(SVFError, match="bc_path is required"):
            backend.analyze("/tmp", "c")

    def test_analyze_nonexistent_bc(self):
        backend = SVFBackend()
        from z_code_analyzer.exceptions import SVFError

        with pytest.raises(SVFError, match="not found"):
            backend.analyze("/tmp", "c", bc_path="/nonexistent/library.bc")


@needs_docker
class TestSVFBackendIntegration:
    """Integration tests — require Docker + svftools/svf image."""

    def test_check_prerequisites(self):
        backend = SVFBackend()
        missing = backend.check_prerequisites("/tmp")
        # If Docker is available and image pulled, should be empty
        if missing:
            pytest.skip(f"Prerequisites missing: {missing}")
