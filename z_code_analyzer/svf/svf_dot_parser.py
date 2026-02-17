"""Parse SVF callgraph DOT output into structured data.

Migrated from experiment/sast-test/pipeline/svf-analyze.py.

SVF produces two DOT files:
  - callgraph_initial.dot — direct calls only (before pointer analysis)
  - callgraph_final.dot   — all calls (after Andersen pointer analysis)

Edges present in final but NOT in initial are function-pointer-resolved (FPTR).
"""

from __future__ import annotations

import re
from collections import defaultdict


def parse_svf_dot(content: str) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Parse SVF's callgraph DOT file.

    Args:
        content: Raw content of a callgraph DOT file.

    Returns:
        nodes: {node_id: function_name}
        adj: {caller_name: {callee_name, ...}}
    """
    nodes: dict[str, str] = {}

    # SVF node format:
    # Node0x5632abc [shape=record,shape=Mrecord,
    #   label="{CallGraphNode ID: 42 \{fun: function_name\}|{<s0>...}}"];
    for m in re.finditer(r"(Node0x[0-9a-fA-F]+)\s*\[[^;]*?fun:\s*(\S+?)\\", content):
        nodes[m.group(1)] = m.group(2)

    # SVF edge format:
    # Node0x5632abc:s0 -> Node0x5632def
    adj: dict[str, set[str]] = defaultdict(set)
    for m in re.finditer(r"(Node0x[0-9a-fA-F]+)(?::s\d+)?\s*->\s*(Node0x[0-9a-fA-F]+)", content):
        src_id = m.group(1)
        dst_id = m.group(2)
        src = nodes.get(src_id)
        dst = nodes.get(dst_id)
        if src and dst and src != dst:  # filter self-loops and unknown nodes
            adj[src].add(dst)

    return nodes, adj


def get_all_function_names(nodes: dict[str, str]) -> set[str]:
    """Get all unique function names from parsed nodes."""
    return set(nodes.values())


def get_edge_list(adj: dict[str, set[str]]) -> list[tuple[str, str]]:
    """Convert adjacency dict to flat edge list of (caller, callee) tuples."""
    edges = []
    for caller, callees in sorted(adj.items()):
        for callee in sorted(callees):
            edges.append((caller, callee))
    return edges


def get_typed_edge_list(
    initial_adj: dict[str, set[str]],
    final_adj: dict[str, set[str]],
) -> list[tuple[str, str, str]]:
    """Classify edges as 'direct' or 'fptr' by diffing initial vs final graphs.

    Args:
        initial_adj: Adjacency from callgraph_initial.dot (direct calls only).
        final_adj: Adjacency from callgraph_final.dot (all calls after pointer analysis).

    Returns:
        List of (caller, callee, call_type) where call_type is 'direct' or 'fptr'.
    """
    edges: list[tuple[str, str, str]] = []
    for caller, callees in sorted(final_adj.items()):
        initial_callees = initial_adj.get(caller, set())
        for callee in sorted(callees):
            call_type = "direct" if callee in initial_callees else "fptr"
            edges.append((caller, callee, call_type))
    return edges
