"""Neo4j graph storage layer for call graph data."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from neo4j import GraphDatabase

from z_code_analyzer.backends.base import CallEdge, FunctionRecord, FuzzerInfo
from z_code_analyzer.exceptions import AmbiguousFunctionError

logger = logging.getLogger(__name__)

# Batch size for UNWIND operations
_BATCH_SIZE = 500

# Hard safety cap for variable-length path queries to prevent Neo4j OOM
_MAX_PATH_DEPTH = 50


class GraphStore:
    """
    Neo4j graph storage layer.
    All queries are scoped by snapshot_id to isolate different versions.
    """

    def __init__(self) -> None:
        self._driver = None

    # ── Connection Management ──

    def connect(self, uri: str, auth: tuple[str, str]) -> None:
        self._driver = GraphDatabase.driver(uri, auth=auth)
        self._ensure_indexes()

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None

    def health_check(self) -> bool:
        if not self._driver:
            return False
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def _ensure_indexes(self) -> None:
        """Create indexes if they don't exist."""
        queries = [
            "CREATE INDEX IF NOT EXISTS FOR (s:Snapshot) ON (s.id)",
            "CREATE INDEX IF NOT EXISTS FOR (f:Function) ON (f.snapshot_id)",
            "CREATE INDEX IF NOT EXISTS FOR (f:Function) ON (f.snapshot_id, f.name)",
            "CREATE INDEX IF NOT EXISTS FOR (f:Function) ON (f.snapshot_id, f.file_path)",
            "CREATE INDEX IF NOT EXISTS FOR (fz:Fuzzer) ON (fz.snapshot_id)",
            "CREATE INDEX IF NOT EXISTS FOR (fz:Fuzzer) ON (fz.snapshot_id, fz.name)",
        ]
        with self._driver.session() as session:
            for q in queries:
                session.run(q)

    def _session(self):
        if not self._driver:
            raise RuntimeError("GraphStore not connected. Call connect() first.")
        return self._driver.session()

    # ── Write Operations ──

    def create_snapshot_node(
        self, snapshot_id: str, repo_url: str, version: str, backend: str
    ) -> None:
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1] if "/" in repo_url else repo_url
        with self._session() as session:
            session.run(
                """
                CREATE (s:Snapshot {
                    id: $sid,
                    repo_name: $repo_name,
                    repo_url: $repo_url,
                    version: $version,
                    backend: $backend,
                    created_at: $created_at
                })
                """,
                sid=snapshot_id,
                repo_name=repo_name,
                repo_url=repo_url,
                version=version,
                backend=backend,
                created_at=datetime.now(timezone.utc).isoformat(),
            )

    def import_functions(self, snapshot_id: str, functions: list[FunctionRecord]) -> int:
        """Batch create :Function nodes + (:Snapshot)-[:CONTAINS]->(:Function) edges."""
        if not functions:
            return 0

        count = 0
        with self._session() as session:
            for i in range(0, len(functions), _BATCH_SIZE):
                batch = functions[i : i + _BATCH_SIZE]
                params = []
                for f in batch:
                    is_external = not f.file_path and not f.content
                    params.append(
                        {
                            "name": f.name,
                            "file_path": f.file_path or None,
                            "start_line": f.start_line,
                            "end_line": f.end_line,
                            "content": f.content,
                            "language": f.language,
                            "cyclomatic_complexity": f.cyclomatic_complexity,
                            "return_type": f.return_type,
                            "parameters": f.parameters,
                            "is_external": is_external,
                        }
                    )

                result = session.run(
                    """
                    UNWIND $funcs AS f
                    MATCH (s:Snapshot {id: $sid})
                    CREATE (fn:Function {
                        name: f.name,
                        snapshot_id: $sid,
                        file_path: f.file_path,
                        start_line: f.start_line,
                        end_line: f.end_line,
                        content: f.content,
                        language: f.language,
                        cyclomatic_complexity: f.cyclomatic_complexity,
                        return_type: f.return_type,
                        parameters: f.parameters,
                        is_external: f.is_external
                    })
                    CREATE (s)-[:CONTAINS]->(fn)
                    WITH fn, f
                    FOREACH (_ IN CASE WHEN f.is_external THEN [1] ELSE [] END |
                        SET fn:External
                    )
                    RETURN count(fn) AS cnt
                    """,
                    sid=snapshot_id,
                    funcs=params,
                )
                record = result.single()
                count += record["cnt"] if record else 0

        return count

    def import_edges(self, snapshot_id: str, edges: list[CallEdge]) -> int:
        """Batch create (:Function)-[:CALLS]->(:Function) edges."""
        if not edges:
            return 0

        count = 0
        with self._session() as session:
            for i in range(0, len(edges), _BATCH_SIZE):
                batch = edges[i : i + _BATCH_SIZE]
                params = [
                    {
                        "caller": e.caller,
                        "callee": e.callee,
                        "caller_file": e.caller_file or None,
                        "callee_file": e.callee_file or None,
                        "call_type": e.call_type.value,
                        "confidence": e.confidence,
                        "backend": e.source_backend,
                    }
                    for e in batch
                ]

                # Use file_path matching when available to avoid Cartesian product
                # on duplicate function names (e.g., static functions in different files)
                result = session.run(
                    """
                    UNWIND $edges AS e
                    MATCH (caller:Function {snapshot_id: $sid, name: e.caller})
                    WHERE e.caller_file IS NULL OR caller.file_path = e.caller_file
                    MATCH (callee:Function {snapshot_id: $sid, name: e.callee})
                    WHERE e.callee_file IS NULL OR callee.file_path = e.callee_file
                    CREATE (caller)-[:CALLS {
                        call_type: e.call_type,
                        confidence: e.confidence,
                        backend: e.backend
                    }]->(callee)
                    RETURN count(*) AS cnt
                    """,
                    sid=snapshot_id,
                    edges=params,
                )
                record = result.single()
                count += record["cnt"] if record else 0

        return count

    def import_fuzzers(self, snapshot_id: str, fuzzers: list[FuzzerInfo]) -> int:
        """
        For each FuzzerInfo:
        1. Create :Fuzzer node + (:Snapshot)-[:CONTAINS]->(:Fuzzer)
        2. Create fuzzer-specific LLVMFuzzerTestOneInput :Function node
        3. Create (:Fuzzer)-[:ENTRY]->(:Function) edge
        4. Create (:Function {LFTOI})-[:CALLS]->(:Function {lib_func}) edges
        """
        if not fuzzers:
            return 0

        with self._session() as session:
            for fz in fuzzers:
                main_file = fz.files[0]["path"] if fz.files else None
                # Step 1-3: Create Fuzzer + Entry function + edges
                session.run(
                    """
                    MATCH (s:Snapshot {id: $sid})
                    CREATE (fz:Fuzzer {
                        name: $name,
                        snapshot_id: $sid,
                        entry_function: $entry_function,
                        focus: $focus,
                        files: $files_json
                    })
                    CREATE (s)-[:CONTAINS]->(fz)
                    CREATE (entry:Function {
                        name: $entry_function,
                        snapshot_id: $sid,
                        file_path: $main_file,
                        start_line: 0,
                        end_line: 0,
                        content: '',
                        language: 'c',
                        cyclomatic_complexity: 0,
                        return_type: '',
                        is_external: false
                    })
                    CREATE (s)-[:CONTAINS]->(entry)
                    CREATE (fz)-[:ENTRY]->(entry)
                    """,
                    sid=snapshot_id,
                    name=fz.name,
                    entry_function=fz.entry_function,
                    focus=fz.focus or "",
                    files_json=json.dumps(fz.files),
                    main_file=main_file,
                )

                # Step 4: Connect entry to library functions
                if fz.called_library_functions:
                    session.run(
                        """
                        UNWIND $lib_funcs AS lib_name
                        MATCH (entry:Function {
                            snapshot_id: $sid,
                            name: $entry_function,
                            file_path: $main_file
                        })
                        MATCH (lib:Function {snapshot_id: $sid, name: lib_name})
                        WHERE $main_file IS NULL
                              OR lib.file_path IS NULL
                              OR lib.file_path <> $main_file
                        CREATE (entry)-[:CALLS {call_type: 'direct', confidence: 1.0, backend: 'fuzzer_parser'}]->(lib)
                        """,
                        sid=snapshot_id,
                        entry_function=fz.entry_function,
                        main_file=main_file,
                        lib_funcs=fz.called_library_functions,
                    )

        return len(fuzzers)

    def import_reaches(self, snapshot_id: str, reaches: list[dict]) -> int:
        """Batch create (:Fuzzer)-[:REACHES {depth}]->(:Function) edges.

        Each reach dict must have: fuzzer_name, function_name, depth.
        Optional: file_path — used for disambiguation when multiple functions share the same name.
        """
        if not reaches:
            return 0

        count = 0
        with self._session() as session:
            for i in range(0, len(reaches), _BATCH_SIZE):
                batch = reaches[i : i + _BATCH_SIZE]
                result = session.run(
                    """
                    UNWIND $reaches AS r
                    MATCH (fz:Fuzzer {snapshot_id: $sid, name: r.fuzzer_name})
                    MATCH (f:Function {snapshot_id: $sid, name: r.function_name})
                    WHERE r.file_path IS NULL OR f.file_path = r.file_path
                    CREATE (fz)-[:REACHES {depth: r.depth}]->(f)
                    RETURN count(*) AS cnt
                    """,
                    sid=snapshot_id,
                    reaches=batch,
                )
                record = result.single()
                count += record["cnt"] if record else 0

        return count

    def delete_snapshot(self, snapshot_id: str) -> None:
        """Delete entire snapshot subgraph including any orphan nodes."""
        with self._session() as session:
            # Delete snapshot node and all nodes connected via :CONTAINS
            session.run(
                """
                MATCH (s:Snapshot {id: $sid})-[:CONTAINS]->(n)
                DETACH DELETE s, n
                """,
                sid=snapshot_id,
            )
            # Also clean up any orphan Function/Fuzzer nodes with this snapshot_id
            # (e.g., from partial imports that weren't connected via :CONTAINS)
            session.run(
                """
                MATCH (n {snapshot_id: $sid})
                WHERE n:Function OR n:Fuzzer
                DETACH DELETE n
                """,
                sid=snapshot_id,
            )

    # ── Query — Single Function ──

    def _resolve_function(
        self, session, snapshot_id: str, name: str, file_path: str | None
    ) -> dict | None:
        """Resolve a function by name, with optional file_path disambiguation."""
        if file_path:
            result = session.run(
                """
                MATCH (f:Function {snapshot_id: $sid, name: $name, file_path: $fp})
                RETURN f
                """,
                sid=snapshot_id,
                name=name,
                fp=file_path,
            )
            record = result.single()
            return dict(record["f"]) if record else None

        result = session.run(
            """
            MATCH (f:Function {snapshot_id: $sid, name: $name})
            RETURN f
            """,
            sid=snapshot_id,
            name=name,
        )
        records = list(result)
        if not records:
            return None
        if len(records) == 1:
            return dict(records[0]["f"])

        # Ambiguous
        files = [dict(r["f"]).get("file_path", "") for r in records]
        raise AmbiguousFunctionError(name, files)

    def get_function_metadata(
        self, snapshot_id: str, name: str, file_path: str | None = None
    ) -> dict | None:
        with self._session() as session:
            node = self._resolve_function(session, snapshot_id, name, file_path)
            if not node:
                return None
            return {
                "name": node["name"],
                "file_path": node.get("file_path"),
                "start_line": node.get("start_line", 0),
                "end_line": node.get("end_line", 0),
                "content": node.get("content", ""),
                "cyclomatic_complexity": node.get("cyclomatic_complexity", 0),
                "return_type": node.get("return_type", ""),
                "parameters": node.get("parameters", []),
                "language": node.get("language", ""),
                "is_external": node.get("is_external", False),
            }

    def list_function_info_by_file(self, snapshot_id: str, file_path: str) -> list[dict]:
        with self._session() as session:
            result = session.run(
                """
                MATCH (f:Function {snapshot_id: $sid, file_path: $fp})
                RETURN f.name AS name, f.start_line AS start_line,
                       f.end_line AS end_line,
                       f.cyclomatic_complexity AS cyclomatic_complexity,
                       f.is_external AS is_external
                ORDER BY f.start_line
                """,
                sid=snapshot_id,
                fp=file_path,
            )
            return [dict(r) for r in result]

    def search_functions(self, snapshot_id: str, pattern: str) -> list[dict]:
        # Convert glob-style wildcards to regex (escape metacharacters first)
        import re as _re

        # Preserve * and ? before escaping, then convert them
        escaped = _re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        regex = "(?i)" + escaped
        with self._session() as session:
            result = session.run(
                """
                MATCH (f:Function {snapshot_id: $sid})
                WHERE f.name =~ $regex
                RETURN f.name AS name, f.file_path AS file_path,
                       f.start_line AS start_line, f.is_external AS is_external
                ORDER BY f.name
                """,
                sid=snapshot_id,
                regex=regex,
            )
            return [dict(r) for r in result]

    # ── Query — Call Relations ──

    def get_callees(
        self, snapshot_id: str, name: str, file_path: str | None = None
    ) -> list[dict]:
        with self._session() as session:
            self._resolve_function(session, snapshot_id, name, file_path)  # validate/disambiguate
            if file_path:
                result = session.run(
                    """
                    MATCH (caller:Function {snapshot_id: $sid, name: $name, file_path: $fp})
                          -[r:CALLS]->(callee:Function {snapshot_id: $sid})
                    RETURN callee.name AS name, callee.file_path AS file_path,
                           r.call_type AS call_type, callee.is_external AS is_external
                    """,
                    sid=snapshot_id,
                    name=name,
                    fp=file_path,
                )
            else:
                result = session.run(
                    """
                    MATCH (caller:Function {snapshot_id: $sid, name: $name})
                          -[r:CALLS]->(callee:Function {snapshot_id: $sid})
                    RETURN callee.name AS name, callee.file_path AS file_path,
                           r.call_type AS call_type, callee.is_external AS is_external
                    """,
                    sid=snapshot_id,
                    name=name,
                )
            return [dict(r) for r in result]

    def get_callers(
        self, snapshot_id: str, name: str, file_path: str | None = None
    ) -> list[dict]:
        with self._session() as session:
            self._resolve_function(session, snapshot_id, name, file_path)
            if file_path:
                result = session.run(
                    """
                    MATCH (caller:Function {snapshot_id: $sid})-[r:CALLS]->
                          (callee:Function {snapshot_id: $sid, name: $name, file_path: $fp})
                    RETURN caller.name AS name, caller.file_path AS file_path,
                           r.call_type AS call_type, caller.is_external AS is_external
                    """,
                    sid=snapshot_id,
                    name=name,
                    fp=file_path,
                )
            else:
                result = session.run(
                    """
                    MATCH (caller:Function {snapshot_id: $sid})-[r:CALLS]->
                          (callee:Function {snapshot_id: $sid, name: $name})
                    RETURN caller.name AS name, caller.file_path AS file_path,
                           r.call_type AS call_type, caller.is_external AS is_external
                    """,
                    sid=snapshot_id,
                    name=name,
                )
            return [dict(r) for r in result]

    def shortest_path(
        self,
        snapshot_id: str,
        from_name: str,
        to_name: str,
        from_file_path: str | None = None,
        to_file_path: str | None = None,
        max_depth: int = 10,
        max_results: int = 10,
    ) -> dict | None:
        with self._session() as session:
            # Build match clauses
            from_match = "MATCH (a:Function {snapshot_id: $sid, name: $from_name"
            if from_file_path:
                from_match += ", file_path: $from_fp"
            from_match += "})"

            to_match = "MATCH (b:Function {snapshot_id: $sid, name: $to_name"
            if to_file_path:
                to_match += ", file_path: $to_fp"
            to_match += "})"

            effective_depth = max_depth if max_depth > 0 else _MAX_PATH_DEPTH
            depth_clause = f"*1..{effective_depth}"

            # First find shortest path length
            cypher = f"""
                {from_match}
                {to_match}
                MATCH path = shortestPath((a)-[:CALLS{depth_clause}]->(b))
                WHERE ALL(n IN nodes(path) WHERE n.snapshot_id = $sid)
                RETURN length(path) AS pathlen
                LIMIT 1
            """
            params = {
                "sid": snapshot_id,
                "from_name": from_name,
                "to_name": to_name,
                "from_fp": from_file_path,
                "to_fp": to_file_path,
            }
            result = session.run(cypher, **params)
            record = result.single()
            if not record:
                return None

            shortest_len = record["pathlen"]

            # Get all paths of that length
            limit_clause = f"LIMIT {max_results}" if max_results > 0 else ""
            cypher_all = f"""
                {from_match}
                {to_match}
                MATCH path = (a)-[:CALLS*{shortest_len}]->(b)
                WHERE ALL(n IN nodes(path) WHERE n.snapshot_id = $sid)
                RETURN path
                {limit_clause}
            """
            result = session.run(cypher_all, **params)
            paths = []
            for record in result:
                path = record["path"]
                nodes_list = [
                    {"name": n["name"], "file_path": n.get("file_path")} for n in path.nodes
                ]
                edges_list = []
                for rel in path.relationships:
                    start = rel.start_node
                    end = rel.end_node
                    edges_list.append(
                        {
                            "from": start["name"],
                            "to": end["name"],
                            "call_type": rel.get("call_type", "direct"),
                        }
                    )
                paths.append({"path": nodes_list, "edges": edges_list})

            if not paths:
                return None

            truncated = max_results > 0 and len(paths) >= max_results
            return {
                "length": shortest_len,
                "paths_found": len(paths),
                "truncated": truncated,
                "paths": paths,
            }

    def get_all_paths(
        self,
        snapshot_id: str,
        from_name: str,
        to_name: str,
        from_file_path: str | None = None,
        to_file_path: str | None = None,
        max_depth: int = 10,
        max_results: int = 100,
    ) -> dict | None:
        with self._session() as session:
            from_match = "MATCH (a:Function {snapshot_id: $sid, name: $from_name"
            if from_file_path:
                from_match += ", file_path: $from_fp"
            from_match += "})"

            to_match = "MATCH (b:Function {snapshot_id: $sid, name: $to_name"
            if to_file_path:
                to_match += ", file_path: $to_fp"
            to_match += "})"

            effective_depth = max_depth if max_depth > 0 else _MAX_PATH_DEPTH
            depth_clause = f"*1..{effective_depth}"
            limit_clause = f"LIMIT {max_results}" if max_results > 0 else ""

            cypher = f"""
                {from_match}
                {to_match}
                MATCH path = (a)-[:CALLS{depth_clause}]->(b)
                WHERE ALL(n IN nodes(path) WHERE n.snapshot_id = $sid)
                RETURN path, length(path) AS pathlen
                ORDER BY pathlen
                {limit_clause}
            """
            params = {
                "sid": snapshot_id,
                "from_name": from_name,
                "to_name": to_name,
                "from_fp": from_file_path,
                "to_fp": to_file_path,
            }
            result = session.run(cypher, **params)
            paths = []
            for record in result:
                path = record["path"]
                nodes_list = [
                    {"name": n["name"], "file_path": n.get("file_path")} for n in path.nodes
                ]
                edges_list = []
                for rel in path.relationships:
                    start = rel.start_node
                    end = rel.end_node
                    edges_list.append(
                        {
                            "from": start["name"],
                            "to": end["name"],
                            "call_type": rel.get("call_type", "direct"),
                        }
                    )
                paths.append(
                    {"path": nodes_list, "edges": edges_list, "length": record["pathlen"]}
                )

            if not paths:
                return None

            truncated = max_results > 0 and len(paths) >= max_results
            return {
                "paths_found": len(paths),
                "truncated": truncated,
                "paths": paths,
            }

    # ── Query — Visualization ──

    def get_subtree(
        self,
        snapshot_id: str,
        name: str,
        file_path: str | None = None,
        depth: int = 3,
    ) -> dict:
        with self._session() as session:
            root_match = "MATCH (root:Function {snapshot_id: $sid, name: $name"
            if file_path:
                root_match += ", file_path: $fp"
            root_match += "})"

            cypher = f"""
                {root_match}
                MATCH path = (root)-[:CALLS*0..{depth}]->(f:Function {{snapshot_id: $sid}})
                UNWIND nodes(path) AS n
                WITH DISTINCT n
                RETURN collect(DISTINCT {{
                    name: n.name,
                    file_path: n.file_path,
                    is_external: n.is_external
                }}) AS nodes
            """
            params = {"sid": snapshot_id, "name": name, "fp": file_path}
            result = session.run(cypher, **params)
            record = result.single()
            nodes = record["nodes"] if record else []

            # Get edges between the collected nodes
            node_names = [n["name"] for n in nodes]
            edge_result = session.run(
                """
                MATCH (a:Function {snapshot_id: $sid})-[r:CALLS]->(b:Function {snapshot_id: $sid})
                WHERE a.name IN $names AND b.name IN $names
                RETURN DISTINCT a.name AS from_name, b.name AS to_name,
                       r.call_type AS call_type
                """,
                sid=snapshot_id,
                names=node_names,
            )
            edges = [
                {"from": r["from_name"], "to": r["to_name"], "call_type": r["call_type"]}
                for r in edge_result
            ]

            return {"nodes": nodes, "edges": edges}

    # ── Query — Fuzzer Reachability ──

    def reachable_functions_by_one_fuzzer(
        self,
        snapshot_id: str,
        fuzzer_name: str,
        depth: int | None = None,
        max_depth: int | None = None,
    ) -> list[dict]:
        with self._session() as session:
            where_clauses = []
            if depth is not None:
                where_clauses.append("r.depth = $depth")
            if max_depth is not None:
                where_clauses.append("r.depth <= $max_depth")
            where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            result = session.run(
                f"""
                MATCH (fz:Fuzzer {{snapshot_id: $sid, name: $fname}})
                      -[r:REACHES]->(f:Function {{snapshot_id: $sid}})
                {where}
                RETURN f.name AS name, f.file_path AS file_path,
                       r.depth AS depth, f.is_external AS is_external
                ORDER BY r.depth
                """,
                sid=snapshot_id,
                fname=fuzzer_name,
                depth=depth,
                max_depth=max_depth,
            )
            return [dict(r) for r in result]

    def unreached_functions_by_all_fuzzers(
        self, snapshot_id: str, include_external: bool = False
    ) -> list[dict]:
        with self._session() as session:
            external_filter = "" if include_external else "AND NOT f:External"
            result = session.run(
                f"""
                MATCH (s:Snapshot {{id: $sid}})-[:CONTAINS]->(f:Function)
                WHERE NOT (f)<-[:REACHES]-(:Fuzzer {{snapshot_id: $sid}})
                  AND f.name <> 'LLVMFuzzerTestOneInput'
                  {external_filter}
                RETURN f.name AS name, f.file_path AS file_path,
                       f.is_external AS is_external
                ORDER BY f.name
                """,
                sid=snapshot_id,
            )
            return [dict(r) for r in result]

    # ── Query — Overview ──

    def list_fuzzer_info_no_code(self, snapshot_id: str) -> list[dict]:
        with self._session() as session:
            result = session.run(
                """
                MATCH (fz:Fuzzer {snapshot_id: $sid})
                RETURN fz.name AS name, fz.entry_function AS entry_function,
                       fz.files AS files, fz.focus AS focus
                ORDER BY fz.name
                """,
                sid=snapshot_id,
            )
            return [dict(r) for r in result]

    def get_fuzzer_metadata(self, snapshot_id: str, fuzzer_name: str) -> dict | None:
        with self._session() as session:
            result = session.run(
                """
                MATCH (fz:Fuzzer {snapshot_id: $sid, name: $fname})
                RETURN fz.name AS name, fz.entry_function AS entry_function,
                       fz.files AS files, fz.focus AS focus
                """,
                sid=snapshot_id,
                fname=fuzzer_name,
            )
            record = result.single()
            return dict(record) if record else None

    def list_external_function_names(self, snapshot_id: str) -> list[str]:
        with self._session() as session:
            result = session.run(
                """
                MATCH (f:Function:External {snapshot_id: $sid})
                RETURN f.name AS name
                ORDER BY f.name
                """,
                sid=snapshot_id,
            )
            return [r["name"] for r in result]

    def get_snapshot_statistics(self, snapshot_id: str) -> dict:
        with self._session() as session:
            result = session.run(
                """
                MATCH (s:Snapshot {id: $sid})
                OPTIONAL MATCH (s)-[:CONTAINS]->(f:Function)
                WITH s,
                     count(f) AS func_count,
                     count(CASE WHEN f.is_external THEN 1 END) AS ext_count
                OPTIONAL MATCH (s)-[:CONTAINS]->(:Function)-[e:CALLS]->(:Function)
                WITH s, func_count, ext_count, count(e) AS edge_count
                OPTIONAL MATCH (s)-[:CONTAINS]->(fz:Fuzzer)
                WITH s, func_count, ext_count, edge_count, count(fz) AS fuzzer_count
                OPTIONAL MATCH (:Fuzzer {snapshot_id: $sid})-[r:REACHES]->(:Function {snapshot_id: $sid})
                WITH func_count, ext_count, edge_count, fuzzer_count,
                     CASE WHEN count(r) > 0 THEN avg(r.depth) ELSE 0 END AS avg_depth,
                     CASE WHEN count(r) > 0 THEN max(r.depth) ELSE 0 END AS max_depth,
                     count(r) AS reach_count
                RETURN func_count, ext_count, edge_count, fuzzer_count,
                       avg_depth, max_depth, reach_count
                """,
                sid=snapshot_id,
            )
            record = result.single()
            if not record:
                return {}

            func_count = record["func_count"]
            ext_count = record["ext_count"]
            fuzzer_count = record["fuzzer_count"]

            # Count unreached (separate query for clarity)
            unreach_result = session.run(
                """
                MATCH (s:Snapshot {id: $sid})-[:CONTAINS]->(f:Function)
                WHERE NOT (f)<-[:REACHES]-(:Fuzzer {snapshot_id: $sid})
                  AND f.name <> 'LLVMFuzzerTestOneInput'
                RETURN count(f) AS cnt
                """,
                sid=snapshot_id,
            )
            unreached = unreach_result.single()["cnt"]

            return {
                "function_count": func_count,
                "external_function_count": ext_count,
                "edge_count": record["edge_count"],
                "fuzzer_count": fuzzer_count,
                "reach_count": record["reach_count"] or 0,
                "avg_depth": round(record["avg_depth"], 1) if record["avg_depth"] else 0,
                "max_depth": record["max_depth"] or 0,
                "unreached_count": unreached,
            }

    # ── Extension ──

    def raw_query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict]:
        with self._session() as session:
            result = session.run(cypher, **(params or {}))
            return [dict(r) for r in result]
