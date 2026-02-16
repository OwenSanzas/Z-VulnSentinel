"""CLI entry point for standalone usage: z-analyze.

Subcommands:
    z-analyze create-work -o work.json    # Generate work order template
    z-analyze run work.json               # Execute analysis from work order
    z-analyze probe /path/to/project      # Quick project probe (Phase 1 only)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import click

# Default connection strings (overridable via env vars)
_DEFAULT_NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
_DEFAULT_MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")


def _parse_neo4j_auth() -> tuple[str, str] | None:
    """Parse Neo4j auth from NEO4J_AUTH env var (doc: appendix-b).

    Supported formats:
        NEO4J_AUTH=none             → no auth (returns None)
        NEO4J_AUTH=neo4j:password   → (neo4j, password)
        NEO4J_USER + NEO4J_PASSWORD → fallback to separate env vars
    """
    neo4j_auth = os.environ.get("NEO4J_AUTH")
    if neo4j_auth is not None:
        if neo4j_auth.lower() == "none":
            return None
        if ":" in neo4j_auth:
            user, password = neo4j_auth.split(":", 1)
            return (user, password)
        # Malformed — treat as no-auth with a warning
        logging.getLogger(__name__).warning(
            "NEO4J_AUTH has unrecognized format (expected 'none' or 'user:password'), treating as no-auth"
        )
        return None
    # Fallback: separate env vars (backward compat)
    user = os.environ.get("NEO4J_USER")
    password = os.environ.get("NEO4J_PASSWORD")
    if user and password:
        return (user, password)
    return None  # default: no auth


def _auto_clone(repo_url: str, version: str) -> str | None:
    """Clone a repo to a temp directory and checkout the given version."""
    tmpdir = tempfile.mkdtemp(prefix="z-analyze-clone-")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", version, repo_url, tmpdir],
            check=True,
            capture_output=True,
            text=True,
        )
        return tmpdir
    except subprocess.CalledProcessError:
        # --branch may fail for commit hashes; try full clone + checkout
        # First remove the partially-created directory contents
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
        os.makedirs(tmpdir, exist_ok=True)
        try:
            subprocess.run(
                ["git", "clone", repo_url, tmpdir],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "checkout", version],
                check=True,
                capture_output=True,
                text=True,
            )
            return tmpdir
        except subprocess.CalledProcessError as e:
            click.echo(f"Git clone/checkout failed: {e.stderr}", err=True)
            return None


# Work order template
_WORK_ORDER_TEMPLATE = {
    "repo_url": "https://github.com/user/project",
    "version": "v1.0",
    "path": "./project-src",
    "build_script": None,
    "backend": "svf",
    "fuzzer_sources": {
        "fuzz_example": ["fuzz/fuzz_example.c"],
    },
    "diff_files": None,
    "ai_refine": False,
}


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def main(verbose: bool) -> None:
    """Z-Code-Analyzer: Static analysis engine for call graph extraction."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@main.command("create-work")
@click.option("-o", "--output", default="work.json", help="Output file path")
def create_work(output: str) -> None:
    """Generate a work order template JSON file."""
    Path(output).write_text(json.dumps(_WORK_ORDER_TEMPLATE, indent=2) + "\n")
    click.echo(f"Work order template written to {output}")
    click.echo("Edit the file, then run: z-analyze run " + output)


@main.command("run")
@click.argument("work_file", type=click.Path(exists=True))
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth ('none' or 'user:password')")
@click.option("--mongo-uri", default=_DEFAULT_MONGO_URI, help="MongoDB URI")
def run(
    work_file: str,
    neo4j_uri: str,
    neo4j_auth: str | None,
    mongo_uri: str,
) -> None:
    """Execute analysis from a work order JSON file."""
    # Load and validate work order
    try:
        work = json.loads(Path(work_file).read_text())
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON in {work_file}: {e}", err=True)
        sys.exit(1)

    # Validate required fields
    for field in ("repo_url", "version", "fuzzer_sources"):
        if field not in work:
            click.echo(f"Error: Missing required field '{field}' in work order", err=True)
            sys.exit(1)

    if not isinstance(work["fuzzer_sources"], dict):
        click.echo("Error: 'fuzzer_sources' must be a JSON object", err=True)
        sys.exit(1)

    project_path = work.get("path")
    if not project_path or not Path(project_path).is_dir():
        # Auto-clone if path not provided (doc §9.1: "不传则自动 clone")
        repo_url = work["repo_url"]
        version = work.get("version", "HEAD")
        click.echo(f"Local path not found, cloning {repo_url}@{version} ...")
        project_path = _auto_clone(repo_url, version)
        if not project_path:
            click.echo("Error: auto-clone failed.", err=True)
            sys.exit(1)
        click.echo(f"Cloned to: {project_path}")

    # Run analysis
    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.orchestrator import StaticAnalysisOrchestrator
    from z_code_analyzer.snapshot_manager import SnapshotManager

    auth = _resolve_auth(neo4j_auth)

    graph_store = GraphStore(neo4j_uri, auth)

    snapshot_mgr = SnapshotManager(mongo_uri=mongo_uri, graph_store=graph_store)

    orchestrator = StaticAnalysisOrchestrator(
        snapshot_manager=snapshot_mgr,
        graph_store=graph_store,
    )

    try:
        result = asyncio.run(
            orchestrator.analyze(
                project_path=project_path,
                repo_url=work["repo_url"],
                version=work["version"],
                fuzzer_sources=work["fuzzer_sources"],
                build_script=work.get("build_script"),
                language=work.get("language"),
                backend=work.get("backend"),
                diff_files=work.get("diff_files"),
            )
        )

        click.echo(f"\nAnalysis {'(cached)' if result.cached else 'complete'}:")
        click.echo(f"  Snapshot ID: {result.snapshot_id}")
        click.echo(f"  Backend: {result.backend}")
        click.echo(f"  Functions: {result.function_count}")
        click.echo(f"  Edges: {result.edge_count}")
        click.echo(f"  Fuzzers: {result.fuzzer_names}")

        # Print progress summary
        summary = orchestrator.progress.get_summary()
        click.echo(f"\nPipeline summary (total: {summary['total_duration']}s):")
        for p in summary["phases"]:
            status_icon = {
                "completed": "+",
                "failed": "!",
                "skipped": "-",
                "running": "~",
                "pending": ".",
            }.get(p["status"], "?")
            duration = f" ({p['duration']}s)" if p["duration"] else ""
            detail = f" - {p['detail']}" if p["detail"] else ""
            click.echo(f"  [{status_icon}] {p['phase']}{duration}{detail}")

    finally:
        graph_store.close()
        snapshot_mgr.close()


@main.command("probe")
@click.argument("project_path", type=click.Path(exists=True))
def probe(project_path: str) -> None:
    """Quick project probe: detect language, build system, source files."""
    from z_code_analyzer.probe import ProjectProbe

    info = ProjectProbe().probe(project_path)
    click.echo(f"Language: {info.language_profile.primary_language} "
               f"(confidence: {info.language_profile.confidence})")
    click.echo(f"Build system: {info.build_system}")
    click.echo(f"Source files: {len(info.source_files)}")
    click.echo(f"Estimated LOC: {info.estimated_loc}")
    if info.git_root:
        click.echo(f"Git root: {info.git_root}")
    click.echo(f"\nFile counts:")
    for ext, count in sorted(info.language_profile.file_counts.items()):
        click.echo(f"  {ext}: {count}")


# ── z-query CLI ──


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def query_main(verbose: bool) -> None:
    """Z-Code Query: Query analysis results in Neo4j."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@query_main.command("shortest-path")
@click.option("--repo-url", required=True, help="Repository URL")
@click.option("--version", required=True, help="Version/tag/commit")
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth ('none' or 'user:password')")
@click.option("--mongo-uri", default=_DEFAULT_MONGO_URI, help="MongoDB URI")
@click.argument("from_func")
@click.argument("to_func")
def query_shortest_path(
    repo_url: str, version: str, neo4j_uri: str, neo4j_auth: str | None,
    mongo_uri: str, from_func: str, to_func: str,
) -> None:
    """Find shortest path between two functions."""
    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.snapshot_manager import SnapshotManager

    auth = _resolve_auth(neo4j_auth)
    gs = GraphStore(neo4j_uri, auth)
    sm = SnapshotManager(mongo_uri=mongo_uri)

    try:
        snap = sm.find_snapshot(repo_url, version)
        if not snap:
            click.echo(f"No snapshot found for {repo_url}@{version}", err=True)
            sys.exit(1)
        sid = str(snap["_id"])
        result = gs.shortest_path(sid, from_func, to_func)
        if result:
            click.echo(json.dumps(result, indent=2, default=str))
        else:
            click.echo(f"No path from {from_func} to {to_func}")
    finally:
        gs.close()
        sm.close()


@query_main.command("search")
@click.option("--repo-url", required=True, help="Repository URL")
@click.option("--version", required=True, help="Version/tag/commit")
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth")
@click.option("--mongo-uri", default=_DEFAULT_MONGO_URI, help="MongoDB URI")
@click.argument("pattern")
def query_search(
    repo_url: str, version: str, neo4j_uri: str, neo4j_auth: str | None,
    mongo_uri: str, pattern: str,
) -> None:
    """Search functions by pattern (e.g. 'parse_*')."""
    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.snapshot_manager import SnapshotManager

    auth = _resolve_auth(neo4j_auth)
    gs = GraphStore(neo4j_uri, auth)
    sm = SnapshotManager(mongo_uri=mongo_uri)

    try:
        snap = sm.find_snapshot(repo_url, version)
        if not snap:
            click.echo(f"No snapshot found for {repo_url}@{version}", err=True)
            sys.exit(1)
        results = gs.search_functions(str(snap["_id"]), pattern)
        for func in results:
            click.echo(f"  {func['name']}  {func.get('file_path', '')}:{func.get('start_line', '')}")
    finally:
        gs.close()
        sm.close()


# ── z-snapshots CLI ──


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def snapshots_main(verbose: bool) -> None:
    """Z-Code Snapshots: Manage analysis snapshots."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@snapshots_main.command("list")
@click.option("--repo-url", default=None, help="Filter by repository URL")
@click.option("--mongo-uri", default=_DEFAULT_MONGO_URI, help="MongoDB URI")
def snapshots_list(repo_url: str | None, mongo_uri: str) -> None:
    """List all analysis snapshots."""
    from z_code_analyzer.snapshot_manager import SnapshotManager

    sm = SnapshotManager(mongo_uri=mongo_uri)
    try:
        query: dict = {"status": "completed"}
        if repo_url:
            query["repo_url"] = repo_url
        snaps = list(sm._snapshots.find(query).sort("last_accessed_at", -1))
        if not snaps:
            click.echo("No snapshots found.")
            return
        for snap in snaps:
            click.echo(
                f"  {str(snap['_id'])[:12]}  "
                f"{snap.get('repo_name', '?'):20s}  "
                f"{snap.get('version', '?'):15s}  "
                f"{snap.get('backend', '?'):10s}  "
                f"funcs={snap.get('node_count', 0):5d}  "
                f"edges={snap.get('edge_count', 0):5d}  "
                f"fuzzers={len(snap.get('fuzzer_names', []))}"
            )
    finally:
        sm.close()


def _resolve_auth(neo4j_auth: str | None) -> tuple[str, str] | None:
    """Resolve Neo4j auth from CLI flag or env."""
    if neo4j_auth is not None:
        if neo4j_auth.lower() == "none":
            return None
        if ":" in neo4j_auth:
            user, password = neo4j_auth.split(":", 1)
            return (user, password)
        return None
    return _parse_neo4j_auth()


if __name__ == "__main__":
    main()
