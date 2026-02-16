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
import sys
from pathlib import Path

import click

# Default connection strings (overridable via env vars)
_DEFAULT_NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
_DEFAULT_NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
_DEFAULT_NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "neo4j")
_DEFAULT_MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

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
@click.option("--neo4j-user", default=_DEFAULT_NEO4J_USER, help="Neo4j user")
@click.option("--neo4j-password", default=_DEFAULT_NEO4J_PASSWORD, help="Neo4j password")
@click.option("--mongo-uri", default=_DEFAULT_MONGO_URI, help="MongoDB URI")
def run(
    work_file: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
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
        click.echo(f"Error: Project path not found: {project_path}", err=True)
        click.echo("Set 'path' in the work order to a valid local directory.", err=True)
        sys.exit(1)

    # Run analysis
    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.orchestrator import StaticAnalysisOrchestrator
    from z_code_analyzer.snapshot_manager import SnapshotManager

    graph_store = GraphStore()
    graph_store.connect(neo4j_uri, (neo4j_user, neo4j_password))

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


if __name__ == "__main__":
    main()
