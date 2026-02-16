"""CLI entry point for standalone usage: z-analyze."""

from __future__ import annotations

import json
import logging
import sys

import click


@click.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--repo-url", required=True, help="Repository URL")
@click.option("--version", required=True, help="Version tag or commit hash")
@click.option(
    "--fuzzer-sources",
    required=True,
    help='JSON: {"fuzzer_name": ["file1.c", "file2.c"]}',
)
@click.option("--build-script", default=None, help="Path to build script")
@click.option("--language", default=None, help="Override language detection")
@click.option("--backend", default=None, help="Override backend selection")
@click.option("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j URI")
@click.option("--neo4j-user", default="neo4j", help="Neo4j user")
@click.option("--neo4j-password", default="neo4j", help="Neo4j password")
@click.option("--mongo-uri", default="mongodb://localhost:27017", help="MongoDB URI")
@click.option("--probe-only", is_flag=True, help="Only run project probe (Phase 1)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def main(
    project_path: str,
    repo_url: str,
    version: str,
    fuzzer_sources: str,
    build_script: str | None,
    language: str | None,
    backend: str | None,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    mongo_uri: str,
    probe_only: bool,
    verbose: bool,
) -> None:
    """Z-Code-Analyzer: Static analysis engine for call graph extraction.

    Analyzes a C/C++ project, extracts call graphs using SVF,
    and stores results in Neo4j for querying.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Parse fuzzer sources JSON
    try:
        fuzz_src = json.loads(fuzzer_sources)
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON for --fuzzer-sources: {e}", err=True)
        sys.exit(1)

    if not isinstance(fuzz_src, dict):
        click.echo("Error: --fuzzer-sources must be a JSON object", err=True)
        sys.exit(1)

    # Probe-only mode
    if probe_only:
        from z_code_analyzer.probe import ProjectProbe

        info = ProjectProbe().probe(project_path)
        click.echo(f"Language: {info.language_profile.primary_language}")
        click.echo(f"Build system: {info.build_system}")
        click.echo(f"Source files: {len(info.source_files)}")
        click.echo(f"Estimated LOC: {info.estimated_loc}")
        return

    # Full analysis
    import asyncio

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
                repo_url=repo_url,
                version=version,
                fuzzer_sources=fuzz_src,
                build_script=build_script,
                language=language,
                backend=backend,
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
            detail = f" — {p['detail']}" if p["detail"] else ""
            click.echo(f"  [{status_icon}] {p['phase']}{duration}{detail}")

    finally:
        graph_store.close()
        snapshot_mgr.close()


if __name__ == "__main__":
    main()
