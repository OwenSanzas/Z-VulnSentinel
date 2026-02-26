"""Tests for CLI commands — no Docker/Neo4j/PostgreSQL needed (mocked)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from z_code_analyzer.cli import (
    _WORK_ORDER_TEMPLATE,
    _parse_neo4j_auth,
    _resolve_auth,
    main,
    query_main,
    snapshots_main,
)

# ── Auth parsing ──


class TestParseNeo4jAuth:
    def test_none_string(self):
        with patch.dict(os.environ, {"NEO4J_AUTH": "none"}):
            assert _parse_neo4j_auth() is None

    def test_none_case_insensitive(self):
        with patch.dict(os.environ, {"NEO4J_AUTH": "None"}):
            assert _parse_neo4j_auth() is None

    def test_user_password(self):
        with patch.dict(os.environ, {"NEO4J_AUTH": "neo4j:secret123"}):
            assert _parse_neo4j_auth() == ("neo4j", "secret123")

    def test_password_with_colon(self):
        with patch.dict(os.environ, {"NEO4J_AUTH": "neo4j:pass:word"}):
            assert _parse_neo4j_auth() == ("neo4j", "pass:word")

    def test_malformed_treated_as_no_auth(self):
        with patch.dict(os.environ, {"NEO4J_AUTH": "garbage"}):
            assert _parse_neo4j_auth() is None

    def test_fallback_to_separate_env_vars(self):
        env = {"NEO4J_USER": "admin", "NEO4J_PASSWORD": "pw"}
        with patch.dict(os.environ, env, clear=False):
            # Remove NEO4J_AUTH if present
            os.environ.pop("NEO4J_AUTH", None)
            assert _parse_neo4j_auth() == ("admin", "pw")

    def test_no_env_vars_returns_none(self):
        env_to_remove = ["NEO4J_AUTH", "NEO4J_USER", "NEO4J_PASSWORD"]
        with patch.dict(os.environ, {}, clear=False):
            for k in env_to_remove:
                os.environ.pop(k, None)
            assert _parse_neo4j_auth() is None


class TestResolveAuth:
    def test_cli_flag_none(self):
        assert _resolve_auth("none") is None

    def test_cli_flag_user_pass(self):
        assert _resolve_auth("neo4j:pw") == ("neo4j", "pw")

    def test_cli_flag_malformed(self):
        assert _resolve_auth("garbage") is None

    def test_cli_flag_none_overrides_env(self):
        """CLI flag takes precedence over env var."""
        with patch.dict(os.environ, {"NEO4J_AUTH": "neo4j:envpass"}):
            assert _resolve_auth("none") is None

    def test_no_flag_falls_through_to_env(self):
        with patch.dict(os.environ, {"NEO4J_AUTH": "neo4j:envpass"}):
            assert _resolve_auth(None) == ("neo4j", "envpass")


# ── create-work ──


class TestCreateWork:
    def test_creates_template(self, tmp_path: Path):
        runner = CliRunner()
        out_file = str(tmp_path / "work.json")
        result = runner.invoke(main, ["create-work", "-o", out_file])
        assert result.exit_code == 0
        data = json.loads(Path(out_file).read_text())
        assert "repo_url" in data
        assert "fuzzer_sources" in data
        assert isinstance(data["fuzzer_sources"], dict)

    def test_template_matches_constant(self, tmp_path: Path):
        runner = CliRunner()
        out_file = str(tmp_path / "work.json")
        runner.invoke(main, ["create-work", "-o", out_file])
        data = json.loads(Path(out_file).read_text())
        assert data == _WORK_ORDER_TEMPLATE


# ── run — validation ──


class TestRunValidation:
    def test_invalid_json(self, tmp_path: Path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json{{{")
        runner = CliRunner()
        result = runner.invoke(main, ["run", str(bad_file)])
        assert result.exit_code != 0
        assert "Invalid JSON" in result.output

    def test_missing_required_field(self, tmp_path: Path):
        work_file = tmp_path / "work.json"
        work_file.write_text(json.dumps({"repo_url": "x"}))
        runner = CliRunner()
        result = runner.invoke(main, ["run", str(work_file)])
        assert result.exit_code != 0
        assert "Missing required field" in result.output

    def test_fuzzer_sources_must_be_dict(self, tmp_path: Path):
        work_file = tmp_path / "work.json"
        work_file.write_text(
            json.dumps({"repo_url": "x", "version": "v1", "fuzzer_sources": ["not_a_dict"]})
        )
        runner = CliRunner()
        result = runner.invoke(main, ["run", str(work_file)])
        assert result.exit_code != 0
        assert "must be a JSON object" in result.output


# ── probe ──


class TestProbe:
    def test_probe_c_project(self, tmp_path: Path):
        (tmp_path / "main.c").write_text("int main() {}")
        (tmp_path / "Makefile").write_text("all:")
        runner = CliRunner()
        result = runner.invoke(main, ["probe", str(tmp_path)])
        assert result.exit_code == 0
        assert "Language: c" in result.output
        assert "Build system: make" in result.output

    def test_probe_empty_dir(self, tmp_path: Path):
        runner = CliRunner()
        result = runner.invoke(main, ["probe", str(tmp_path)])
        assert result.exit_code == 0
        assert "Language: unknown" in result.output

    def test_probe_nonexistent_path(self):
        runner = CliRunner()
        result = runner.invoke(main, ["probe", "/nonexistent/path/xyz"])
        assert result.exit_code != 0


# ── z-snapshots list (mocked) ──


class TestSnapshotsList:
    @patch("sqlalchemy.orm.sessionmaker")
    @patch("sqlalchemy.create_engine")
    @patch("z_code_analyzer.snapshot_manager.SnapshotManager", autospec=True)
    def test_list_no_snapshots(self, MockSM, _mock_engine, _mock_sf):
        mock_instance = MockSM.return_value
        mock_instance.list_snapshots.return_value = []
        runner = CliRunner()
        result = runner.invoke(snapshots_main, ["list", "--pg-url", "postgresql://fake/db"])
        assert result.exit_code == 0
        assert "No snapshots found" in result.output

    @patch("sqlalchemy.orm.sessionmaker")
    @patch("sqlalchemy.create_engine")
    @patch("z_code_analyzer.snapshot_manager.SnapshotManager", autospec=True)
    def test_list_with_snapshots(self, MockSM, _mock_engine, _mock_sf):
        import uuid

        mock_snap = type(
            "Snap",
            (),
            {
                "id": uuid.uuid4(),
                "repo_name": "curl",
                "version": "v8.0",
                "backend": "svf",
                "node_count": 2334,
                "edge_count": 18540,
                "fuzzer_names": ["fuzz1"],
            },
        )()
        mock_instance = MockSM.return_value
        mock_instance.list_snapshots.return_value = [mock_snap]
        runner = CliRunner()
        result = runner.invoke(snapshots_main, ["list", "--pg-url", "postgresql://fake/db"])
        assert result.exit_code == 0
        assert "curl" in result.output
        assert "v8.0" in result.output


# ── z-query (mocked — lazy import) ──


class TestQueryCommands:
    def test_shortest_path_no_snapshot(self):
        """Tests that missing snapshot gives proper error."""
        with (
            patch("z_code_analyzer.graph_store.GraphStore"),
            patch("z_code_analyzer.snapshot_manager.SnapshotManager") as MockSM,
            patch("sqlalchemy.create_engine"),
            patch("sqlalchemy.orm.sessionmaker"),
        ):
            mock_sm = MockSM.return_value
            mock_sm.find_snapshot.return_value = None
            runner = CliRunner()
            result = runner.invoke(
                query_main,
                [
                    "shortest-path",
                    "--repo-url",
                    "https://r/a",
                    "--version",
                    "v1",
                    "--neo4j-uri",
                    "bolt://fake:7687",
                    "--pg-url",
                    "postgresql://fake/db",
                    "func_a",
                    "func_b",
                ],
            )
            assert result.exit_code != 0
            assert "No snapshot found" in result.output

    def test_search_no_snapshot(self):
        with (
            patch("z_code_analyzer.graph_store.GraphStore"),
            patch("z_code_analyzer.snapshot_manager.SnapshotManager") as MockSM,
            patch("sqlalchemy.create_engine"),
            patch("sqlalchemy.orm.sessionmaker"),
        ):
            mock_sm = MockSM.return_value
            mock_sm.find_snapshot.return_value = None
            runner = CliRunner()
            result = runner.invoke(
                query_main,
                [
                    "search",
                    "--repo-url",
                    "https://r/a",
                    "--version",
                    "v1",
                    "--neo4j-uri",
                    "bolt://fake:7687",
                    "--pg-url",
                    "postgresql://fake/db",
                    "parse_*",
                ],
            )
            assert result.exit_code != 0
            assert "No snapshot found" in result.output
