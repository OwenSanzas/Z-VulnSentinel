"""Tests for ReachabilityChecker (zca facade) and diff_parser (Sentinel side)."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest

from vulnsentinel.engines.reachability.diff_parser import (
    _parse_functions_from_patch,
    extract_functions_from_diff,
)
from z_code_analyzer.reachability import ReachabilityChecker

# ── Helpers ──────────────────────────────────────────────────────────────────

CLIENT_URL = "https://github.com/foo/bar"
LIB_URL = "https://github.com/lib/vulnerable"
LIB_VERSION = "abc123"


@dataclass
class FakeSnapshot:
    id: str = "snap-001"


def _make_checker(
    client_snapshot=None,
    library_snapshot=None,
    fuzzers=None,
    reachable=None,
    shortest=None,
):
    """Build a ReachabilityChecker with mocked GraphStore + SnapshotManager."""
    gs = MagicMock()
    sm = MagicMock()

    def _find_snapshot(repo_url, version):
        if repo_url == CLIENT_URL:
            return client_snapshot
        if repo_url == LIB_URL:
            return library_snapshot
        return None

    sm.find_snapshot.side_effect = _find_snapshot
    gs.list_fuzzer_info_no_code.return_value = fuzzers or []
    gs.reachable_functions_by_one_fuzzer.return_value = reachable or []
    gs.shortest_path.return_value = shortest

    return ReachabilityChecker(graph_store=gs, snapshot_manager=sm)


# ═══════════════════════════════════════════════════════════════════════════
#  ReachabilityChecker tests
# ═══════════════════════════════════════════════════════════════════════════


class TestReachabilityChecker:
    """Unit tests for z_code_analyzer.reachability.ReachabilityChecker."""

    @pytest.mark.asyncio
    async def test_client_snapshot_not_found(self):
        checker = _make_checker(client_snapshot=None, library_snapshot=FakeSnapshot("lib-001"))
        vuln = {"affected_functions": ["parse"]}
        result = await checker.check(CLIENT_URL, "v1.0", LIB_URL, LIB_VERSION, vuln)
        assert result.is_reachable is False
        assert result.error == "client_snapshot_not_found"

    @pytest.mark.asyncio
    async def test_library_snapshot_not_found(self):
        checker = _make_checker(client_snapshot=FakeSnapshot(), library_snapshot=None)
        vuln = {"affected_functions": ["parse"]}
        result = await checker.check(CLIENT_URL, "v1.0", LIB_URL, LIB_VERSION, vuln)
        assert result.is_reachable is False
        assert result.error == "library_snapshot_not_found"

    @pytest.mark.asyncio
    async def test_no_affected_functions(self):
        checker = _make_checker(
            client_snapshot=FakeSnapshot(),
            library_snapshot=FakeSnapshot("lib-001"),
        )
        result = await checker.check(
            CLIENT_URL, "v1.0", LIB_URL, LIB_VERSION, {"affected_functions": []},
        )
        assert result.is_reachable is False
        assert result.error == "no_affected_functions"

    @pytest.mark.asyncio
    async def test_no_affected_functions_key_missing(self):
        checker = _make_checker(
            client_snapshot=FakeSnapshot(),
            library_snapshot=FakeSnapshot("lib-001"),
        )
        result = await checker.check(CLIENT_URL, "v1.0", LIB_URL, LIB_VERSION, {})
        assert result.is_reachable is False
        assert result.error == "no_affected_functions"

    @pytest.mark.asyncio
    async def test_fuzzer_reaches(self):
        checker = _make_checker(
            client_snapshot=FakeSnapshot(),
            library_snapshot=FakeSnapshot("lib-001"),
            fuzzers=[{"name": "fuzz_url"}],
            reachable=[
                {"name": "parse_url", "file_path": "lib/url.c", "depth": 3, "is_external": False},
                {
                    "name": "other_func",
                    "file_path": "lib/other.c",
                    "depth": 1,
                    "is_external": False,
                },
            ],
        )
        result = await checker.check(
            CLIENT_URL,
            "v1.0",
            LIB_URL,
            LIB_VERSION,
            {"affected_functions": ["parse_url"]},
        )
        assert result.is_reachable is True
        assert result.strategy == "fuzzer_reaches"
        assert result.depth == 3
        assert result.client_snapshot_id == "snap-001"
        assert result.library_snapshot_id == "lib-001"

    @pytest.mark.asyncio
    async def test_shortest_path_reachable(self):
        checker = _make_checker(
            client_snapshot=FakeSnapshot(),
            library_snapshot=FakeSnapshot("lib-001"),
            fuzzers=[],
            shortest={
                "length": 5,
                "paths_found": 1,
                "truncated": False,
                "paths": [
                    [
                        {"name": "main", "file_path": "main.c"},
                        {"name": "process", "file_path": "proc.c"},
                        {"name": "vulnerable_func", "file_path": "vuln.c"},
                    ]
                ],
            },
        )
        result = await checker.check(
            CLIENT_URL,
            "v1.0",
            LIB_URL,
            LIB_VERSION,
            {"affected_functions": ["vulnerable_func"]},
        )
        assert result.is_reachable is True
        assert result.strategy == "shortest_path"
        assert result.depth == 5
        assert result.paths is not None
        assert result.client_snapshot_id == "snap-001"
        assert result.library_snapshot_id == "lib-001"

    @pytest.mark.asyncio
    async def test_not_reachable(self):
        checker = _make_checker(
            client_snapshot=FakeSnapshot(),
            library_snapshot=FakeSnapshot("lib-001"),
            fuzzers=[{"name": "fuzz_http"}],
            reachable=[
                {"name": "http_parse", "file_path": "http.c", "depth": 1, "is_external": False},
            ],
            shortest=None,
        )
        result = await checker.check(
            CLIENT_URL,
            "v1.0",
            LIB_URL,
            LIB_VERSION,
            {"affected_functions": ["unrelated_func"]},
        )
        assert result.is_reachable is False
        assert result.error is None
        assert result.strategy == "exhausted"

    @pytest.mark.asyncio
    async def test_shortest_path_no_paths_found(self):
        checker = _make_checker(
            client_snapshot=FakeSnapshot(),
            library_snapshot=FakeSnapshot("lib-001"),
            fuzzers=[],
            shortest={
                "length": 0,
                "paths_found": 0,
                "truncated": False,
                "paths": [],
            },
        )
        result = await checker.check(
            CLIENT_URL,
            "v1.0",
            LIB_URL,
            LIB_VERSION,
            {"affected_functions": ["target_func"]},
        )
        assert result.is_reachable is False
        assert result.strategy == "exhausted"

    @pytest.mark.asyncio
    async def test_multiple_targets_first_match(self):
        """If the first target is reachable via fuzzer, stop early."""
        checker = _make_checker(
            client_snapshot=FakeSnapshot(),
            library_snapshot=FakeSnapshot("lib-001"),
            fuzzers=[{"name": "fuzz_a"}],
            reachable=[
                {"name": "func_b", "file_path": "b.c", "depth": 2, "is_external": False},
            ],
        )
        result = await checker.check(
            CLIENT_URL,
            "v1.0",
            LIB_URL,
            LIB_VERSION,
            {"affected_functions": ["func_a", "func_b"]},
        )
        assert result.is_reachable is True
        assert result.strategy == "fuzzer_reaches"


# ═══════════════════════════════════════════════════════════════════════════
#  diff_parser tests
# ═══════════════════════════════════════════════════════════════════════════


class TestParseFunctionsFromPatch:
    """Unit tests for _parse_functions_from_patch."""

    def test_basic_hunk_header(self):
        diff_text = "@@ -123,4 +123,5 @@ static int parse_url(const char *url)\n some code\n"
        funcs = _parse_functions_from_patch(diff_text)
        assert funcs == ["parse_url"]

    def test_multiple_hunks(self):
        diff_text = (
            "@@ -10,3 +10,4 @@ void init_connection(void)\n"
            " code\n"
            "@@ -50,2 +51,3 @@ int handle_request(struct req *r)\n"
            " more code\n"
        )
        funcs = _parse_functions_from_patch(diff_text)
        assert funcs == ["init_connection", "handle_request"]

    def test_no_function_context(self):
        diff_text = "@@ -1,3 +1,4 @@\n just a change with no function context\n"
        funcs = _parse_functions_from_patch(diff_text)
        assert funcs == []

    def test_bare_identifier(self):
        diff_text = "@@ -10,3 +10,4 @@ my_function\n code\n"
        funcs = _parse_functions_from_patch(diff_text)
        assert funcs == ["my_function"]

    def test_deduplication_within_patch(self):
        # _parse_functions_from_patch does NOT deduplicate; caller does.
        diff_text = (
            "@@ -10,3 +10,4 @@ void foo(int x)\n code\n@@ -20,3 +20,4 @@ void foo(int x)\n code\n"
        )
        funcs = _parse_functions_from_patch(diff_text)
        assert funcs == ["foo", "foo"]


class TestExtractFunctionsFromDiff:
    """Integration-level tests for extract_functions_from_diff."""

    @pytest.mark.asyncio
    async def test_extracts_functions_from_c_files(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = {
            "files": [
                {
                    "filename": "lib/url.c",
                    "patch": (
                        "@@ -100,4 +100,5 @@"
                        " static int parse_url(const char *url)\n"
                        " code\n"
                        "@@ -200,3 +201,4 @@"
                        " void Curl_disconnect(struct conn *c)\n"
                        " code\n"
                    ),
                },
                {
                    "filename": "README.md",
                    "patch": "@@ -1,3 +1,4 @@\n some text\n",
                },
            ]
        }

        funcs = await extract_functions_from_diff(mock_client, "curl", "curl", "abc123")
        assert "parse_url" in funcs
        assert "Curl_disconnect" in funcs
        assert len(funcs) == 2

    @pytest.mark.asyncio
    async def test_no_c_files_returns_empty(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = {
            "files": [
                {
                    "filename": "setup.py",
                    "patch": "@@ -1,3 +1,4 @@ def setup()\n code\n",
                },
            ]
        }

        funcs = await extract_functions_from_diff(mock_client, "owner", "repo", "sha")
        assert funcs == []

    @pytest.mark.asyncio
    async def test_fetch_failure_returns_empty(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = RuntimeError("network error")

        funcs = await extract_functions_from_diff(mock_client, "owner", "repo", "sha")
        assert funcs == []

    @pytest.mark.asyncio
    async def test_deduplicates_across_files(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = {
            "files": [
                {
                    "filename": "a.c",
                    "patch": ("@@ -10,3 +10,4 @@ void common_func(int x)\n code\n"),
                },
                {
                    "filename": "b.c",
                    "patch": ("@@ -20,3 +20,4 @@ void common_func(int x)\n code\n"),
                },
            ]
        }

        funcs = await extract_functions_from_diff(mock_client, "owner", "repo", "sha")
        assert funcs == ["common_func"]

    @pytest.mark.asyncio
    async def test_no_patch_field(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = {
            "files": [
                {"filename": "lib/url.c"},
            ]
        }

        funcs = await extract_functions_from_diff(mock_client, "owner", "repo", "sha")
        assert funcs == []
