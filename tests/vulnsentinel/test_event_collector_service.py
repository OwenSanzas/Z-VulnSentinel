"""Tests for EventCollectorRunner (mock engine + mock Services)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnsentinel.engines.event_collector.models import CollectedEvent
from vulnsentinel.engines.event_collector.runner import EventCollectorRunner

# ── helpers ───────────────────────────────────────────────────────────────


def _fake_library(**overrides):
    lib = MagicMock()
    lib.id = overrides.get("id", uuid.uuid4())
    lib.name = overrides.get("name", "test-lib")
    lib.repo_url = overrides.get("repo_url", "https://github.com/org/test-lib")
    lib.platform = overrides.get("platform", "github")
    lib.default_branch = overrides.get("default_branch", "main")
    lib.latest_commit_sha = overrides.get("latest_commit_sha", None)
    lib.latest_tag_version = overrides.get("latest_tag_version", None)
    lib.last_scanned_at = overrides.get("last_scanned_at", None)
    return lib


def _make_runner():
    library_service = AsyncMock()
    event_service = AsyncMock()
    runner = EventCollectorRunner(library_service, event_service)
    return runner, library_service, event_service


# ── TestRun ───────────────────────────────────────────────────────────────


class TestRun:
    @pytest.mark.anyio
    async def test_normal_flow(self):
        runner, library_service, event_service = _make_runner()
        lib = _fake_library()
        library_service.get_by_id.return_value = lib
        event_service.batch_create.return_value = 2

        client = AsyncMock()
        collected = [
            CollectedEvent(type="commit", ref="sha1", title="fix: bug"),
            CollectedEvent(type="tag", ref="v1.0", title="v1.0"),
        ]

        with patch(
            "vulnsentinel.engines.event_collector.runner.collect",
            return_value=(
                collected,
                [],
                {"commits": "ok", "prs": "ok", "tags": "ok", "issues": "ok", "ghsa": "ok"},
            ),
        ):
            result = await runner.run(AsyncMock(), lib.id, client)

        assert result.fetched == 2
        assert result.inserted == 2
        assert result.by_type == {"commit": 1, "tag": 1}
        assert result.errors == []
        event_service.batch_create.assert_called_once()
        library_service.update_pointers.assert_called_once()

    @pytest.mark.anyio
    async def test_library_not_found(self):
        runner, library_service, event_service = _make_runner()
        library_service.get_by_id.return_value = None

        lib_id = uuid.uuid4()
        result = await runner.run(AsyncMock(), lib_id, AsyncMock())

        assert result.library_id == lib_id
        assert "not found" in result.errors[0]

    @pytest.mark.anyio
    async def test_non_github_platform(self):
        runner, library_service, event_service = _make_runner()
        lib = _fake_library(platform="gitlab")
        library_service.get_by_id.return_value = lib

        result = await runner.run(AsyncMock(), lib.id, AsyncMock())

        assert "unsupported platform" in result.errors[0]

    @pytest.mark.anyio
    async def test_invalid_repo_url(self):
        runner, library_service, event_service = _make_runner()
        lib = _fake_library(repo_url="not-a-url")
        library_service.get_by_id.return_value = lib

        result = await runner.run(AsyncMock(), lib.id, AsyncMock())

        assert len(result.errors) == 1
        assert "cannot parse" in result.errors[0]

    @pytest.mark.anyio
    async def test_no_events_still_updates_pointers(self):
        runner, library_service, event_service = _make_runner()
        lib = _fake_library()
        library_service.get_by_id.return_value = lib

        with patch(
            "vulnsentinel.engines.event_collector.runner.collect",
            return_value=(
                [],
                [],
                {"commits": "ok", "prs": "ok", "tags": "ok", "issues": "ok", "ghsa": "ok"},
            ),
        ):
            result = await runner.run(AsyncMock(), lib.id, AsyncMock())

        assert result.fetched == 0
        assert result.inserted == 0
        library_service.update_pointers.assert_called_once()
        event_service.batch_create.assert_not_called()

    @pytest.mark.anyio
    async def test_no_events_with_errors_skips_pointer_update(self):
        """When all sub-collectors fail, don't update last_scanned_at
        so the library is retried on the next cycle."""
        runner, library_service, event_service = _make_runner()
        lib = _fake_library()
        library_service.get_by_id.return_value = lib

        with patch(
            "vulnsentinel.engines.event_collector.runner.collect",
            return_value=(
                [],
                ["commits failed", "tags failed"],
                {"commits": "error", "prs": "ok", "tags": "error", "issues": "ok", "ghsa": "ok"},
            ),
        ):
            result = await runner.run(AsyncMock(), lib.id, AsyncMock())

        assert result.fetched == 0
        assert len(result.errors) == 2
        library_service.update_pointers.assert_called_once()
        call_kwargs = library_service.update_pointers.call_args.kwargs
        assert call_kwargs["collect_status"] == "unhealthy"
        event_service.batch_create.assert_not_called()

    @pytest.mark.anyio
    async def test_updates_latest_commit_and_tag(self):
        runner, library_service, event_service = _make_runner()
        lib = _fake_library()
        library_service.get_by_id.return_value = lib
        event_service.batch_create.return_value = 3

        collected = [
            CollectedEvent(type="commit", ref="sha_new", title="new"),
            CollectedEvent(type="commit", ref="sha_old", title="old"),
            CollectedEvent(type="tag", ref="v2.0", title="v2.0"),
        ]

        with patch(
            "vulnsentinel.engines.event_collector.runner.collect",
            return_value=(
                collected,
                [],
                {"commits": "ok", "prs": "ok", "tags": "ok", "issues": "ok", "ghsa": "ok"},
            ),
        ):
            await runner.run(AsyncMock(), lib.id, AsyncMock())

        call_kwargs = library_service.update_pointers.call_args[1]
        # First commit in list = newest
        assert call_kwargs["latest_commit_sha"] == "sha_new"
        assert call_kwargs["latest_tag_version"] == "v2.0"


# ── TestRunAll ────────────────────────────────────────────────────────────


class _FakeBeginCtx:
    """Minimal async context manager for ``session.begin()``."""

    async def __aenter__(self):
        return None

    async def __aexit__(self, *exc):
        return False


class _FakeSessionCtx:
    """Minimal async context manager for ``session_factory()``."""

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc):
        return False


def _mock_session_factory():
    """Build a mock that behaves like async_sessionmaker."""
    session = AsyncMock()
    session.begin = MagicMock(return_value=_FakeBeginCtx())

    factory = MagicMock(return_value=_FakeSessionCtx(session))
    return factory, session


class TestRunAll:
    @pytest.mark.anyio
    async def test_runs_all_due_libraries(self):
        runner, library_service, event_service = _make_runner()
        lib1 = _fake_library(name="lib1")
        lib2 = _fake_library(name="lib2")

        library_service.list_due_for_collect.return_value = [lib1, lib2]
        library_service.get_by_id.return_value = _fake_library()
        event_service.batch_create.return_value = 0

        factory, _ = _mock_session_factory()

        with patch(
            "vulnsentinel.engines.event_collector.runner.collect",
            return_value=(
                [],
                [],
                {"commits": "ok", "prs": "ok", "tags": "ok", "issues": "ok", "ghsa": "ok"},
            ),
        ):
            results = await runner.run_all(factory, AsyncMock())

        assert len(results) == 2

    @pytest.mark.anyio
    async def test_no_due_libraries(self):
        runner, library_service, event_service = _make_runner()
        library_service.list_due_for_collect.return_value = []

        factory, _ = _mock_session_factory()

        results = await runner.run_all(factory, AsyncMock())
        assert results == []

    @pytest.mark.anyio
    async def test_single_library_failure_isolated(self):
        runner, library_service, event_service = _make_runner()
        lib1 = _fake_library(name="lib1")
        lib2 = _fake_library(name="lib2")
        library_service.list_due_for_collect.return_value = [lib1, lib2]

        call_count = 0

        async def _mock_run(session, lib_id, client):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("boom")
            from vulnsentinel.engines.event_collector.models import CollectResult

            return CollectResult(library_id=lib_id, fetched=1, inserted=1)

        runner.run = _mock_run

        factory, _ = _mock_session_factory()

        results = await runner.run_all(factory, AsyncMock())
        assert len(results) == 2
        # One succeeded, one failed
        errored = [r for r in results if r.errors]
        succeeded = [r for r in results if not r.errors]
        assert len(errored) == 1
        assert "boom" in errored[0].errors[0]
        assert len(succeeded) == 1
