"""Tests for the event collector engine (no DB required)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vulnsentinel.engines.event_collector.collector import (
    _collect_commits,
    _collect_issues,
    _collect_prs,
    _collect_tags,
    _parse_datetime,
    collect,
    count_by_type,
)
from vulnsentinel.engines.event_collector.github_client import GitHubClient, RateLimitError
from vulnsentinel.engines.event_collector.models import CollectedEvent
from vulnsentinel.engines.event_collector.ref_parser import (
    ISSUE_FIX_PATTERN,
    PR_REF_PATTERN,
    parse_refs,
)

# ── TestRefParser ─────────────────────────────────────────────────────────


class TestRefParser:
    def test_fixes_pattern(self):
        assert ISSUE_FIX_PATTERN.search("Fixes #42")
        assert ISSUE_FIX_PATTERN.search("fixes #1")
        assert ISSUE_FIX_PATTERN.search("Fixed #99")
        assert ISSUE_FIX_PATTERN.search("Closes #7")
        assert ISSUE_FIX_PATTERN.search("closes #100")
        assert ISSUE_FIX_PATTERN.search("Resolves #3")

    def test_fixes_pattern_no_match(self):
        assert ISSUE_FIX_PATTERN.search("fix typo") is None
        assert ISSUE_FIX_PATTERN.search("see issue 42") is None

    def test_pr_ref_pattern(self):
        m = PR_REF_PATTERN.search("feat: add thing (#123)")
        assert m and m.group(1) == "123"

    def test_pr_ref_pattern_no_match(self):
        assert PR_REF_PATTERN.search("feat: add thing") is None
        assert PR_REF_PATTERN.search("issue #123") is None  # no parens

    def test_parse_refs_fills_issue(self):
        ev = CollectedEvent(type="commit", ref="abc", title="Fixes #42")
        parse_refs(ev, "org", "repo")
        assert ev.related_issue_ref == "#42"
        assert ev.related_issue_url == "https://github.com/org/repo/issues/42"

    def test_parse_refs_fills_pr(self):
        ev = CollectedEvent(type="commit", ref="abc", title="feat: do thing (#55)")
        parse_refs(ev, "org", "repo")
        assert ev.related_pr_ref == "#55"
        assert ev.related_pr_url == "https://github.com/org/repo/pull/55"

    def test_parse_refs_scans_message_too(self):
        ev = CollectedEvent(type="commit", ref="abc", title="fix bug", message="Resolves #10")
        parse_refs(ev, "org", "repo")
        assert ev.related_issue_ref == "#10"

    def test_parse_refs_does_not_overwrite_existing(self):
        ev = CollectedEvent(
            type="commit",
            ref="abc",
            title="Fixes #42",
            related_issue_ref="#1",
            related_issue_url="http://existing",
        )
        parse_refs(ev, "org", "repo")
        assert ev.related_issue_ref == "#1"  # unchanged

    def test_parse_refs_both_issue_and_pr(self):
        ev = CollectedEvent(type="commit", ref="abc", title="Fixes #42 (#55)")
        parse_refs(ev, "org", "repo")
        assert ev.related_issue_ref == "#42"
        assert ev.related_pr_ref == "#55"

    def test_parse_refs_no_matches(self):
        ev = CollectedEvent(type="commit", ref="abc", title="refactor code")
        parse_refs(ev, "org", "repo")
        assert ev.related_issue_ref is None
        assert ev.related_pr_ref is None

    def test_parse_refs_pr_pattern_only_matches_title(self):
        """(#N) in message body should NOT populate related_pr_ref."""
        ev = CollectedEvent(
            type="pr_merge",
            ref="42",
            title="feat: add feature",
            message="Related to (#99) and (#100)",
        )
        parse_refs(ev, "org", "repo")
        assert ev.related_pr_ref is None


# ── TestGitHubClient ──────────────────────────────────────────────────────


class TestGitHubClient:
    def test_parse_next_link(self):
        header = (
            '<https://api.github.com/repos/a/b/commits?page=2>; rel="next", '
            '<https://api.github.com/repos/a/b/commits?page=5>; rel="last"'
        )
        url = "https://api.github.com/repos/a/b/commits?page=2"
        assert GitHubClient._parse_next_link(header) == url

    def test_parse_next_link_empty(self):
        assert GitHubClient._parse_next_link("") is None

    def test_parse_next_link_no_next(self):
        header = '<https://api.github.com/repos/a/b/commits?page=1>; rel="last"'
        assert GitHubClient._parse_next_link(header) is None

    @pytest.mark.anyio
    async def test_rate_limit_sleep(self):
        """When remaining=0, _check_rate_limit should sleep."""
        client = GitHubClient.__new__(GitHubClient)
        import time

        reset_time = int(time.time()) + 2  # 2 seconds from now
        response = MagicMock()
        response.headers = {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(reset_time),
        }
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await client._check_rate_limit(response)
            mock_sleep.assert_called_once()
            # Should sleep for at least 1 second
            assert mock_sleep.call_args[0][0] >= 1

    @pytest.mark.anyio
    async def test_rate_limit_no_sleep(self):
        """When remaining > 0, no sleep."""
        client = GitHubClient.__new__(GitHubClient)
        response = MagicMock()
        response.headers = {
            "X-RateLimit-Remaining": "100",
            "X-RateLimit-Reset": "9999999999",
        }
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await client._check_rate_limit(response)
            mock_sleep.assert_not_called()

    @pytest.mark.anyio
    async def test_retry_on_server_error(self):
        """5xx triggers retry with backoff."""
        client = GitHubClient.__new__(GitHubClient)
        client._client = AsyncMock()

        error_resp = MagicMock(spec=httpx.Response)
        error_resp.status_code = 502
        error_resp.request = MagicMock()

        ok_resp = MagicMock(spec=httpx.Response)
        ok_resp.status_code = 200
        ok_resp.raise_for_status = MagicMock()

        client._client.get = AsyncMock(side_effect=[error_resp, ok_resp])

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await client._request_with_retry("/test")
            assert result.status_code == 200
            assert client._client.get.call_count == 2

    @pytest.mark.anyio
    async def test_retry_exhausted(self):
        """After max retries, raises the last exception."""
        client = GitHubClient.__new__(GitHubClient)
        client._client = AsyncMock()

        error_resp = MagicMock(spec=httpx.Response)
        error_resp.status_code = 503
        error_resp.request = MagicMock()

        client._client.get = AsyncMock(return_value=error_resp)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(httpx.HTTPStatusError):
                await client._request_with_retry("/test")
            assert client._client.get.call_count == 3

    @pytest.mark.anyio
    async def test_retry_on_timeout(self):
        """Timeout triggers retry."""
        client = GitHubClient.__new__(GitHubClient)
        client._client = AsyncMock()

        ok_resp = MagicMock(spec=httpx.Response)
        ok_resp.status_code = 200
        ok_resp.raise_for_status = MagicMock()

        client._client.get = AsyncMock(side_effect=[httpx.ReadTimeout("timeout"), ok_resp])

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await client._request_with_retry("/test")
            assert result.status_code == 200

    @pytest.mark.anyio
    async def test_retry_on_403_rate_limit(self):
        """403 with rate-limit headers triggers sleep and retry."""
        client = GitHubClient.__new__(GitHubClient)
        client._client = AsyncMock()

        rate_limited_resp = MagicMock(spec=httpx.Response)
        rate_limited_resp.status_code = 403
        rate_limited_resp.headers = {
            "X-RateLimit-Remaining": "0",
            "Retry-After": "5",
        }

        ok_resp = MagicMock(spec=httpx.Response)
        ok_resp.status_code = 200
        ok_resp.raise_for_status = MagicMock()

        client._client.get = AsyncMock(side_effect=[rate_limited_resp, ok_resp])

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await client._request_with_retry("/test")
            assert result.status_code == 200
            assert client._client.get.call_count == 2

    @pytest.mark.anyio
    async def test_403_rate_limit_exhausted(self):
        """403 rate-limit on all retries raises RateLimitError."""
        client = GitHubClient.__new__(GitHubClient)
        client._client = AsyncMock()

        rate_limited_resp = MagicMock(spec=httpx.Response)
        rate_limited_resp.status_code = 403
        rate_limited_resp.headers = {
            "X-RateLimit-Remaining": "0",
            "Retry-After": "60",
        }

        client._client.get = AsyncMock(return_value=rate_limited_resp)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(RateLimitError):
                await client._request_with_retry("/test")
            assert client._client.get.call_count == 3

    @pytest.mark.anyio
    async def test_403_non_rate_limit_raises(self):
        """403 without rate-limit headers raises HTTPStatusError."""
        client = GitHubClient.__new__(GitHubClient)
        client._client = AsyncMock()

        forbidden_resp = MagicMock(spec=httpx.Response)
        forbidden_resp.status_code = 403
        forbidden_resp.headers = {"X-RateLimit-Remaining": "50"}
        forbidden_resp.request = MagicMock()
        forbidden_resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=forbidden_resp)
        )

        client._client.get = AsyncMock(return_value=forbidden_resp)

        with pytest.raises(httpx.HTTPStatusError):
            await client._request_with_retry("/test")
        # Should not retry — only 1 attempt
        assert client._client.get.call_count == 1

    def test_parse_header_int_valid(self):
        assert GitHubClient._parse_header_int("42") == 42

    def test_parse_header_int_none(self):
        assert GitHubClient._parse_header_int(None) is None

    def test_parse_header_int_garbage(self):
        assert GitHubClient._parse_header_int("not-a-number") is None

    def test_is_rate_limited_by_remaining(self):
        resp = MagicMock()
        resp.headers = {"X-RateLimit-Remaining": "0"}
        assert GitHubClient._is_rate_limited(resp) is True

    def test_is_rate_limited_by_retry_after(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": "120"}
        assert GitHubClient._is_rate_limited(resp) is True

    def test_not_rate_limited(self):
        resp = MagicMock()
        resp.headers = {"X-RateLimit-Remaining": "100"}
        assert GitHubClient._is_rate_limited(resp) is False

    @pytest.mark.anyio
    async def test_get_paginated_multi_page(self):
        """get_paginated follows Link next headers across multiple pages."""
        client = GitHubClient.__new__(GitHubClient)

        page1_resp = MagicMock(spec=httpx.Response)
        page1_resp.status_code = 200
        page1_resp.json.return_value = [{"id": 1}, {"id": 2}]
        page1_resp.headers = {
            "Link": '<https://api.github.com/repos/o/r/commits?page=2>; rel="next"',
            "X-RateLimit-Remaining": "100",
        }
        page1_resp.raise_for_status = MagicMock()

        page2_resp = MagicMock(spec=httpx.Response)
        page2_resp.status_code = 200
        page2_resp.json.return_value = [{"id": 3}]
        page2_resp.headers = {
            "X-RateLimit-Remaining": "99",
        }
        page2_resp.raise_for_status = MagicMock()

        with patch.object(
            client, "_request_with_retry", new_callable=AsyncMock, side_effect=[page1_resp, page2_resp]
        ), patch.object(client, "_check_rate_limit", new_callable=AsyncMock):
            items = []
            async for item in client.get_paginated("/repos/o/r/commits", {"sha": "main"}):
                items.append(item)

        assert len(items) == 3
        assert [i["id"] for i in items] == [1, 2, 3]

    @pytest.mark.anyio
    async def test_get_paginated_respects_max_pages(self):
        """get_paginated stops after max_pages even if Link next exists."""
        client = GitHubClient.__new__(GitHubClient)

        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.return_value = [{"id": 1}]
        resp.headers = {
            "Link": '<https://api.github.com/repos/o/r/commits?page=2>; rel="next"',
            "X-RateLimit-Remaining": "100",
        }
        resp.raise_for_status = MagicMock()

        with patch.object(
            client, "_request_with_retry", new_callable=AsyncMock, return_value=resp
        ), patch.object(client, "_check_rate_limit", new_callable=AsyncMock):
            items = []
            async for item in client.get_paginated("/repos/o/r/commits", max_pages=1):
                items.append(item)

        assert len(items) == 1

    @pytest.mark.anyio
    async def test_check_rate_limit_malformed_header(self):
        """Malformed X-RateLimit-Remaining should not crash."""
        client = GitHubClient.__new__(GitHubClient)
        response = MagicMock()
        response.headers = {"X-RateLimit-Remaining": "garbage"}
        # Should not raise — _parse_header_int returns None
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await client._check_rate_limit(response)
            mock_sleep.assert_not_called()


# ── TestCollectCommits ────────────────────────────────────────────────────


def _mock_client(items: list[dict]) -> GitHubClient:
    """Create a mock GitHubClient that yields the given items from get_paginated."""
    client = AsyncMock(spec=GitHubClient)

    async def _paginated(*args, **kwargs):
        for item in items:
            yield item

    client.get_paginated = _paginated
    return client


class TestCollectCommits:
    @pytest.mark.anyio
    async def test_basic_commit(self):
        client = _mock_client(
            [
                {
                    "sha": "abc123",
                    "html_url": "https://github.com/o/r/commit/abc123",
                    "commit": {
                        "message": "fix: handle null input",
                        "author": {"date": "2025-01-15T10:00:00Z"},
                    },
                    "author": {"login": "dev1"},
                    "parents": [{"sha": "parent1"}],
                }
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_commits(
            client, "o", "r", branch="main", since=since, last_sha=None, max_pages=3
        )
        assert len(events) == 1
        assert events[0].type == "commit"
        assert events[0].ref == "abc123"
        assert events[0].title == "fix: handle null input"
        assert events[0].author == "dev1"

    @pytest.mark.anyio
    async def test_excludes_merge_commits(self):
        client = _mock_client(
            [
                {
                    "sha": "merge1",
                    "html_url": "https://github.com/o/r/commit/merge1",
                    "commit": {
                        "message": "Merge branch 'dev'",
                        "author": {"date": "2025-01-15T10:00:00Z"},
                    },
                    "author": {"login": "dev1"},
                    "parents": [{"sha": "p1"}, {"sha": "p2"}],
                }
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_commits(
            client, "o", "r", branch="main", since=since, last_sha=None, max_pages=3
        )
        assert len(events) == 0

    @pytest.mark.anyio
    async def test_stops_at_last_sha(self):
        client = _mock_client(
            [
                {
                    "sha": "new1",
                    "commit": {"message": "new commit", "author": {"date": "2025-01-15T10:00:00Z"}},
                    "author": {"login": "dev1"},
                    "parents": [{"sha": "p1"}],
                },
                {
                    "sha": "known",
                    "commit": {
                        "message": "known commit",
                        "author": {"date": "2025-01-14T10:00:00Z"},
                    },
                    "author": {"login": "dev1"},
                    "parents": [{"sha": "p0"}],
                },
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_commits(
            client, "o", "r", branch="main", since=since, last_sha="known", max_pages=3
        )
        assert len(events) == 1
        assert events[0].ref == "new1"

    @pytest.mark.anyio
    async def test_multiline_message(self):
        client = _mock_client(
            [
                {
                    "sha": "abc",
                    "commit": {
                        "message": "title line\n\nbody text here",
                        "author": {"date": "2025-01-15T10:00:00Z"},
                    },
                    "author": {"login": "dev1"},
                    "parents": [{"sha": "p1"}],
                }
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_commits(
            client, "o", "r", branch="main", since=since, last_sha=None, max_pages=3
        )
        assert events[0].title == "title line"
        assert events[0].message == "title line\n\nbody text here"


# ── TestCollectPrs ────────────────────────────────────────────────────────


class TestCollectPrs:
    @pytest.mark.anyio
    async def test_collects_merged_pr(self):
        client = _mock_client(
            [
                {
                    "number": 42,
                    "title": "feat: add feature",
                    "html_url": "https://github.com/o/r/pull/42",
                    "merged_at": "2025-01-15T12:00:00Z",
                    "merge_commit_sha": "sha123",
                    "user": {"login": "dev1"},
                    "body": "PR description",
                }
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_prs(client, "o", "r", since=since, max_pages=3)
        assert len(events) == 1
        assert events[0].type == "pr_merge"
        assert events[0].ref == "42"
        assert events[0].related_commit_sha == "sha123"

    @pytest.mark.anyio
    async def test_skips_unmerged_pr(self):
        client = _mock_client(
            [
                {
                    "number": 43,
                    "title": "draft",
                    "html_url": "https://github.com/o/r/pull/43",
                    "merged_at": None,
                    "user": {"login": "dev1"},
                    "body": None,
                }
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_prs(client, "o", "r", since=since, max_pages=3)
        assert len(events) == 0

    @pytest.mark.anyio
    async def test_skips_old_pr_without_breaking(self):
        """Old PR with recent comment should not cause us to miss newer merges."""
        client = _mock_client(
            [
                # PR#2: merged 6 months ago, but got a comment today → updated_at is recent
                {
                    "number": 2,
                    "title": "old PR with comment",
                    "html_url": "https://github.com/o/r/pull/2",
                    "merged_at": "2024-06-01T12:00:00Z",
                    "merge_commit_sha": "old_sha",
                    "user": {"login": "dev"},
                    "body": None,
                },
                # PR#1: merged yesterday — should NOT be missed
                {
                    "number": 1,
                    "title": "recent merge",
                    "html_url": "https://github.com/o/r/pull/1",
                    "merged_at": "2025-01-14T12:00:00Z",
                    "merge_commit_sha": "new_sha",
                    "user": {"login": "dev"},
                    "body": None,
                },
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_prs(client, "o", "r", since=since, max_pages=3)
        # Must collect PR#1 even though PR#2 (merged before since) appeared first
        assert len(events) == 1
        assert events[0].ref == "1"

    @pytest.mark.anyio
    async def test_stops_when_merged_before_since(self):
        client = _mock_client(
            [
                {
                    "number": 44,
                    "title": "old PR",
                    "html_url": "https://github.com/o/r/pull/44",
                    "merged_at": "2024-12-01T12:00:00Z",
                    "merge_commit_sha": "old_sha",
                    "user": {"login": "dev1"},
                    "body": None,
                }
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_prs(client, "o", "r", since=since, max_pages=3)
        assert len(events) == 0


# ── TestCollectTags ───────────────────────────────────────────────────────


class TestCollectTags:
    @pytest.mark.anyio
    async def test_collects_new_tags(self):
        client = _mock_client(
            [
                {"name": "v2.0.0", "commit": {"sha": "sha2"}},
                {"name": "v1.0.0", "commit": {"sha": "sha1"}},
            ]
        )
        events = await _collect_tags(client, "o", "r", latest_tag=None, max_pages=3)
        assert len(events) == 2
        assert events[0].type == "tag"
        assert events[0].ref == "v2.0.0"

    @pytest.mark.anyio
    async def test_stops_at_latest_tag(self):
        client = _mock_client(
            [
                {"name": "v2.0.0", "commit": {"sha": "sha2"}},
                {"name": "v1.0.0", "commit": {"sha": "sha1"}},
            ]
        )
        events = await _collect_tags(client, "o", "r", latest_tag="v1.0.0", max_pages=3)
        assert len(events) == 1
        assert events[0].ref == "v2.0.0"

    @pytest.mark.anyio
    async def test_no_new_tags(self):
        client = _mock_client(
            [
                {"name": "v1.0.0", "commit": {"sha": "sha1"}},
            ]
        )
        events = await _collect_tags(client, "o", "r", latest_tag="v1.0.0", max_pages=3)
        assert len(events) == 0


# ── TestCollectIssues ─────────────────────────────────────────────────────


class TestCollectIssues:
    @pytest.mark.anyio
    async def test_collects_bug_issue(self):
        client = _mock_client(
            [
                {
                    "number": 10,
                    "title": "crash on null input",
                    "html_url": "https://github.com/o/r/issues/10",
                    "user": {"login": "reporter"},
                    "created_at": "2025-01-15T10:00:00Z",
                    "body": "Steps to reproduce...",
                }
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_issues(client, "o", "r", since=since, max_pages=3)
        assert len(events) == 1
        assert events[0].type == "bug_issue"
        assert events[0].ref == "10"

    @pytest.mark.anyio
    async def test_excludes_pull_requests(self):
        client = _mock_client(
            [
                {
                    "number": 11,
                    "title": "PR disguised as issue",
                    "html_url": "https://github.com/o/r/issues/11",
                    "user": {"login": "dev"},
                    "created_at": "2025-01-15T10:00:00Z",
                    "body": None,
                    "pull_request": {"url": "https://api.github.com/repos/o/r/pulls/11"},
                }
            ]
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = await _collect_issues(client, "o", "r", since=since, max_pages=3)
        assert len(events) == 0


# ── TestCollect (integration) ─────────────────────────────────────────────


class TestCollect:
    @pytest.mark.anyio
    async def test_collect_merges_all_types(self):
        """collect() should call all 4 sub-collectors and merge results."""
        client = AsyncMock(spec=GitHubClient)

        call_count = 0

        async def _paginated(path, params=None, *, max_pages=10):
            nonlocal call_count
            call_count += 1
            if "/commits" in path:
                yield {
                    "sha": "abc",
                    "commit": {
                        "message": "fix: bug (#5)\n\nResolves #3",
                        "author": {"date": "2025-01-15T10:00:00Z"},
                    },
                    "author": {"login": "dev"},
                    "parents": [{"sha": "p1"}],
                    "html_url": "https://github.com/o/r/commit/abc",
                }
            elif "/pulls" in path:
                yield {
                    "number": 5,
                    "title": "fix: bug",
                    "html_url": "https://github.com/o/r/pull/5",
                    "merged_at": "2025-01-15T12:00:00Z",
                    "merge_commit_sha": "abc",
                    "user": {"login": "dev"},
                    "body": None,
                }
            elif "/tags" in path:
                yield {"name": "v1.0.0", "commit": {"sha": "tag_sha"}}
            elif "/issues" in path:
                yield {
                    "number": 3,
                    "title": "crash on null",
                    "html_url": "https://github.com/o/r/issues/3",
                    "user": {"login": "reporter"},
                    "created_at": "2025-01-15T10:00:00Z",
                    "body": "...",
                }

        client.get_paginated = _paginated

        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events, errors = await collect(client, "o", "r", since=since)

        assert len(events) == 4
        assert errors == []
        types = {e.type for e in events}
        assert types == {"commit", "pr_merge", "tag", "bug_issue"}

        # Verify ref parsing ran
        commit_ev = next(e for e in events if e.type == "commit")
        assert commit_ev.related_issue_ref == "#3"
        assert commit_ev.related_pr_ref == "#5"

    @pytest.mark.anyio
    async def test_collect_first_time_uses_default_since(self):
        """When since=None, collect() should use a default lookback window."""
        client = AsyncMock(spec=GitHubClient)

        async def _paginated(path, params=None, *, max_pages=10):
            # Verify max_pages is limited for first-time collection
            assert max_pages == 3
            return
            yield  # make it a generator

        client.get_paginated = _paginated

        events, errors = await collect(client, "o", "r", since=None)
        assert events == []
        assert errors == []

    @pytest.mark.anyio
    async def test_collect_handles_sub_task_failure(self):
        """If a sub-collector raises, collect() logs and continues."""
        client = AsyncMock(spec=GitHubClient)

        call_paths = []

        async def _paginated(path, params=None, *, max_pages=10):
            call_paths.append(path)
            if "/commits" in path:
                raise httpx.HTTPStatusError("fail", request=MagicMock(), response=MagicMock())
            elif "/tags" in path:
                yield {"name": "v1.0.0", "commit": {"sha": "sha1"}}
            # PRs and issues return nothing
            return
            yield

        client.get_paginated = _paginated

        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events, errors = await collect(client, "o", "r", since=since)

        # Only tag should succeed
        assert len(events) == 1
        assert events[0].type == "tag"
        # Commits sub-collector failed
        assert len(errors) == 1
        assert "collect_commits" in errors[0]


# ── TestHelpers ───────────────────────────────────────────────────────────


class TestHelpers:
    def test_parse_datetime_iso(self):
        dt = _parse_datetime("2025-01-15T10:30:00Z")
        assert dt == datetime(2025, 1, 15, 10, 30, tzinfo=timezone.utc)

    def test_parse_datetime_none(self):
        assert _parse_datetime(None) is None
        assert _parse_datetime("") is None

    def test_parse_datetime_with_offset(self):
        dt = _parse_datetime("2025-01-15T10:30:00+00:00")
        assert dt is not None

    def test_count_by_type(self):
        events = [
            CollectedEvent(type="commit", ref="a", title="t"),
            CollectedEvent(type="commit", ref="b", title="t"),
            CollectedEvent(type="tag", ref="v1", title="v1"),
        ]
        result = count_by_type(events)
        assert result == {"commit": 2, "tag": 1}


# ── TestParseRepoUrl ─────────────────────────────────────────────────────


class TestParseRepoUrl:
    def test_https_url(self):
        from vulnsentinel.core.github import parse_repo_url

        assert parse_repo_url("https://github.com/org/repo") == ("org", "repo")

    def test_https_url_with_dot_git(self):
        from vulnsentinel.core.github import parse_repo_url

        assert parse_repo_url("https://github.com/org/repo.git") == ("org", "repo")

    def test_https_url_trailing_slash(self):
        from vulnsentinel.core.github import parse_repo_url

        assert parse_repo_url("https://github.com/org/repo/") == ("org", "repo")

    def test_ssh_url(self):
        from vulnsentinel.core.github import parse_repo_url

        assert parse_repo_url("git@github.com:org/repo.git") == ("org", "repo")

    def test_ssh_url_no_dot_git(self):
        from vulnsentinel.core.github import parse_repo_url

        assert parse_repo_url("git@github.com:org/repo") == ("org", "repo")

    def test_invalid_url_raises(self):
        from vulnsentinel.core.github import parse_repo_url

        with pytest.raises(ValueError, match="cannot parse"):
            parse_repo_url("not-a-url")
