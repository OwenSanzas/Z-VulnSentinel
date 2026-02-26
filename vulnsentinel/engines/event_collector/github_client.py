"""Async GitHub API client with pagination, rate-limit handling, and retries."""

from __future__ import annotations

import asyncio
import os
import re
import time
from collections.abc import AsyncGenerator
from typing import Any

import httpx
import structlog

log = structlog.get_logger("vulnsentinel.engine")

_NEXT_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # seconds


class RateLimitError(Exception):
    """Raised when GitHub rate limit is exhausted and we need to wait."""

    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__(f"rate limit exceeded, retry after {retry_after}s")


class GitHubClient:
    """Thin async wrapper around the GitHub REST API."""

    def __init__(self, token: str | None = None) -> None:
        resolved_token = token or os.environ.get("GITHUB_TOKEN")
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if resolved_token:
            headers["Authorization"] = f"token {resolved_token}"
        self._client = httpx.AsyncClient(
            base_url="https://api.github.com",
            headers=headers,
            timeout=30.0,
        )

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ── public ─────────────────────────────────────────────────────────────

    async def get_paginated(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        max_pages: int = 10,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Yield JSON items from a paginated GitHub API endpoint.

        Automatically follows ``Link: <...>; rel="next"`` headers and
        respects rate-limit headers. Stops after *max_pages* pages.
        """
        url: str | None = path
        params = dict(params or {})
        params.setdefault("per_page", 100)
        page = 0

        while url and page < max_pages:
            response = await self._request_with_retry(url, params if page == 0 else None)
            await self._check_rate_limit(response)

            data = response.json()
            if isinstance(data, list):
                for item in data:
                    yield item
            else:
                yield data

            url = self._parse_next_link(response.headers.get("Link", ""))
            page += 1

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Single-resource GET, returns parsed JSON.

        Unlike :meth:`get_paginated`, this is a one-shot request intended for
        endpoints that return a single object (commit detail, PR detail, etc.).

        *headers* are merged on top of the client's default headers for this
        request only (e.g. a custom ``Accept`` for diff format).
        """
        # Temporarily patch client headers if caller needs overrides.
        original_headers: dict[str, str] | None = None
        if headers:
            original_headers = dict(self._client.headers)
            self._client.headers.update(headers)
        try:
            response = await self._request_with_retry(path, params)
            await self._check_rate_limit(response)
            return response.json()
        finally:
            if original_headers is not None:
                self._client.headers = httpx.Headers(original_headers)

    # ── internal ───────────────────────────────────────────────────────────

    async def _request_with_retry(
        self,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """GET with exponential backoff on 5xx, 403 rate-limit, and timeout errors."""
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = await self._client.get(url, params=params)

                # 403 with rate-limit headers → sleep and retry
                if resp.status_code == 403 and self._is_rate_limited(resp):
                    wait = self._get_rate_limit_wait(resp)
                    log.warning(
                        "github.rate_limit",
                        url=url,
                        wait_seconds=wait,
                        attempt=attempt + 1,
                        max_retries=_MAX_RETRIES,
                    )
                    await asyncio.sleep(wait)
                    last_exc = RateLimitError(wait)
                    continue

                if resp.status_code < 500:
                    resp.raise_for_status()
                    return resp

                # 5xx — retry
                log.warning(
                    "github.server_error",
                    url=url,
                    status=resp.status_code,
                    attempt=attempt + 1,
                    max_retries=_MAX_RETRIES,
                )
                last_exc = httpx.HTTPStatusError(
                    f"{resp.status_code}", request=resp.request, response=resp
                )
            except httpx.TimeoutException as exc:
                log.warning(
                    "github.timeout",
                    url=url,
                    attempt=attempt + 1,
                    max_retries=_MAX_RETRIES,
                )
                last_exc = exc

            if attempt < _MAX_RETRIES - 1:
                delay = _RETRY_BASE_DELAY * (2**attempt)
                await asyncio.sleep(delay)

        raise last_exc  # type: ignore[misc]

    async def _check_rate_limit(self, response: httpx.Response) -> None:
        """Sleep until rate-limit resets if remaining == 0."""
        remaining = self._parse_header_int(response.headers.get("X-RateLimit-Remaining"))
        if remaining is not None and remaining == 0:
            wait = self._get_rate_limit_wait(response)
            log.warning("github.rate_limit_wait", wait_seconds=wait)
            await asyncio.sleep(wait)

    @staticmethod
    def _is_rate_limited(response: httpx.Response) -> bool:
        """Check if a 403 response is due to rate limiting."""
        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining is not None:
            try:
                return int(remaining) == 0
            except (ValueError, TypeError):
                pass
        # GitHub also uses Retry-After header for abuse rate limits
        return "Retry-After" in response.headers

    @staticmethod
    def _get_rate_limit_wait(response: httpx.Response) -> int:
        """Calculate how long to wait based on rate-limit headers."""
        # Prefer Retry-After (used for abuse/secondary rate limits)
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                return max(int(retry_after), 1)
            except (ValueError, TypeError):
                pass
        # Fall back to X-RateLimit-Reset timestamp
        reset_ts = response.headers.get("X-RateLimit-Reset")
        if reset_ts is not None:
            try:
                return max(int(reset_ts) - int(time.time()), 1)
            except (ValueError, TypeError):
                pass
        return 60  # conservative fallback

    @staticmethod
    def _parse_header_int(value: str | None) -> int | None:
        """Safely parse an integer header value."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_next_link(link_header: str) -> str | None:
        """Extract the ``next`` URL from a GitHub ``Link`` header."""
        match = _NEXT_LINK_RE.search(link_header)
        return match.group(1) if match else None
