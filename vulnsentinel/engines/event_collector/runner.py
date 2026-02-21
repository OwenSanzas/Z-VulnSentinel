"""EventCollectorRunner — orchestrates collect engine + Service-layer DB writes."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import asdict
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnsentinel.core.github import parse_repo_url
from vulnsentinel.engines.event_collector.collector import collect, count_by_type
from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.engines.event_collector.models import CollectResult
from vulnsentinel.services.event_service import EventService
from vulnsentinel.services.library_service import LibraryService

logger = logging.getLogger(__name__)

_MAX_CONCURRENCY = 5


class EventCollectorRunner:
    """Orchestration layer: pure engine → Service-layer DB writes."""

    def __init__(self, library_service: LibraryService, event_service: EventService) -> None:
        self._library_service = library_service
        self._event_service = event_service

    async def run(
        self,
        session: AsyncSession,
        library_id: uuid.UUID,
        client: GitHubClient,
    ) -> CollectResult:
        """Collect events for a single library and persist them.

        1. Read library via LibraryService
        2. Call engine ``collect()``
        3. Batch-insert events via EventService
        4. Update library pointers via LibraryService
        """
        result = CollectResult(library_id=library_id)

        library = await self._library_service.get_by_id(session, library_id)
        if library is None:
            result.errors.append(f"library {library_id} not found")
            return result

        if library.platform != "github":
            result.errors.append(f"unsupported platform: {library.platform}")
            return result

        try:
            owner, repo = parse_repo_url(library.repo_url)
        except ValueError as exc:
            result.errors.append(str(exc))
            return result

        events, collect_errors = await collect(
            client,
            owner,
            repo,
            branch=library.default_branch,
            since=library.last_activity_at,
            last_sha=library.latest_commit_sha,
            latest_tag=library.latest_tag_version,
        )

        result.errors.extend(collect_errors)
        result.fetched = len(events)
        result.by_type = count_by_type(events)

        if not events:
            # Update last_activity_at only if no errors — if all sub-collectors
            # failed we want to retry on the next cycle, not suppress for 75 min.
            if not collect_errors:
                await self._library_service.update_pointers(
                    session,
                    library_id,
                    last_activity_at=datetime.now(timezone.utc),
                )
            return result

        # Build dicts for batch_create
        rows = []
        for ev in events:
            d = asdict(ev)
            d["library_id"] = library_id
            rows.append(d)

        inserted = await self._event_service.batch_create(session, rows)
        result.inserted = inserted

        # Update pointers
        new_sha = None
        new_tag = None
        for ev in events:
            if ev.type == "commit" and new_sha is None:
                new_sha = ev.ref
            if ev.type == "tag" and new_tag is None:
                new_tag = ev.ref

        await self._library_service.update_pointers(
            session,
            library_id,
            latest_commit_sha=new_sha,
            latest_tag_version=new_tag,
            last_activity_at=datetime.now(timezone.utc),
        )

        return result

    async def run_all(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        client: GitHubClient,
    ) -> list[CollectResult]:
        """Collect events for all due libraries with bounded concurrency."""
        # Get due libraries in a short-lived session
        async with session_factory() as session:
            async with session.begin():
                libraries = await self._library_service.list_due_for_collect(session)

        if not libraries:
            return []

        sem = asyncio.Semaphore(_MAX_CONCURRENCY)

        async def _run_one(lib_id: uuid.UUID) -> CollectResult:
            async with sem:
                try:
                    async with session_factory() as session:
                        async with session.begin():
                            return await self.run(session, lib_id, client)
                except Exception as exc:
                    logger.error("collect failed for %s: %s", lib_id, exc)
                    r = CollectResult(library_id=lib_id)
                    r.errors.append(str(exc))
                    return r

        tasks = [_run_one(lib.id) for lib in libraries]
        return list(await asyncio.gather(*tasks))
