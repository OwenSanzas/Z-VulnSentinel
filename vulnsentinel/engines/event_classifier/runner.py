"""EventClassifierRunner — orchestrates classification + DB writes."""

from __future__ import annotations

import asyncio

import structlog

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnsentinel.agent.agents.classifier import ClassificationResult
from vulnsentinel.core.github import parse_repo_url
from vulnsentinel.engines.event_classifier.classifier import classify
from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.models.event import Event
from vulnsentinel.services.event_service import EventService
from vulnsentinel.services.library_service import LibraryService

log = structlog.get_logger("vulnsentinel.engine")


class EventClassifierRunner:
    """Integrated mode: classify events + persist results to DB."""

    def __init__(
        self,
        event_service: EventService,
        library_service: LibraryService,
        github_client: GitHubClient,
    ) -> None:
        self._event_service = event_service
        self._library_service = library_service
        self._client = github_client

    async def classify_one(
        self,
        session: AsyncSession,
        event: Event,
    ) -> ClassificationResult:
        """Classify a single event, updating the DB row.

        Delegates to the pure :func:`classify` function, then persists.
        """
        library = await self._library_service.get_by_id(session, event.library_id)
        if library is None:
            raise ValueError(
                f"library {event.library_id} not found for event {event.id}"
            )

        owner, repo = parse_repo_url(library.repo_url)
        result = await classify(self._client, owner, repo, event)  # type: ignore[arg-type]

        await self._event_service.update_classification(
            session,
            event.id,
            classification=result.classification,
            confidence=result.confidence,
        )
        return result

    async def classify_batch(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        limit: int = 10,
        concurrency: int = 3,
    ) -> list[tuple[Event, ClassificationResult]]:
        """Classify up to *limit* unclassified events with bounded concurrency.

        Each concurrent task gets its own ``AsyncSession`` from *session_factory*
        to avoid SQLAlchemy concurrent-access errors.
        """
        # Fetch the event list with a short-lived session.
        async with session_factory() as session:
            events = await self._event_service.list_unclassified(session, limit)
        if not events:
            return []

        sem = asyncio.Semaphore(concurrency)
        results: list[tuple[Event, ClassificationResult]] = []

        async def _run(ev: Event) -> tuple[Event, ClassificationResult]:
            async with sem, session_factory() as sess:
                r = await self.classify_one(sess, ev)
                await sess.commit()
                return (ev, r)

        tasks = [_run(ev) for ev in events]
        for coro in asyncio.as_completed(tasks):
            try:
                pair = await coro
                results.append(pair)
            except Exception:
                log.error("classifier.batch_event_failed", exc_info=True)

        return results
