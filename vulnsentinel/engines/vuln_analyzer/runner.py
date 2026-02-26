"""VulnAnalyzerRunner — orchestrates analysis + DB writes."""

from __future__ import annotations

import asyncio

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnsentinel.agent.agents.analyzer import VulnAnalysisResult
from vulnsentinel.core.github import parse_repo_url
from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.engines.vuln_analyzer.analyzer import analyze
from vulnsentinel.models.event import Event
from vulnsentinel.services.event_service import EventService
from vulnsentinel.services.library_service import LibraryService
from vulnsentinel.services.upstream_vuln_service import UpstreamVulnService

log = structlog.get_logger("vulnsentinel.engine")


class VulnAnalyzerRunner:
    """Integrated mode: analyze bugfix events + persist results to DB."""

    def __init__(
        self,
        event_service: EventService,
        upstream_vuln_service: UpstreamVulnService,
        library_service: LibraryService,
        github_client: GitHubClient,
    ) -> None:
        self._event_service = event_service
        self._vuln_service = upstream_vuln_service
        self._library_service = library_service
        self._client = github_client

    async def analyze_one(
        self,
        session: AsyncSession,
        event: Event,
    ) -> list[VulnAnalysisResult]:
        """Analyze a single bugfix event, writing results to DB.

        A single event may contain multiple independent vulnerability fixes.
        For each vulnerability found:
          create (flush) → update_analysis → publish.

        On analysis failure: create a placeholder vuln, set_error, re-raise.
        The placeholder prevents ``list_bugfix_without_vuln`` from
        re-fetching the same event on the next poll.
        """
        library = await self._library_service.get_by_id(session, event.library_id)
        if library is None:
            raise ValueError(f"library {event.library_id} not found for event {event.id}")

        owner, repo = parse_repo_url(library.repo_url)

        # Create a placeholder vuln so the event is never re-polled,
        # even if analyze() fails.
        placeholder = await self._vuln_service.create(
            session,
            event_id=event.id,
            library_id=library.id,
            commit_sha=event.ref,
        )
        await session.flush()

        try:
            results = await analyze(self._client, owner, repo, event)  # type: ignore[arg-type]
        except Exception as exc:
            await self._vuln_service.set_error(session, placeholder.id, str(exc))
            await session.commit()
            raise

        # First result reuses the placeholder; additional results get new records.
        for i, result in enumerate(results):
            if i == 0:
                vuln = placeholder
            else:
                vuln = await self._vuln_service.create(
                    session,
                    event_id=event.id,
                    library_id=library.id,
                    commit_sha=event.ref,
                )
                await session.flush()

            await self._vuln_service.update_analysis(
                session,
                vuln.id,
                vuln_type=result.vuln_type,
                severity=result.severity,
                affected_versions=result.affected_versions,
                summary=result.summary,
                reasoning=result.reasoning,
                upstream_poc=result.upstream_poc,
            )
            await self._vuln_service.publish(session, vuln.id)

        return results

    async def analyze_batch(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        limit: int = 10,
        concurrency: int = 3,
    ) -> list[tuple[Event, list[VulnAnalysisResult]]]:
        """Analyze up to *limit* bugfix events with bounded concurrency.

        Each concurrent task gets its own ``AsyncSession`` from *session_factory*
        to avoid SQLAlchemy concurrent-access errors.
        """
        async with session_factory() as session:
            events = await self._event_service.list_bugfix_without_vuln(session, limit)
        if not events:
            return []

        sem = asyncio.Semaphore(concurrency)
        results: list[tuple[Event, list[VulnAnalysisResult]]] = []

        async def _run(ev: Event) -> tuple[Event, list[VulnAnalysisResult]]:
            async with sem, session_factory() as sess:
                r = await self.analyze_one(sess, ev)
                await sess.commit()
                return (ev, r)

        tasks = [_run(ev) for ev in events]
        for coro in asyncio.as_completed(tasks):
            try:
                pair = await coro
                results.append(pair)
            except Exception:
                log.error("analyzer.batch_event_failed", exc_info=True)

        return results
