"""Scheduler — wires all engines into a live pipeline with chained triggers."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnsentinel.engines.dependency_scanner.scanner import DependencyScanner
from vulnsentinel.engines.event_classifier.runner import EventClassifierRunner
from vulnsentinel.engines.event_collector.github_client import GitHubClient
from vulnsentinel.engines.event_collector.runner import EventCollectorRunner
from vulnsentinel.engines.impact_engine.runner import ImpactRunner
from vulnsentinel.engines.notification.runner import NotificationRunner
from vulnsentinel.engines.reachability.runner import ReachabilityRunner
from vulnsentinel.engines.vuln_analyzer.runner import VulnAnalyzerRunner
from vulnsentinel.services.project_service import ProjectService

logger = structlog.get_logger(__name__)


class EngineLoop:
    """Single engine scheduling loop with trigger/timeout wake mechanism."""

    def __init__(
        self,
        name: str,
        run_fn: Callable[[], Awaitable[int]],
        interval: float,
        downstream: asyncio.Event | None = None,
    ) -> None:
        self.name = name
        self.run_fn = run_fn
        self.interval = interval
        self.trigger = asyncio.Event()
        self.downstream = downstream

    async def loop(self) -> None:
        """Run the engine in an infinite loop, waking on trigger or timeout."""
        while True:
            try:
                await asyncio.wait_for(self.trigger.wait(), timeout=self.interval)
                self.trigger.clear()
            except asyncio.TimeoutError:
                pass

            try:
                processed = await self.run_fn()
                logger.info("engine.cycle", engine=self.name, processed=processed)
                if processed > 0 and self.downstream is not None:
                    self.downstream.set()
            except Exception:
                logger.exception("engine.error", engine=self.name)


class Scheduler:
    """Manages lifecycle of all EngineLoop tasks."""

    def __init__(self, loops: list[EngineLoop]) -> None:
        self._loops = loops
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        """Start all engine loops as asyncio tasks."""
        self._tasks = [
            asyncio.create_task(loop.loop(), name=f"engine-{loop.name}") for loop in self._loops
        ]
        # Kick off the first engine immediately
        if self._loops:
            self._loops[0].trigger.set()
        logger.info("scheduler.started", engines=[loop.name for loop in self._loops])

    async def stop(self) -> None:
        """Cancel all engine loops and wait for them to exit."""
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("scheduler.stopped")


def _env_float(key: str, default: float) -> float:
    return float(os.environ.get(key, default))


def create_scheduler(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    scanner: DependencyScanner,
    project_service: ProjectService,
    event_collector_runner: EventCollectorRunner,
    github_client: GitHubClient,
    event_classifier_runner: EventClassifierRunner,
    vuln_analyzer_runner: VulnAnalyzerRunner,
    impact_runner: ImpactRunner,
    notification_runner: NotificationRunner,
    reachability_runner: ReachabilityRunner | None = None,
) -> Scheduler:
    """Build a Scheduler with all engines wired in a chain."""

    # Read intervals from env
    scan_interval = _env_float("VULNSENTINEL_SCAN_INTERVAL", 1800)
    collect_interval = _env_float("VULNSENTINEL_COLLECT_INTERVAL", 600)
    classify_interval = _env_float("VULNSENTINEL_CLASSIFY_INTERVAL", 60)
    analyze_interval = _env_float("VULNSENTINEL_ANALYZE_INTERVAL", 60)
    impact_interval = _env_float("VULNSENTINEL_IMPACT_INTERVAL", 60)
    reach_interval = _env_float("VULNSENTINEL_REACHABILITY_INTERVAL", 120)
    notify_interval = _env_float("VULNSENTINEL_NOTIFY_INTERVAL", 60)

    # Build asyncio.Event chain (created bottom-up so downstream refs exist)
    trigger_notify = asyncio.Event()
    trigger_reach = asyncio.Event()
    trigger_impact = asyncio.Event()
    trigger_analyze = asyncio.Event()
    trigger_classify = asyncio.Event()
    trigger_collect = asyncio.Event()

    # -- Adapter functions (closures over runners + session_factory) --

    async def _scan_due_projects() -> int:
        async with session_factory() as session:
            async with session.begin():
                projects = await project_service.list_due_for_scan(session)
        processed = 0
        for project in projects:
            try:
                async with session_factory() as session:
                    async with session.begin():
                        await scanner.run(session, project.id)
                        processed += 1
            except Exception:
                logger.exception("scan.project_failed", project_id=str(project.id))
        return processed

    async def _collect_events() -> int:
        results = await event_collector_runner.run_all(session_factory, github_client)
        return sum(r.inserted for r in results)

    async def _classify_events() -> int:
        results = await event_classifier_runner.classify_batch(session_factory)
        return len(results)

    async def _analyze_vulns() -> int:
        results = await vuln_analyzer_runner.analyze_batch(session_factory)
        return len(results)

    async def _run_impact() -> int:
        return await impact_runner.run_batch(session_factory)

    async def _run_reachability() -> int:
        if reachability_runner is None:
            return 0
        return await reachability_runner.run_batch(session_factory)

    async def _run_notifications() -> int:
        return await notification_runner.run_batch(session_factory)

    # -- Build loops (order matters for chaining) --

    notification_loop = EngineLoop("notification", _run_notifications, notify_interval)
    notification_loop.trigger = trigger_notify

    reachability_loop = EngineLoop(
        "reachability", _run_reachability, reach_interval, downstream=trigger_notify
    )
    reachability_loop.trigger = trigger_reach

    impact_loop = EngineLoop("impact", _run_impact, impact_interval, downstream=trigger_reach)
    impact_loop.trigger = trigger_impact

    analyze_loop = EngineLoop(
        "vuln_analyzer", _analyze_vulns, analyze_interval, downstream=trigger_impact
    )
    analyze_loop.trigger = trigger_analyze

    classify_loop = EngineLoop(
        "classifier", _classify_events, classify_interval, downstream=trigger_analyze
    )
    classify_loop.trigger = trigger_classify

    collect_loop = EngineLoop(
        "event_collector", _collect_events, collect_interval, downstream=trigger_classify
    )
    collect_loop.trigger = trigger_collect

    scan_loop = EngineLoop(
        "dep_scanner", _scan_due_projects, scan_interval, downstream=trigger_collect
    )

    loops = [
        scan_loop,
        collect_loop,
        classify_loop,
        analyze_loop,
        impact_loop,
        reachability_loop,
        notification_loop,
    ]

    return Scheduler(loops)
