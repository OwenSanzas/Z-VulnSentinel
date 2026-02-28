"""Unit tests for EngineLoop and Scheduler."""

from __future__ import annotations

import asyncio

import pytest

from vulnsentinel.scheduler import EngineLoop, Scheduler


@pytest.fixture
def make_loop():
    """Factory for creating EngineLoop instances with a controllable run_fn."""

    def _make(
        *,
        name: str = "test",
        return_value: int = 0,
        interval: float = 100,
        downstream: asyncio.Event | None = None,
        side_effect: Exception | None = None,
    ) -> tuple[EngineLoop, list[int]]:
        calls: list[int] = []

        async def run_fn() -> int:
            calls.append(1)
            if side_effect is not None:
                raise side_effect
            return return_value

        loop = EngineLoop(name, run_fn, interval, downstream=downstream)
        return loop, calls

    return _make


@pytest.mark.asyncio
async def test_loop_runs_on_timeout(make_loop):
    """Loop fires after interval timeout when no trigger is set."""
    loop, calls = make_loop(interval=0.05)

    task = asyncio.create_task(loop.loop())
    try:
        await asyncio.wait_for(_wait_until(lambda: len(calls) >= 1), timeout=1.0)
        assert len(calls) >= 1
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_loop_runs_on_trigger(make_loop):
    """Setting trigger wakes the loop immediately."""
    loop, calls = make_loop(interval=100)  # very long interval

    task = asyncio.create_task(loop.loop())
    try:
        # Give the loop a moment to start waiting
        await asyncio.sleep(0.01)
        loop.trigger.set()
        await asyncio.wait_for(_wait_until(lambda: len(calls) >= 1), timeout=1.0)
        assert len(calls) >= 1
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_chain_propagation(make_loop):
    """Upstream processed > 0 sets downstream trigger."""
    downstream = asyncio.Event()
    loop, calls = make_loop(return_value=5, interval=100, downstream=downstream)

    task = asyncio.create_task(loop.loop())
    try:
        await asyncio.sleep(0.01)
        loop.trigger.set()
        await asyncio.wait_for(downstream.wait(), timeout=1.0)
        assert downstream.is_set()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_no_chain_on_zero(make_loop):
    """Upstream processed == 0 does NOT set downstream trigger."""
    downstream = asyncio.Event()
    loop, calls = make_loop(return_value=0, interval=100, downstream=downstream)

    task = asyncio.create_task(loop.loop())
    try:
        await asyncio.sleep(0.01)
        loop.trigger.set()
        # Wait long enough for the run_fn to complete
        await asyncio.wait_for(_wait_until(lambda: len(calls) >= 1), timeout=1.0)
        # Give a small window to see if downstream gets set (it shouldn't)
        await asyncio.sleep(0.05)
        assert not downstream.is_set()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_exception_does_not_crash(make_loop):
    """run_fn raising an exception does not crash the loop; it continues."""
    loop, calls = make_loop(
        interval=0.05,
        side_effect=RuntimeError("boom"),
    )

    task = asyncio.create_task(loop.loop())
    try:
        await asyncio.wait_for(_wait_until(lambda: len(calls) >= 2), timeout=2.0)
        assert len(calls) >= 2  # loop kept running after the error
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_scheduler_start_stop(make_loop):
    """Scheduler lifecycle: start creates tasks, stop cancels them cleanly."""
    loop1, calls1 = make_loop(name="a", interval=0.05)
    loop2, calls2 = make_loop(name="b", interval=0.05)

    scheduler = Scheduler([loop1, loop2])
    await scheduler.start()

    # Wait for at least one cycle on each
    await asyncio.wait_for(
        _wait_until(lambda: len(calls1) >= 1 and len(calls2) >= 1),
        timeout=2.0,
    )

    await scheduler.stop()
    assert all(t.done() for t in scheduler._tasks) or len(scheduler._tasks) == 0


@pytest.mark.asyncio
async def test_scheduler_start_triggers_first_loop():
    """start() sets trigger on the first loop so it runs immediately."""
    calls: list[int] = []

    async def run_fn() -> int:
        calls.append(1)
        return 0

    loop = EngineLoop("first", run_fn, interval=100)
    scheduler = Scheduler([loop])
    await scheduler.start()
    try:
        await asyncio.wait_for(_wait_until(lambda: len(calls) >= 1), timeout=1.0)
        assert len(calls) >= 1
    finally:
        await scheduler.stop()


async def _wait_until(predicate, poll: float = 0.01):
    """Poll until predicate returns True."""
    while not predicate():
        await asyncio.sleep(poll)
