import asyncio
import threading

import pytest

from app.engine.subprocess_loop import SubprocessEventLoop


@pytest.mark.asyncio
async def test_work_runs_on_a_dedicated_event_loop_thread():
    runner = SubprocessEventLoop()
    caller_thread = threading.get_ident()
    caller_loop = asyncio.get_running_loop()

    async def runtime_identity():
        return threading.get_ident(), asyncio.get_running_loop()

    try:
        worker_thread, worker_loop = await runner.run(runtime_identity())
    finally:
        runner.close()

    assert worker_thread != caller_thread
    assert worker_loop is not caller_loop


def test_windows_uses_a_proactor_event_loop(monkeypatch):
    expected_loop = object()
    monkeypatch.setattr("app.engine.subprocess_loop.sys.platform", "win32")
    monkeypatch.setattr(
        "app.engine.subprocess_loop.asyncio.ProactorEventLoop",
        lambda: expected_loop,
        raising=False,
    )

    assert SubprocessEventLoop._new_loop() is expected_loop
