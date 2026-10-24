"""Run subprocess-backed async libraries on a compatible event loop.

Windows' selector event loop cannot create subprocesses, but ASGI servers may use
it when reload or multiple-worker mode is enabled. Playwright starts a driver
subprocess, so it is isolated on a dedicated loop: Proactor on Windows and the
platform default everywhere else.
"""
import asyncio
import atexit
import sys
import threading
from typing import Any, Coroutine, Optional, TypeVar


Result = TypeVar("Result")


class SubprocessEventLoop:
    """A lazily started event loop dedicated to subprocess-backed work."""

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._lock = threading.Lock()
        self._startup_error: Optional[BaseException] = None
        self._closed = False

    @staticmethod
    def _new_loop() -> asyncio.AbstractEventLoop:
        if sys.platform == "win32":
            # SelectorEventLoop raises NotImplementedError for subprocess APIs.
            return asyncio.ProactorEventLoop()
        return asyncio.new_event_loop()

    def _run_loop(self) -> None:
        try:
            loop = self._new_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            return

        self._ready.set()
        try:
            loop.run_forever()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._closed:
                raise RuntimeError("The subprocess event loop has been closed")
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run_loop,
                    name="safeparse-subprocess-loop",
                    daemon=True,
                )
                self._thread.start()

        self._ready.wait()
        if self._startup_error is not None:
            raise RuntimeError("Could not start the subprocess event loop") from self._startup_error
        if self._loop is None:
            raise RuntimeError("Could not start the subprocess event loop")
        return self._loop

    async def run(self, coroutine: Coroutine[Any, Any, Result]) -> Result:
        """Run a coroutine on the dedicated loop without blocking the caller."""
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, self._get_loop())
        except BaseException:
            coroutine.close()
            raise
        return await asyncio.wrap_future(future)

    def close(self) -> None:
        """Stop the loop if it was started."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            loop = self._loop
            thread = self._thread

        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)


subprocess_event_loop = SubprocessEventLoop()
atexit.register(subprocess_event_loop.close)
