"""Playwright renderer with network-boundary and SSRF protection."""
import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlsplit

import httpx
from playwright.async_api import (
    Browser,
    Error as PlaywrightError,
    Playwright,
    async_playwright,
)

from config import settings
from app.engine.dom_cleaner import DOM_CLEANER_SCRIPT
from app.engine.subprocess_loop import subprocess_event_loop


class UnsafeURLError(ValueError):
    pass


@dataclass
class RenderResult:
    text: str
    findings: list


async def _resolved_addresses(hostname: str):
    loop = asyncio.get_running_loop()
    records = await loop.run_in_executor(
        None,
        lambda: socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
    )
    return {record[4][0].split('%')[0] for record in records}


async def validate_public_url(url: str):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeURLError("Only absolute HTTP(S) URLs are allowed")
    if parsed.username or parsed.password:
        raise UnsafeURLError("URLs containing credentials are not allowed")
    try:
        addresses = await _resolved_addresses(parsed.hostname)
    except socket.gaierror as exc:
        raise UnsafeURLError("The URL hostname could not be resolved") from exc
    if not addresses:
        raise UnsafeURLError("The URL hostname could not be resolved")
    if not settings.allow_private_networks:
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise UnsafeURLError(
                    "Private, loopback, link-local, and reserved networks are not allowed"
                )


async def _fetch_html(url: str, timeout_seconds: int):
    """HTTP/1.1 fallback for origins that fail Chromium's HTTP/2 negotiation."""
    current_url = url
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SafeParse/1.0)"}
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout_seconds,
        headers=headers,
    ) as client:
        for _ in range(settings.navigation_max_redirects + 1):
            await validate_public_url(current_url)
            async with client.stream("GET", current_url) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if not location:
                        raise RuntimeError("Target returned a redirect without a location")
                    current_url = urljoin(current_url, location)
                    continue
                if response.status_code >= 400:
                    raise RuntimeError(
                        "Target returned HTTP status {}".format(response.status_code)
                    )
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                    raise RuntimeError("Target did not return an HTML document")
                chunks = bytearray()
                async for chunk in response.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > settings.max_download_bytes:
                        raise RuntimeError("Target HTML exceeds the download limit")
                encoding = response.encoding or "utf-8"
                return bytes(chunks).decode(encoding, errors="replace"), current_url
        raise RuntimeError("Target exceeded the redirect limit")


class BrowserRenderer:
    """Reuse one Chromium process while isolating every request in its own context."""

    def __init__(self) -> None:
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._startup_lock = asyncio.Lock()

    async def start(self) -> Browser:
        """Start Chromium once and return the shared browser process."""
        if self._browser is not None and self._browser.is_connected():
            return self._browser

        async with self._startup_lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser
            if self._playwright is not None:
                await self._playwright.stop()
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=True)
            return self._browser

    async def close(self) -> None:
        """Release the shared browser and its Playwright driver."""
        async with self._startup_lock:
            browser, playwright = self._browser, self._playwright
            self._browser = None
            self._playwright = None
            if browser is not None and browser.is_connected():
                await browser.close()
            if playwright is not None:
                await playwright.stop()

    async def render(self, url: str, timeout_seconds: int) -> RenderResult:
        await validate_public_url(url)
        browser = await self.start()
        context = await browser.new_context(
            java_script_enabled=True,
            ignore_https_errors=False,
            service_workers="block",
        )
        page = await context.new_page()

        async def protect_request(route):
            request_url = route.request.url
            scheme = urlsplit(request_url).scheme
            if scheme in ("data", "blob", "about"):
                await route.continue_()
                return
            try:
                await validate_public_url(request_url)
            except UnsafeURLError:
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        await page.route("**/*", protect_request)
        try:
            try:
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=timeout_seconds * 1000,
                )
                if response is None:
                    raise RuntimeError("Navigation produced no HTTP response")
                if response.status >= 400:
                    raise RuntimeError(
                        "Target returned HTTP status {}".format(response.status)
                    )
            except PlaywrightError as exc:
                if "ERR_HTTP2_PROTOCOL_ERROR" not in str(exc):
                    raise
                html, final_url = await _fetch_html(url, timeout_seconds)
                # The failed navigation can leave its renderer unstable. Use a fresh,
                # script-disabled context for the static fallback; page.evaluate still
                # works, but untrusted page scripts cannot crash the replacement page.
                await context.close()
                context = await browser.new_context(
                    java_script_enabled=False,
                    ignore_https_errors=False,
                    service_workers="block",
                )
                page = await context.new_page()
                await page.route("**/*", protect_request)
                # A base URL lets relative styles retain browser semantics.
                base = '<base href="{}">'.format(final_url.replace('"', "&quot;"))
                lower_html = html.lower()
                if "<head" in lower_html:
                    head_start = lower_html.find("<head")
                    head_end = lower_html.find(">", head_start)
                    html = html[: head_end + 1] + base + html[head_end + 1 :]
                else:
                    html = base + html
                await page.set_content(
                    html,
                    wait_until="domcontentloaded",
                    timeout=timeout_seconds * 1000,
                )
            # A short network-idle attempt captures JS-rendered content without making
            # analytics-heavy pages consume the entire request timeout.
            try:
                await page.wait_for_load_state(
                    "networkidle",
                    timeout=min(3000, timeout_seconds * 1000),
                )
            except PlaywrightError:
                pass
            result: Dict[str, Any] = await page.evaluate(DOM_CLEANER_SCRIPT)
            return RenderResult(text=result["text"], findings=result["findings"])
        finally:
            await context.close()


_browser_renderer = BrowserRenderer()


async def start_renderer() -> None:
    """Warm Chromium on the subprocess-compatible event loop."""
    await subprocess_event_loop.run(_browser_renderer.start())


async def close_renderer() -> None:
    """Close Chromium before stopping its dedicated event loop."""
    await subprocess_event_loop.run(_browser_renderer.close())


async def render(url: str, timeout_seconds: int) -> RenderResult:
    """Render a URL on an event loop that supports Playwright's subprocess."""
    return await subprocess_event_loop.run(_browser_renderer.render(url, timeout_seconds))
