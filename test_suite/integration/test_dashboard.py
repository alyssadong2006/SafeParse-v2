"""Exercise dashboard JavaScript in Chromium with local assets and mocked API."""
import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import pytest_asyncio
from playwright.async_api import async_playwright, expect

STATIC = Path(__file__).resolve().parents[2] / "app" / "static"


@pytest_asyncio.fixture
async def dashboard():
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        page = await browser.new_page()

        async def asset(route):
            path = urlsplit(route.request.url).path
            if route.request.url.startswith("http://localhost/"):
                files = {"/": ("index.html", "text/html"),
                         "/static/app.js": ("app.js", "text/javascript"),
                         "/static/styles.css": ("styles.css", "text/css")}
                if path in files:
                    name, content_type = files[path]
                    await route.fulfill(body=(STATIC / name).read_text(encoding="utf-8"), content_type=content_type)
                    return
            await route.abort()

        await page.route("**/*", asset)
        # Stub clipboard to exercise copy buttons without platform permissions.
        await page.add_init_script("""
            window.copiedText = null;
            Object.defineProperty(navigator, 'clipboard', {value: {
              writeText: async text => { window.copiedText = text; }
            }});
        """)
        await page.goto("http://localhost/")
        yield page
        await browser.close()


def success(url, text="Article text"):
    return {
        "status": "success", "url": url,
        "data": {"clean_text": text, "safe_prompt_payload": text},
        "security_audit": {"is_threat_detected": False, "threat_score": 0,
                           "threat_actions_taken": [], "flagged_elements": []},
        "performance": {"execution_time_ms": 10},
    }


def failure(url):
    return {"status": "error", "url": url,
            "error": {"status_code": 504, "detail": "Target page timed out <script>"}}


async def fill_urls(page, urls):
    for index, url in enumerate(urls):
        if index:
            await page.locator("#add-url").click()
        await page.locator("#url-rows input").nth(index).fill(url)


@pytest.mark.asyncio
async def test_batch_selection_errors_copy_and_single_mode(dashboard):
    page = dashboard
    requests = []
    payload = {"results": [success("https://example.com/a", "<img src=x onerror=alert(1)>"),
                           failure("https://example.com/b"),
                           success("https://example.com/a", "Duplicate article")]}

    async def api(route):
        requests.append((urlsplit(route.request.url).path, route.request.post_data_json))
        response = payload if route.request.url.endswith("/batch") else success("https://example.com/single")
        await route.fulfill(json=response)

    await page.route("**/api/v1/**", api)
    await fill_urls(page, ["https://example.com/a", "https://example.com/b", "https://example.com/a"])
    await expect(page.locator(".button-label")).to_have_text("Scan 3 pages")
    await page.locator("#submit-button").click()
    await expect(page.locator("#batch-counts")).to_contain_text("2 succeeded, 1 failed")
    assert requests == [("/api/v1/sanitize/batch", {"items": [
        {"url": url, "timeout_seconds": 15, "strict_mode": True}
        for url in ["https://example.com/a", "https://example.com/b", "https://example.com/a"]
    ]})]
    await expect(page.locator(".batch-error-detail")).to_have_text("Target page timed out <script>")
    await expect(page.locator("#detail-area")).to_be_hidden()
    await page.locator(".batch-select").first.click()
    await expect(page.locator("#formatted-text")).to_have_text("<img src=x onerror=alert(1)>")
    assert await page.locator("#formatted-text img").count() == 0
    await page.locator(".batch-select").last.click()
    await expect(page.locator("#formatted-text")).to_have_text("Duplicate article")
    await expect(page.locator(".batch-select").last).to_have_attribute("aria-pressed", "true")
    await page.locator("#copy-batch").click()
    assert json.loads(await page.evaluate("window.copiedText")) == payload
    await page.locator("#new-scan").click()
    await expect(page.locator("#results")).to_be_hidden()
    await page.locator(".remove-url").last.click()
    await page.locator(".remove-url").last.click()
    await page.locator("#url").fill("https://example.com/single")
    await page.locator("#submit-button").click()
    await expect(page.locator("#formatted-text")).to_have_text("Article text")
    await expect(page.locator("#batch-summary")).to_be_hidden()
    assert requests[-1][0] == "/api/v1/sanitize"


@pytest.mark.asyncio
async def test_all_failures_remain_visible_and_copyable(dashboard):
    page = dashboard
    payload = {"results": [failure("https://example.com/"), failure("https://example.org/")]}
    await page.route("**/api/v1/sanitize/batch", lambda route: route.fulfill(json=payload))
    await fill_urls(page, ["https://example.com/", "https://example.org/"])
    await page.locator("#submit-button").click()
    await expect(page.locator("#batch-counts")).to_contain_text("All scans failed")
    await expect(page.locator("#detail-area")).to_be_hidden()
    await page.locator("#copy-batch").click()
    assert json.loads(await page.evaluate("window.copiedText")) == payload


@pytest.mark.asyncio
async def test_batch_validation_and_structured_api_errors(dashboard):
    page = dashboard
    requests = []

    async def api(route):
        requests.append(route.request.post_data_json)
        await route.fulfill(status=422, json={"detail": [
            {"loc": ["body", "items", 0, "url"], "msg": "Invalid URL"},
        ]})

    await page.route("**/api/v1/sanitize/batch", api)
    for value, message in [("", "Enter a URL for row 1"),
                           ("file:///etc/passwd", "URL 1 must be a valid HTTP(S) URL")]:
        await page.locator("#url").fill(value)
        await page.locator("#submit-button").click()
        await expect(page.locator("#error")).to_contain_text(message)
    assert requests == []
    await page.locator("#url").fill("https://example.com/")
    await page.locator("#add-url").click()
    await page.locator("#submit-button").click()
    await expect(page.locator("#error")).to_contain_text("Enter a URL for row 2")
    assert requests == []
    await page.locator("#url-rows input").last.fill("https://example.org/")
    await page.locator("#submit-button").click()
    await expect(page.locator("#error")).to_have_text("items.0.url: Invalid URL")
    await expect(page.locator("#submit-button")).to_be_enabled()


@pytest.mark.asyncio
async def test_url_row_limit_removal_labels_and_mobile_layout(dashboard):
    page = dashboard
    await page.set_viewport_size({"width": 390, "height": 844})
    await fill_urls(page, [f"https://example.com/{index}" for index in range(10)])
    await expect(page.locator("#url-count")).to_have_text("10 / 10 URLs")
    await expect(page.locator("#add-url")).to_be_disabled()
    assert await page.locator("#url-rows input").count() == 10
    await page.locator(".remove-url").nth(4).click()
    await expect(page.locator("#add-url")).to_be_enabled()
    assert await page.locator("#url-rows input").nth(4).input_value() == "https://example.com/5"
    await expect(page.locator("#url-rows input").nth(4)).to_be_focused()
    await page.locator("#add-url svg").click()
    await expect(page.locator("#url-rows input").last).to_have_value("")
    labels = await page.locator(".url-entry label").all_text_contents()
    assert labels == [f"URL {index}" for index in range(1, 11)]
    assert await page.evaluate("""() => {
      const inputs = [...document.querySelectorAll('#url-rows input')];
      return new Set(inputs.map(input => input.id)).size === inputs.length &&
        inputs.every(input => document.querySelector(`label[for="${input.id}"]`));
    }""")
    assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    for _ in range(9):
        await page.locator(".remove-url").first.click()
    await expect(page.locator(".remove-url")).to_be_disabled()
    await expect(page.locator("#url-count")).to_have_text("1 / 10 URLs")
    await expect(page.locator(".button-label")).to_have_text("Scan page")
    last_row = await page.locator(".url-entry").last.bounding_box()
    add_button = await page.locator("#add-url").bounding_box()
    assert add_button["y"] - (last_row["y"] + last_row["height"]) >= 24


@pytest.mark.asyncio
async def test_url_rows_locked_during_scan_and_restored_after_failure(dashboard):
    page = dashboard
    release = asyncio.Event()

    async def api(route):
        await release.wait()
        await route.fulfill(status=503, json={"detail": "Model unavailable"})

    await page.route("**/api/v1/sanitize/batch", api)
    await fill_urls(page, ["https://example.com/", "https://example.org/"])
    await page.locator("#submit-button").click()
    await expect(page.locator("#add-url")).to_be_disabled()
    await expect(page.locator(".remove-url").first).to_be_disabled()
    await expect(page.locator("#url-rows input").first).to_be_disabled()
    release.set()
    await expect(page.locator("#error")).to_have_text("Model unavailable")
    await expect(page.locator("#add-url")).to_be_enabled()
    await expect(page.locator(".remove-url").first).to_be_enabled()
    await expect(page.locator("#url-rows input").first).to_have_value("https://example.com/")
