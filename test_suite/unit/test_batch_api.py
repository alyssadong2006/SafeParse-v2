"""Batch API contracts without browsers, network calls, or model weights."""
import asyncio
from unittest.mock import Mock

import httpx
import pytest
from playwright.async_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

from app.api.v1 import endpoints
from app.api.v1.models import BatchSanitizeRequest
from app.engine.renderer import RenderResult, UnsafeURLError
from app.main import app
from app.security.guardrail_model import GuardrailModelError


@pytest.fixture
def pipeline(monkeypatch):
    calls = []

    async def render(url, timeout):
        calls.append((url, timeout))
        return RenderResult(text="Useful article content", findings=[])

    audit = Mock()
    monkeypatch.setattr(endpoints, "render", render)
    monkeypatch.setattr(endpoints, "predict_prompt_injection", lambda text: None)
    monkeypatch.setattr(endpoints, "log_audit", audit)
    return calls, audit


async def post(path, payload):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.post(path, json=payload)


@pytest.mark.asyncio
async def test_batch_preserves_order_duplicates_and_per_item_options(pipeline):
    calls, audit = pipeline
    urls = ["https://example.com/one", "https://example.com/two", "https://example.com/one"]
    response = await post("/api/v1/sanitize/batch", {"items": [
        {"url": url, "timeout_seconds": index + 1, "strict_mode": False}
        for index, url in enumerate(urls)
    ]})
    assert response.status_code == 200
    results = response.json()["results"]
    assert [item["url"] for item in results] == urls
    assert calls == list(zip(urls, [1, 2, 3]))
    assert audit.call_count == 3
    for item in results:
        assert item["status"] == "success"
        assert item["data"]["clean_text"] == "Useful article content"
        assert "untrusted_data_" in item["data"]["safe_prompt_payload"]
        assert "security_audit" in item
        assert "performance" in item


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,code,detail", [
    (UnsafeURLError("Private network blocked"), 400, "Private network blocked"),
    (PlaywrightTimeoutError("internal timeout"), 504, "Target page timed out"),
    (PlaywrightError("internal browser failure"), 502, "Target page could not be rendered"),
    (GuardrailModelError("Model unavailable"), 503, "Model unavailable"),
    (RuntimeError("Target returned HTTP status 404"), 502, "Target returned HTTP status 404"),
    (ValueError("private internal details"), 500, "Page could not be sanitized"),
])
async def test_batch_isolates_failures(monkeypatch, pipeline, failure, code, detail):
    original = endpoints.render

    async def render(url, timeout):
        if url.endswith("/bad"):
            raise failure
        return await original(url, timeout)

    monkeypatch.setattr(endpoints, "render", render)
    response = await post("/api/v1/sanitize/batch", {"items": [
        {"url": "https://example.com/first"},
        {"url": "https://example.com/bad"},
        {"url": "https://example.com/last"},
    ]})
    assert response.status_code == 200
    results = response.json()["results"]
    assert [item["status"] for item in results] == ["success", "error", "success"]
    assert results[1] == {
        "status": "error", "url": "https://example.com/bad",
        "error": {"status_code": code, "detail": detail},
    }
    assert pipeline[1].call_count == 2


@pytest.mark.asyncio
async def test_all_failed_batch(monkeypatch, pipeline):
    async def render(url, timeout):
        raise UnsafeURLError("Private network blocked")

    monkeypatch.setattr(endpoints, "render", render)
    response = await post("/api/v1/sanitize/batch", {"items": [
        {"url": "http://127.0.0.1/"}, {"url": "http://localhost/"},
    ]})
    assert response.status_code == 200
    assert [item["error"]["status_code"] for item in response.json()["results"]] == [400, 400]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {}, {"items": []},
    {"items": [{"url": "https://example.com"}] * 11},
    {"items": [{"url": "https://example.com"}, {"url": "not-a-url"}]},
    {"items": [{"url": "file:///etc/passwd"}]},
    {"items": [{"url": "https://example.com", "timeout_seconds": 0}]},
    {"items": [{"url": "https://example.com", "timeout_seconds": 31}]},
])
async def test_invalid_batch_is_rejected_before_processing(pipeline, payload):
    response = await post("/api/v1/sanitize/batch", payload)
    assert response.status_code == 422
    assert pipeline[0] == []
    pipeline[1].assert_not_called()


@pytest.mark.asyncio
async def test_maximum_batch_size(pipeline):
    response = await post("/api/v1/sanitize/batch", {
        "items": [{"url": "https://example.com/"}] * 10,
    })
    assert response.status_code == 200
    assert len(response.json()["results"]) == 10


@pytest.mark.asyncio
async def test_cancellation_is_not_converted_to_item_failure(monkeypatch, pipeline):
    async def render(url, timeout):
        raise asyncio.CancelledError()

    monkeypatch.setattr(endpoints, "render", render)
    request = BatchSanitizeRequest(items=[{"url": "https://example.com"}])
    with pytest.raises(asyncio.CancelledError):
        await endpoints.sanitize_batch(request)


@pytest.mark.asyncio
async def test_single_endpoint_contract_is_unchanged(pipeline):
    response = await post("/api/v1/sanitize", {"url": "https://example.com/"})
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "results" not in response.json()
    assert response.json()["data"]["clean_text"] == "Useful article content"
