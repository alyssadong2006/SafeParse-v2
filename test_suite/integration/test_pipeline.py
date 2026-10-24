import functools
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from config import settings
from app.engine.renderer import render
from app.engine.unicode_cleaner import clean_unicode
from app.security.heuristics import scan


@pytest.fixture(scope="module")
def mock_site():
    directory = Path(__file__).parents[1] / "mock_pages"
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original = settings.allow_private_networks
    settings.allow_private_networks = True
    try:
        yield "http://127.0.0.1:{}".format(server.server_port)
    finally:
        settings.allow_private_networks = original
        server.shutdown()
        server.server_close()


@pytest.mark.asyncio
async def test_benign(mock_site):
    result = await render(mock_site + "/benign_article.html", 10)
    assert "16GB RAM" in result.text
    assert not result.findings


@pytest.mark.asyncio
async def test_hidden_css(mock_site):
    result = await render(mock_site + "/hidden_css.html", 10)
    assert "Visible and useful" in result.text
    assert "SYSTEM OVERRIDE" not in result.text
    assert len(result.findings) == 3


@pytest.mark.asyncio
async def test_unicode(mock_site):
    result = await render(mock_site + "/zero_width.html", 10)
    cleaned, findings = clean_unicode(result.text)
    assert "Ignore previous instructions" in cleaned
    assert findings
    assert scan(cleaned)


@pytest.mark.asyncio
async def test_override(mock_site):
    result = await render(mock_site + "/prompt_override.html", 10)
    assert {finding["rule"] for finding in scan(result.text)} >= {"control_token", "instruction_override"}
