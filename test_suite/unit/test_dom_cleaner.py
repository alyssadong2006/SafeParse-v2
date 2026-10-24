import pytest

from app.engine.renderer import UnsafeURLError, validate_public_url


@pytest.mark.asyncio
async def test_ssrf_protection_rejects_loopback():
    with pytest.raises(UnsafeURLError):
        await validate_public_url("http://127.0.0.1/private")


@pytest.mark.asyncio
async def test_rejects_non_http_protocol():
    with pytest.raises(UnsafeURLError):
        await validate_public_url("file:///etc/passwd")
