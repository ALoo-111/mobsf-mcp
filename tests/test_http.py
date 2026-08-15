from __future__ import annotations

import httpx
import pytest

from mobsf_mcp.config import ConfigurationError, Settings
from mobsf_mcp.mcp_client.http import (
    CurlCffiBackend,
    HttpxBackend,
    RequestsBackend,
    create_http_backend,
)


def test_factory_selects_httpx_and_http2() -> None:
    settings = Settings(
        mobsf_url="http://mobsf.test",
        http_client_backend="httpx",
        http_client_http2=True,
    )
    backend = create_http_backend(settings, {"X-Mobsf-Api-Key": "placeholder"})
    assert isinstance(backend, HttpxBackend)
    assert backend.http2 is True


@pytest.mark.asyncio
async def test_requests_backend_normalizes_response(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    class FakeResponse:
        status_code = 200
        headers = {"content-type": "application/json"}
        content = b'{"scans": []}'

    captured: dict[str, object] = {}

    def fake_request(self, method: str, url: str, **kwargs: object) -> FakeResponse:
        captured.update({"method": method, "url": url, **kwargs})
        return FakeResponse()

    monkeypatch.setattr(requests.Session, "request", fake_request)
    settings = Settings(mobsf_url="http://mobsf.test", http_client_backend="requests")
    backend = create_http_backend(settings, {"X-Mobsf-Api-Key": "placeholder"})
    assert isinstance(backend, RequestsBackend)

    response = await backend.request("GET", "/api/v1/scans", params={"page": 1})
    await backend.aclose()

    assert response.status_code == 200
    assert response.json() == {"scans": []}
    assert captured["method"] == "GET"
    assert captured["url"] == "http://mobsf.test/api/v1/scans"


@pytest.mark.asyncio
async def test_httpx_backend_uses_mock_transport() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"scans": []}, request=request)

    client = httpx.AsyncClient(
        base_url="http://mobsf.test",
        transport=httpx.MockTransport(handler),
    )
    backend = HttpxBackend(client, owns_client=True)
    response = await backend.request("GET", "/api/v1/scans")
    await backend.aclose()

    assert response.status_code == 200
    assert response.json() == {"scans": []}


@pytest.mark.asyncio
async def test_optional_curl_cffi_backend_initializes_without_impersonation() -> None:
    pytest.importorskip("curl_cffi")
    settings = Settings(mobsf_url="http://mobsf.test", http_client_backend="curl_cffi")
    backend = create_http_backend(settings, {"X-Mobsf-Api-Key": "placeholder"})
    assert isinstance(backend, CurlCffiBackend)
    await backend.aclose()


def test_factory_rejects_unknown_backend() -> None:
    settings = Settings(mobsf_url="http://mobsf.test", http_client_backend="unknown")
    with pytest.raises(ConfigurationError):
        settings.validate()
