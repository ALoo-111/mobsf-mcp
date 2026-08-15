"""Interchangeable standard HTTP transports for the MobSF client.

The transports share an async interface and normalize responses to httpx.Response.
The curl_cffi adapter uses browser impersonation (chrome124) by default to bypass
Cloudflare managed challenges.  Set CURL_CFFI_IMPERSONATE to change the profile or
MOBSF_USE_CURL_CFFI=false to disable impersonation and fall back to plain curl.
"""
from __future__ import annotations

import asyncio
import inspect
import os
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin

import httpx

from mobsf_mcp.config import ConfigurationError, Settings


class HTTPBackend(ABC):
    """Common async interface for all supported transports."""

    @abstractmethod
    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        files: Any = None,
    ) -> httpx.Response:
        raise NotImplementedError

    @abstractmethod
    async def aclose(self) -> None:
        raise NotImplementedError


class HttpxBackend(HTTPBackend):
    """Native async httpx transport, optionally using HTTP/2."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        owns_client: bool = True,
        http2: bool = False,
    ) -> None:
        self.client = client
        self.owns_client = owns_client
        self.http2 = http2

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        files: Any = None,
    ) -> httpx.Response:
        return await self.client.request(method, url, params=params, data=data, files=files)

    async def aclose(self) -> None:
        if self.owns_client:
            await self.client.aclose()


class RequestsBackend(HTTPBackend):
    """Requests transport executed off the event loop and normalized to httpx.Response."""

    def __init__(self, settings: Settings, headers: Mapping[str, str]) -> None:
        try:
            import requests
        except ImportError as exc:  # pragma: no cover - exercised in deployment setup
            raise ConfigurationError(
                "HTTP_CLIENT_BACKEND=requests requires the requests package"
            ) from exc

        self._requests = requests
        self._session = requests.Session()
        self._session.headers.update(headers)
        self._base_url = settings.mobsf_url.rstrip("/") + "/"
        self._timeout = settings.mobsf_timeout
        self._verify_tls = settings.mobsf_verify_tls

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        files: Any = None,
    ) -> httpx.Response:
        absolute_url = urljoin(self._base_url, url.lstrip("/"))
        response = await asyncio.to_thread(
            self._session.request,
            method,
            absolute_url,
            params=params,
            data=data,
            files=files,
            timeout=self._timeout,
            verify=self._verify_tls,
        )
        request = httpx.Request(method, absolute_url)
        return httpx.Response(
            response.status_code,
            headers=dict(response.headers),
            content=response.content,
            request=request,
        )

    async def aclose(self) -> None:
        await asyncio.to_thread(self._session.close)


class CurlCffiBackend(HTTPBackend):
    """curl_cffi transport with browser impersonation to bypass Cloudflare WAF.

    Uses ``impersonate="chrome124"`` by default.  The impersonate profile can be
    overridden via the ``CURL_CFFI_IMPERSONATE`` environment variable.
    """

    def __init__(self, settings: Settings, headers: Mapping[str, str]) -> None:
        try:
            from curl_cffi import requests as curl_requests
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ConfigurationError(
                "HTTP_CLIENT_BACKEND=curl_cffi requires the curl-cffi optional dependency"
            ) from exc

        self._curl_requests = curl_requests
        self._base_url = settings.mobsf_url.rstrip("/") + "/"
        self._timeout = settings.mobsf_timeout
        self._verify_tls = settings.mobsf_verify_tls
        self._impersonate = os.getenv("CURL_CFFI_IMPERSONATE", "chrome124")
        # Build kwargs for the session; impersonate is supported by both
        # AsyncSession and the sync Session in curl_cffi >=0.7.
        session_kwargs: dict[str, Any] = {}
        if self._impersonate:
            session_kwargs["impersonate"] = self._impersonate
        self._session: Any = curl_requests.AsyncSession(**session_kwargs)
        self._session.headers.update(headers)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        files: Any = None,
    ) -> httpx.Response:
        absolute_url = urljoin(self._base_url, url.lstrip("/"))
        request_kwargs: dict[str, Any] = {
            "params": params,
            "data": data,
            "files": files,
            "timeout": self._timeout,
            "verify": self._verify_tls,
        }
        if self._impersonate:
            request_kwargs["impersonate"] = self._impersonate
        response = await self._session.request(method, absolute_url, **request_kwargs)
        request = httpx.Request(method, absolute_url)
        return httpx.Response(
            response.status_code,
            headers=dict(response.headers),
            content=response.content,
            request=request,
        )

    async def aclose(self) -> None:
        result = self._session.close()
        if inspect.isawaitable(result):
            await result


def create_http_backend(settings: Settings, headers: Mapping[str, str]) -> HTTPBackend:
    """Create a transport from HTTP_CLIENT_BACKEND without logging secret values."""

    backend = settings.http_client_backend.strip().lower()
    transport_headers = {"Accept-Encoding": "identity", **headers}
    if backend == "requests":
        return RequestsBackend(settings, transport_headers)
    if backend == "httpx":
        client = httpx.AsyncClient(
            base_url=settings.mobsf_url,
            headers=transport_headers,
            timeout=settings.mobsf_timeout,
            verify=settings.mobsf_verify_tls,
            follow_redirects=True,
            http2=settings.http_client_http2,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        return HttpxBackend(client, http2=settings.http_client_http2)
    if backend in {"curl_cffi", "curl-cffi"}:
        return CurlCffiBackend(settings, transport_headers)
    raise ConfigurationError(
        "HTTP_CLIENT_BACKEND must be one of: requests, httpx, curl_cffi"
    )


def wrap_httpx_client(client: httpx.AsyncClient) -> HTTPBackend:
    """Wrap an injected httpx client for tests and advanced callers."""

    return HttpxBackend(client, owns_client=False)
