"""Interchangeable standard HTTP transports for the MobSF client.

The transports share an async interface and normalize responses to httpx.Response.
The curl_cffi adapter intentionally does not use browser impersonation or challenge
solving; it is available only for ordinary transport interoperability diagnostics.
"""
from __future__ import annotations

import asyncio
import inspect
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
    """Optional curl_cffi transport without browser impersonation or challenge solving."""

    def __init__(self, settings: Settings, headers: Mapping[str, str]) -> None:
        try:
            from curl_cffi import requests as curl_requests
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ConfigurationError(
                "HTTP_CLIENT_BACKEND=curl_cffi requires the curl-cffi optional dependency"
            ) from exc

        self._curl_requests = curl_requests
        self._session: Any = curl_requests.AsyncSession()
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
        response = await self._session.request(
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
        result = self._session.close()
        if inspect.isawaitable(result):
            await result


def create_http_backend(settings: Settings, headers: Mapping[str, str]) -> HTTPBackend:
    """Create a transport from HTTP_CLIENT_BACKEND without logging secret values."""

    backend = settings.http_client_backend.strip().lower()
    if backend == "requests":
        return RequestsBackend(settings, headers)
    if backend == "httpx":
        client = httpx.AsyncClient(
            base_url=settings.mobsf_url,
            headers=headers,
            timeout=settings.mobsf_timeout,
            verify=settings.mobsf_verify_tls,
            follow_redirects=True,
            http2=settings.http_client_http2,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        return HttpxBackend(client, http2=settings.http_client_http2)
    if backend in {"curl_cffi", "curl-cffi"}:
        return CurlCffiBackend(settings, headers)
    raise ConfigurationError(
        "HTTP_CLIENT_BACKEND must be one of: requests, httpx, curl_cffi"
    )


def wrap_httpx_client(client: httpx.AsyncClient) -> HTTPBackend:
    """Wrap an injected httpx client for tests and advanced callers."""

    return HttpxBackend(client, owns_client=False)
