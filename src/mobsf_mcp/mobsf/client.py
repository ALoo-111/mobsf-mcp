from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx

from mobsf_mcp.config import Settings
from mobsf_mcp.mobsf.endpoints import ENDPOINTS, Endpoint
from mobsf_mcp.mobsf.exceptions import (
    MobSFAuthenticationError,
    MobSFConnectionError,
    MobSFError,
    MobSFTimeoutError,
    MobSFUnsupportedEndpoint,
)

logger = logging.getLogger(__name__)


class MobSFClient:
    def __init__(
        self,
        settings: Settings,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        headers = {"X-Mobsf-Api-Key": settings.mobsf_api_key}
        self._client = http_client or httpx.AsyncClient(
            base_url=settings.mobsf_url,
            headers=headers,
            timeout=settings.mobsf_timeout,
            verify=settings.mobsf_verify_tls,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        if http_client is not None:
            self._client.headers.update(headers)
        self._owns_client = http_client is None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def health_check(self) -> dict[str, Any]:
        response = await self._request("scans", params={"page": 1, "page_size": 1})
        return {"reachable": True, "response": response}

    async def upload(self, path: Path) -> dict[str, Any]:
        endpoint = ENDPOINTS["upload"]
        with path.open("rb") as handle:
            response = await self._request(
                endpoint,
                files={"file": (path.name, handle, "application/vnd.android.package-archive")},
            )
        return _as_json(response)

    async def scan(self, scan_hash: str, *, rescan: bool = False) -> dict[str, Any]:
        response = await self._request(
            "scan", data={"hash": scan_hash, "re_scan": "1" if rescan else "0"}
        )
        return _as_json(response)

    async def scan_logs(self, scan_hash: str) -> dict[str, Any]:
        return _as_json(await self._request("scan_logs", data={"hash": scan_hash}))

    async def report_json(self, scan_hash: str) -> dict[str, Any]:
        return _as_json(await self._request("report_json", data={"hash": scan_hash}))

    async def scorecard(self, scan_hash: str) -> dict[str, Any]:
        return _as_json(await self._request("scorecard", data={"hash": scan_hash}))

    async def search(self, query: str) -> dict[str, Any]:
        return _as_json(await self._request("search", data={"query": query}))

    async def view_source(
        self, scan_hash: str, file: str, source_type: str = "apk"
    ) -> dict[str, Any]:
        return _as_json(
            await self._request(
                "view_source", data={"hash": scan_hash, "file": file, "type": source_type}
            )
        )

    async def compare(self, first_hash: str, second_hash: str) -> dict[str, Any]:
        return _as_json(
            await self._request("compare", data={"hash1": first_hash, "hash2": second_hash})
        )

    async def download_pdf(self, scan_hash: str) -> bytes:
        response = await self._request("download_pdf", data={"hash": scan_hash})
        return response.content

    async def scans(self, *, page: int = 1, page_size: int = 20) -> dict[str, Any]:
        return _as_json(await self._request("scans", params={"page": page, "page_size": page_size}))

    async def dynamic_get_apps(self) -> dict[str, Any]:
        return _as_json(await self._request("dynamic_get_apps"))

    async def dynamic_start_analysis(self, scan_hash: str, **params: str) -> dict[str, Any]:
        data = {"hash": scan_hash, **params}
        return _as_json(await self._request("dynamic_start_analysis", data=data))

    async def dynamic_report_json(self, scan_hash: str) -> dict[str, Any]:
        return _as_json(await self._request("dynamic_report_json", data={"hash": scan_hash}))

    async def dynamic_stop_analysis(self, scan_hash: str) -> dict[str, Any]:
        return _as_json(await self._request("dynamic_stop_analysis", data={"hash": scan_hash}))

    async def _request(
        self,
        endpoint: str | Endpoint,
        *,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        files: Any = None,
    ) -> httpx.Response:
        definition = ENDPOINTS[endpoint] if isinstance(endpoint, str) else endpoint
        url = definition.path
        logger.info("MobSF request: %s %s", definition.method, url)
        try:
            response = await self._client.request(
                definition.method, url, params=params, data=data, files=files
            )
        except httpx.TimeoutException as exc:
            raise MobSFTimeoutError("MobSF request timed out") from exc
        except httpx.HTTPError as exc:
            raise MobSFConnectionError("Unable to connect to the configured MobSF backend") from exc

        if len(response.content) > self.settings.max_response_bytes:
            raise MobSFError("MobSF response exceeded the configured response-size limit")
        if response.status_code in {401, 403}:
            backend_message = _safe_auth_message(response)
            raise MobSFAuthenticationError(
                f"MobSF authentication failed: {backend_message}",
                status_code=response.status_code,
            )
        if response.status_code in {404, 405, 501}:
            raise MobSFUnsupportedEndpoint(
                f"Endpoint unavailable in this MobSF version: {definition.path}",
                status_code=response.status_code,
            )
        if response.is_error:
            raise MobSFError(
                _safe_error_message(response),
                status_code=response.status_code,
                response_body=_safe_body(response),
            )
        return response


def _as_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise MobSFError("MobSF returned malformed JSON", status_code=response.status_code) from exc
    if not isinstance(payload, dict):
        raise MobSFError(
            "MobSF returned a non-object JSON response", status_code=response.status_code
        )
    return payload


def _safe_body(response: httpx.Response) -> Any:
    try:
        body = response.json()
        if isinstance(body, dict) and "error" in body:
            return {"error": str(body["error"])[:500]}
        return body
    except (json.JSONDecodeError, UnicodeDecodeError):
        return response.text[:500]


def _safe_auth_message(response: httpx.Response) -> str:
    body = _safe_body(response)
    if isinstance(body, dict) and body.get("error"):
        return str(body["error"])[:500]
    content_type = response.headers.get("content-type", "unknown").split(";", 1)[0]
    return f"HTTP {response.status_code} non-JSON response (content_type={content_type})"


def _safe_error_message(response: httpx.Response) -> str:
    body = _safe_body(response)
    if isinstance(body, dict) and body.get("error"):
        return f"MobSF request failed: {body['error']}"
    return f"MobSF request failed with HTTP {response.status_code}"
