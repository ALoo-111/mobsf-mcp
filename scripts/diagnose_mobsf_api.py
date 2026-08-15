"""Redacted MobSF REST/Cloudflare diagnostic.

Run this on the deployed MCP host with MOBSF_URL and MOBSF_API_KEY set. The
script never prints the API key, cookies, CSRF tokens, or full response bodies.
It does not use browser fingerprinting, browser sessions, or proxies.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys

import httpx

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-csrftoken",
    "x-mobsf-api-key",
}


def redact_header(name: str, value: str) -> str:
    if name.lower() in SENSITIVE_HEADERS:
        return "<redacted>"
    return value


def redact_text(value: str, api_key: str) -> str:
    if api_key:
        value = value.replace(api_key, "<redacted>")
    value = re.sub(
        r"(?i)(api[_-]?key|token|password|secret)=?[: ]+[^&\\s<]{8,}",
        r"\1=<redacted>",
        value,
    )
    return value[:200]


def classify_body(value: str) -> str:
    stripped = value.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if stripped.startswith("<"):
        return "html"
    return "other"


def response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        name: redact_header(name, value)
        for name, value in response.headers.items()
    }


async def main() -> int:
    base_url = os.getenv("MOBSF_URL", "https://mobsf.live").rstrip("/")
    api_key = os.getenv("MOBSF_API_KEY", "")
    if not api_key:
        print("MOBSF_API_KEY is missing; no request was sent.", file=sys.stderr)
        return 2

    url = f"{base_url}/api/v1/scans?page=1&page_size=1"
    timeout = float(os.getenv("MOBSF_TIMEOUT", "30"))
    variants: list[tuple[str, dict[str, str]]] = [
        ("x-mobsf-api-key", {"X-Mobsf-Api-Key": api_key}),
        ("authorization-raw", {"Authorization": api_key}),
        ("authorization-bearer", {"Authorization": f"Bearer {api_key}"}),
        ("x-api-key", {"X-API-Key": api_key}),
    ]

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for name, auth_headers in variants:
            request_headers = {
                "Accept": "application/json",
                "User-Agent": "mobsf-mcp-diagnostic/1.0",
                **auth_headers,
            }
            print(f"=== {name} ===")
            print(f"request_method=GET request_url={base_url}/api/v1/scans?page=1&page_size=1")
            print(
                "request_headers="
                + repr(
                    {
                        key: redact_header(key, value)
                        for key, value in request_headers.items()
                    }
                )
            )
            try:
                response = await client.get(url, headers=request_headers)
            except httpx.HTTPError as exc:
                print(f"transport_error={type(exc).__name__}")
                print(f"transport_message={redact_text(str(exc), api_key)}")
                continue

            body = response.text
            print(f"status={response.status_code}")
            print(f"response_headers={response_headers(response)!r}")
            print(f"body_class={classify_body(body)}")
            print(f"body_excerpt={redact_text(body, api_key)!r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
