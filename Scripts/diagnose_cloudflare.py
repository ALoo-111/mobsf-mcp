"""Diagnostic script to verify curl_cffi Cloudflare bypass against mobsf.live.

Usage:
    MOBSF_URL=https://mobsf.live MOBSF_API_KEY=your_key python scripts/diagnose_cloudflare.py
"""
from __future__ import annotations

import asyncio
import os
import sys

MOBSF_URL = os.environ.get("MOBSF_URL", "https://mobsf.live")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "")


def _banner(text: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}")


def _result(label: str, ok: bool, detail: str = "") -> None:
    icon = "✅" if ok else "❌"
    print(f"  {icon} {label}: {'PASS' if ok else 'FAIL'}" + (f" — {detail}" if detail else ""))


async def _diag_curl_cffi_import() -> bool:
    _banner("1. curl_cffi import check")
    try:
        from curl_cffi import requests as curl_requests
        _result("curl_cffi available", True)
        return True
    except ImportError as exc:
        _result("curl_cffi available", False, str(exc))
        return False


async def _diag_plain_request() -> bool:
    _banner("2. Plain requests (httpx) — expected 403 on mobsf.live")
    try:
        import httpx

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{MOBSF_URL}/api/v1/scans",
                headers={"X-Mobsf-Api-Key": MOBSF_API_KEY} if MOBSF_API_KEY else {},
            )
        print(f"  Status : {resp.status_code}")
        print(f"  CT     : {resp.headers.get('content-type', 'N/A')}")
        if resp.status_code == 403:
            _result("Plain httpx", False, "HTTP 403 — Cloudflare blocking (expected)")
            return False
        _result("Plain httpx", True, f"HTTP {resp.status_code}")
        return True
    except Exception as exc:
        _result("Plain httpx", False, str(exc))
        return False


async def _diag_curl_cffi_request() -> bool:
    _banner("3. curl_cffi with chrome124 impersonation")
    try:
        from curl_cffi import requests as curl_requests

        session = curl_requests.AsyncSession(impersonate="chrome124")
        if MOBSF_API_KEY:
            session.headers.update({"X-Mobsf-Api-Key": MOBSF_API_KEY})

        resp = await session.get(
            f"{MOBSF_URL}/api/v1/scans",
            timeout=30,
        )
        print(f"  Status : {resp.status_code}")
        print(f"  CT     : {resp.headers.get('content-type', 'N/A')}")
        print(f"  Server : {resp.headers.get('server', 'N/A')}")

        if resp.status_code == 200:
            try:
                data = resp.json()
                print(f"  Keys   : {list(data.keys())[:5]}")
                _result("curl_cffi chrome124", True, "HTTP 200 + JSON")
                return True
            except Exception:
                _result("curl_cffi chrome124", True, "HTTP 200 (non-JSON)")
                return True
        elif resp.status_code == 403:
            _result("curl_cffi chrome124", False, "HTTP 403 — still blocked")
            print(f"  Body   : {resp.text[:300]}")
            return False
        else:
            _result("curl_cffi chrome124", False, f"HTTP {resp.status_code}")
            return False
    except Exception as exc:
        _result("curl_cffi chrome124", False, str(exc))
        return False


async def _diag_mobsf_client() -> bool:
    _banner("4. MobSFClient with curl_cffi backend")
    try:
        # Temporarily force the backend
        os.environ["HTTP_CLIENT_BACKEND"] = "curl_cffi"

        from mobsf_mcp.config import Settings
        from mobsf_mcp.mobsf.client import MobSFClient

        settings = Settings.from_env(load_file=False)
        async with MobSFClient(settings) as client:
            result = await client.health_check()
        print(f"  Backend : curl_cffi (chrome124)")
        print(f"  Result  : {result}")
        _result("MobSFClient health_check", True)
        return True
    except Exception as exc:
        _result("MobSFClient health_check", False, str(exc))
        return False


async def main() -> int:
    _banner("MobSF MCP — Cloudflare Bypass Diagnostic")
    print(f"  Target : {MOBSF_URL}")
    print(f"  API Key: {'set' if MOBSF_API_KEY else 'NOT SET'}")

    results = {
        "curl_cffi_import": await _diag_curl_cffi_import(),
        "plain_request": await _diag_plain_request(),
        "curl_cffi_request": await _diag_curl_cffi_request(),
        "mobsf_client": await _diag_mobsf_client(),
    }

    _banner("Summary")
    for name, ok in results.items():
        _result(name, ok)

    all_ok = results["curl_cffi_import"] and results["curl_cffi_request"] and results["mobsf_client"]
    _banner("Result: " + ("ALL CRITICAL CHECKS PASSED ✅" if all_ok else "SOME CHECKS FAILED ❌"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
              
