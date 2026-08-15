#!/usr/bin/env python3
"""Quick test to verify curl_cffi impersonation works on Render."""
import asyncio
import os

async def main():
    url = os.environ.get("MOBSF_URL", "https://mobsf.live")
    key = os.environ.get("MOBSF_API_KEY", "")

    print(f"Testing: {url}/api/v1/scans")
    print(f"API key set: {bool(key)}")

    # Test 1: raw curl_cffi sync
    try:
        from curl_cffi import requests as cr
        headers = {"X-Mobsf-Api-Key": key} if key else {}
        r = cr.get(f"{url}/api/v1/scans", headers=headers, impersonate="chrome124", timeout=30)
        print(f"[SYNC] status={r.status_code} ct={r.headers.get('content-type','?')}")
    except Exception as e:
        print(f"[SYNC] ERROR: {e}")

    # Test 2: async session per-request impersonate
    try:
        from curl_cffi.requests import AsyncSession
        headers = {"X-Mobsf-Api-Key": key} if key else {}
        async with AsyncSession() as s:
            s.headers.update(headers)
            r = await s.get(f"{url}/api/v1/scans", impersonate="chrome124", timeout=30)
        print(f"[ASYNC] status={r.status_code} ct={r.headers.get('content-type','?')}")
    except Exception as e:
        print(f"[ASYNC] ERROR: {e}")

    # Test 3: through MobSFClient
    try:
        os.environ["HTTP_CLIENT_BACKEND"] = "curl_cffi"
        from mobsf_mcp.config import Settings
        from mobsf_mcp.mobsf.client import MobSFClient
        settings = Settings.from_env(load_file=False)
        print(f"[CLIENT] backend={settings.http_client_backend}")
        async with MobSFClient(settings) as client:
            r = await client.health_check()
        print(f"[CLIENT] health_check={r}")
    except Exception as e:
        print(f"[CLIENT] ERROR: {type(e).__name__}: {e}")

asyncio.run(main())
