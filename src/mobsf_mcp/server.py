from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any

from mcp.server import MCPServer

from mobsf_mcp.analysis.findings import extract_findings
from mobsf_mcp.analysis.normalizer import normalize_report
from mobsf_mcp.analysis.orchestrator import analyze_apk as run_analysis
from mobsf_mcp.config import Settings
from mobsf_mcp.logging_config import configure_logging
from mobsf_mcp.mobsf.client import MobSFClient
from mobsf_mcp.mobsf.exceptions import error_payload

logger = logging.getLogger(__name__)
settings = Settings.from_env()
mcp = MCPServer(
    "MobSF MCP",
    version="0.1.0",
    instructions="Authorized MobSF mobile application security analysis.",
)
_REPORT_CACHE: dict[str, dict[str, Any]] = {}


async def _call(method: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        async with MobSFClient(settings) as client:
            value = await getattr(client, method)(*args, **kwargs)
        return {"status": "completed", "data": value}
    except Exception as exc:
        logger.exception("MobSF operation failed: %s", method)
        return {"status": "failed", "error": error_payload(exc)}


@mcp.tool()
async def analyze_apk(
    apk_path: str,
    include_source_evidence: bool = True,
    include_raw_report: bool = False,
    enable_dynamic: bool = False,
) -> dict[str, Any]:
    """Upload an APK, run static analysis, and optionally attempt dynamic analysis.

    The result is normalized for AI consumption and preserves limitations.
    """
    try:
        async with MobSFClient(settings) as client:
            report = await run_analysis(
                apk_path,
                settings=settings,
                client=client,
                include_source_evidence=include_source_evidence,
                include_raw_report=include_raw_report,
                enable_dynamic=enable_dynamic,
            )
        payload = report.model_dump(mode="json")
        scan_hash = payload.get("hashes", {}).get("mobsf_scan_hash")
        if scan_hash:
            _REPORT_CACHE[scan_hash] = payload
        return payload
    except Exception as exc:
        logger.exception("APK analysis failed")
        return {"status": "failed", "error": error_payload(exc)}


@mcp.tool()
async def mobsf_upload(apk_path: str) -> dict[str, Any]:
    """Upload a validated APK to the configured MobSF backend."""
    from mobsf_mcp.utils.files import validate_apk_path

    try:
        path = validate_apk_path(apk_path, settings)
        return await _call("upload", path)
    except Exception as exc:
        return {"status": "failed", "error": error_payload(exc)}


@mcp.tool()
async def mobsf_scan(scan_hash: str, rescan: bool = False) -> dict[str, Any]:
    """Start or re-run a MobSF scan for an uploaded scan hash."""
    return await _call("scan", scan_hash, rescan=rescan)


@mcp.tool()
async def mobsf_scan_status(scan_hash: str) -> dict[str, Any]:
    """Retrieve the current and latest MobSF scan logs for a scan hash."""
    return await _call("scan_logs", scan_hash)


@mcp.tool()
async def mobsf_report(scan_hash: str, include_raw_report: bool = False) -> dict[str, Any]:
    """Retrieve and normalize a MobSF JSON report, optionally including the raw report."""
    try:
        async with MobSFClient(settings) as client:
            report = await client.report_json(scan_hash)
            scorecard = await client.scorecard(scan_hash)
        normalized = normalize_report(
            report,
            scorecard,
            findings=extract_findings(report),
            include_raw=include_raw_report,
        )
        payload = normalized.model_dump(mode="json")
        _REPORT_CACHE[scan_hash] = payload
        return payload
    except Exception as exc:
        return {"status": "failed", "error": error_payload(exc)}


@mcp.tool()
async def mobsf_scorecard(scan_hash: str) -> dict[str, Any]:
    """Retrieve the MobSF application security scorecard."""
    return await _call("scorecard", scan_hash)


@mcp.tool()
async def mobsf_search(query: str) -> dict[str, Any]:
    """Search MobSF scans by MD5, application name, package name, or filename."""
    return await _call("search", query)


@mcp.tool()
async def mobsf_source(scan_hash: str, file: str, source_type: str = "apk") -> dict[str, Any]:
    """Retrieve a specific MobSF source/decompiled file for evidence review."""
    return await _call("view_source", scan_hash, file, source_type)


@mcp.tool()
async def mobsf_compare(first_hash: str, second_hash: str) -> dict[str, Any]:
    """Compare two MobSF scan results."""
    return await _call("compare", first_hash, second_hash)


@mcp.tool()
async def mobsf_download_report(scan_hash: str) -> dict[str, Any]:
    """Download a MobSF PDF report as base64, when supported by the configured backend."""
    try:
        async with MobSFClient(settings) as client:
            content = await client.download_pdf(scan_hash)
        return {
            "status": "completed",
            "content_type": "application/pdf",
            "filename": f"mobsf-{scan_hash}.pdf",
            "base64": base64.b64encode(content).decode("ascii"),
        }
    except Exception as exc:
        return {"status": "failed", "error": error_payload(exc)}


@mcp.tool()
async def mobsf_dynamic_analysis(scan_hash: str) -> dict[str, Any]:
    """Run dynamic analysis only when enabled and supported.

    Unsupported environments are reported explicitly; results are never fabricated.
    """
    from mobsf_mcp.analysis.dynamic import run_dynamic_analysis

    try:
        async with MobSFClient(settings) as client:
            result = await run_dynamic_analysis(client, scan_hash, settings)
        return result.model_dump(mode="json")
    except Exception as exc:
        return {"status": "failed", "error": error_payload(exc)}


@mcp.resource("analysis://{scan_hash}/report", mime_type="application/json")
def analysis_report(scan_hash: str) -> str:
    """Read the latest normalized report cached by this server process."""
    return json.dumps(_REPORT_CACHE.get(scan_hash, {"status": "not_found", "scan_hash": scan_hash}))


@mcp.resource("analysis://{scan_hash}/findings", mime_type="application/json")
def analysis_findings(scan_hash: str) -> str:
    """Read normalized findings cached by this server process."""
    report = _REPORT_CACHE.get(scan_hash, {})
    return json.dumps({"scan_hash": scan_hash, "findings": report.get("findings", [])})


@mcp.resource("analysis://{scan_hash}/metadata", mime_type="application/json")
def analysis_metadata(scan_hash: str) -> str:
    """Read application metadata and hashes cached by this server process."""
    report = _REPORT_CACHE.get(scan_hash, {})
    return json.dumps(
        {
            "scan_hash": scan_hash,
            "application": report.get("application", {}),
            "hashes": report.get("hashes", {}),
        }
    )


@mcp.resource("analysis://{scan_hash}/scorecard", mime_type="application/json")
def analysis_scorecard(scan_hash: str) -> str:
    """Read the normalized security summary cached by this server process."""
    report = _REPORT_CACHE.get(scan_hash, {})
    return json.dumps({"scan_hash": scan_hash, "security": report.get("security", {})})


async def _startup_check() -> None:
    try:
        async with MobSFClient(settings) as client:
            await client.health_check()
        logger.info("MobSF connectivity/authentication check succeeded")
    except Exception as exc:
        logger.warning("MobSF startup check failed: %s", error_payload(exc))


def main() -> None:
    configure_logging()
    runtime_settings = Settings.from_env()
    asyncio.run(_startup_check())
    transport = __import__("os").getenv("MCP_TRANSPORT", "stdio").lower()
    if transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            host=runtime_settings.mcp_host,
            port=runtime_settings.mcp_port,
        )
    else:
        mcp.run()


if __name__ == "__main__":
    main()
