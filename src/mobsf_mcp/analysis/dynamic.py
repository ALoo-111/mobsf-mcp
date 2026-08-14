from __future__ import annotations

from mobsf_mcp.config import Settings
from mobsf_mcp.mobsf.client import MobSFClient
from mobsf_mcp.mobsf.exceptions import MobSFUnsupportedEndpoint
from mobsf_mcp.models.report import DynamicAnalysisResult


async def run_dynamic_analysis(
    client: MobSFClient,
    scan_hash: str,
    settings: Settings,
) -> DynamicAnalysisResult:
    if not settings.enable_dynamic_analysis:
        return DynamicAnalysisResult(
            available=False,
            status="not_configured",
            reason="Dynamic analysis is disabled by ENABLE_DYNAMIC_ANALYSIS",
        )
    try:
        apps = await client.dynamic_get_apps()
        start = await client.dynamic_start_analysis(scan_hash)
        report = await client.dynamic_report_json(scan_hash)
        return DynamicAnalysisResult(
            available=True,
            status="completed",
            report={"apps": apps, "start": start, "report": report},
        )
    except MobSFUnsupportedEndpoint as exc:
        return DynamicAnalysisResult(available=False, status="unsupported", reason=str(exc))
    except Exception as exc:
        return DynamicAnalysisResult(
            available=False,
            status="failed",
            reason=f"Dynamic analysis failed: {type(exc).__name__}",
        )
