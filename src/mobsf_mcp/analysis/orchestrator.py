from __future__ import annotations

import logging
from time import perf_counter

from mobsf_mcp.analysis.dynamic import run_dynamic_analysis
from mobsf_mcp.analysis.static import run_static_analysis
from mobsf_mcp.config import Settings
from mobsf_mcp.mobsf.client import MobSFClient
from mobsf_mcp.models.apk import APKMetadata
from mobsf_mcp.models.report import NormalizedReport
from mobsf_mcp.utils.files import validate_apk_path
from mobsf_mcp.utils.hashing import calculate_hashes

logger = logging.getLogger(__name__)


async def analyze_apk(
    apk_path: str,
    *,
    settings: Settings,
    client: MobSFClient,
    include_source_evidence: bool = True,
    include_raw_report: bool = False,
    enable_dynamic: bool = False,
) -> NormalizedReport:
    started = perf_counter()
    path = validate_apk_path(apk_path, settings)
    hashes = calculate_hashes(path)
    metadata = APKMetadata.from_path(path, **hashes)
    logger.info(
        "Analysis started: filename=%s size_bytes=%s sha256=%s",
        metadata.filename,
        metadata.size_bytes,
        metadata.sha256,
    )
    result = await run_static_analysis(
        client,
        metadata,
        settings,
        include_source_evidence=include_source_evidence,
        include_raw_report=include_raw_report,
    )
    if enable_dynamic:
        scan_hash = result.hashes.get("mobsf_scan_hash", metadata.md5)
        result.dynamic_analysis = await run_dynamic_analysis(client, scan_hash, settings)
    result.limitations.append(
        "Static analysis is heuristic evidence and does not by itself prove "
        "malware or exploitability."
    )
    result.limitations.append(
        "Dynamic analysis requires a supported MobSF Android runtime and is disabled "
        "unless explicitly enabled."
    )
    logger.info("Analysis completed in %.2fs", perf_counter() - started)
    return result
