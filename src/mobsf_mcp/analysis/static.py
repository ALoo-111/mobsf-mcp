from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mobsf_mcp.analysis.evidence import build_evidence
from mobsf_mcp.analysis.findings import extract_findings
from mobsf_mcp.analysis.normalizer import normalize_report
from mobsf_mcp.config import Settings
from mobsf_mcp.mobsf.client import MobSFClient
from mobsf_mcp.mobsf.exceptions import MobSFScanError
from mobsf_mcp.models.apk import APKMetadata
from mobsf_mcp.models.report import NormalizedReport

logger = logging.getLogger(__name__)


async def run_static_analysis(
    client: MobSFClient,
    apk: APKMetadata,
    settings: Settings,
    *,
    include_source_evidence: bool = True,
    include_raw_report: bool = False,
) -> NormalizedReport:
    upload_result = await client.upload(_path_from_metadata(apk))
    scan_hash = str(upload_result.get("hash") or apk.md5)
    logger.info("MobSF scan started for %s", apk.filename)
    await client.scan(scan_hash)
    logs = await client.scan_logs(scan_hash)
    if _scan_failed(logs):
        raise MobSFScanError("MobSF reported a scan failure")
    report = await client.report_json(scan_hash)
    scorecard = await client.scorecard(scan_hash)
    findings = extract_findings(report)

    if include_source_evidence:
        for finding in findings:
            if not finding.affected_file:
                continue
            try:
                source = await client.view_source(scan_hash, finding.affected_file)
            except Exception as exc:  # Evidence is best-effort; primary analysis remains usable.
                logger.warning(
                    "Source evidence unavailable for finding %s: %s", finding.id, type(exc).__name__
                )
                continue
            evidence = build_evidence(
                finding,
                source,
                max_bytes=settings.max_source_bytes,
                context_lines=settings.source_context_lines,
            )
            if evidence:
                finding.evidence.append(evidence)

    result = normalize_report(
        report,
        scorecard,
        apk=apk,
        findings=findings,
        include_raw=include_raw_report,
    )
    result.hashes["mobsf_scan_hash"] = scan_hash
    return result


def _path_from_metadata(apk: APKMetadata) -> Path:
    return Path(apk.path)


def _scan_failed(logs: dict[str, Any]) -> bool:
    for item in logs.get("logs", []) if isinstance(logs.get("logs"), list) else []:
        if isinstance(item, dict) and item.get("exception"):
            return True
    return False
