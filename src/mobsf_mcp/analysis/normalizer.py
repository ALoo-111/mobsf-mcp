from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from mobsf_mcp.models.apk import APKMetadata
from mobsf_mcp.models.finding import Finding
from mobsf_mcp.models.report import ApplicationMetadata, NormalizedReport, SecuritySummary


def normalize_report(
    report: Mapping[str, Any],
    scorecard: Mapping[str, Any] | None,
    *,
    apk: APKMetadata | None = None,
    findings: list[Finding] | None = None,
    include_raw: bool = False,
) -> NormalizedReport:
    metadata = _metadata(report)
    counts = _severity_counts(findings or [])
    score = _first(report, "score", "security_score")
    if score is None and scorecard:
        score = _first(scorecard, "score", "security_score", "overall_score")
    risk = _risk_level(counts, score)
    return NormalizedReport(
        status="completed",
        application=metadata,
        hashes={
            key: value
            for key, value in {
                "md5": _string(_first(report, "md5", "MD5")),
                "sha1": _string(_first(report, "sha1", "SHA1", "SHA-1")),
                "sha256": _string(_first(report, "sha256", "SHA256", "SHA-256")),
            }.items()
            if value
        },
        security=SecuritySummary(score=_number(score), risk_level=risk, counts=counts),
        findings=findings or [],
        permissions=_string_list(_first(report, "permissions", "Permissions")),
        components=_mapping_or_empty(
            _first(report, "components", "android_components", "manifest")
        ),
        urls_domains=_string_list(_first(report, "urls", "domains", "urls_domains")),
        certificates=_list_or_empty(_first(report, "certificate_analysis", "certificates")),
        libraries=_string_list(_first(report, "libraries", "third_party_libraries")),
        native_libraries=_string_list(_first(report, "native_libraries", "native_libs")),
        secrets=_list_or_empty(_first(report, "secrets", "hardcoded_secrets")),
        network_security=_mapping_or_empty(
            _first(report, "network_security", "network_security_config")
        ),
        webviews=_list_or_empty(_first(report, "webviews", "webview")),
        crypto=_list_or_empty(_first(report, "crypto", "cryptography")),
        firebase=_list_or_empty(_first(report, "firebase", "firebase_services")),
        trackers=_list_or_empty(_first(report, "trackers", "tracking")),
        apk=apk,
        raw_report=dict(report) if include_raw else None,
        recommended_fix_priority=_recommendations(findings or []),
    )


def _metadata(report: Mapping[str, Any]) -> ApplicationMetadata:
    source = (
        cast(Mapping[str, Any], report["appsec"])
        if isinstance(report.get("appsec"), Mapping)
        else report
    )
    return ApplicationMetadata(
        name=_string(_first(source, "app_name", "appname", "name", "APP_NAME")),
        package=_string(_first(source, "package_name", "packagename", "package", "PACKAGE_NAME")),
        version_name=_string(_first(source, "version_name", "version", "VERSION_NAME")),
        version_code=_string(_first(source, "version_code", "versioncode", "VERSION_CODE")),
        min_sdk=_string(_first(source, "min_sdk", "minSdk", "MIN_SDK")),
        target_sdk=_string(_first(source, "target_sdk", "targetSdk", "TARGET_SDK")),
    )


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _risk_level(counts: dict[str, int], score: Any) -> str:
    if counts.get("critical", 0):
        return "critical"
    if counts.get("high", 0):
        return "high"
    if counts.get("medium", 0):
        return "medium"
    if isinstance(score, (int, float)):
        if score < 40:
            return "high"
        if score < 70:
            return "medium"
        return "low"
    if counts.get("low", 0):
        return "low"
    return "unknown"


def _recommendations(findings: list[Finding]) -> list[str]:
    ordered = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    return [
        finding.recommendation
        for finding in sorted(findings, key=lambda item: ordered[item.severity])
        if finding.recommendation
    ][:10]


def _first(source: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in source:
            return source[key]
    return None


def _string(value: Any) -> str | None:
    return str(value) if isinstance(value, (str, int, float)) else None


def _number(value: Any) -> float | int | None:
    return value if isinstance(value, (int, float)) else None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item if isinstance(item, str) else str(item) for item in value]
    if isinstance(value, dict):
        return [str(key) for key in value]
    return []


def _list_or_empty(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value] if isinstance(value, (str, dict)) else []


def _mapping_or_empty(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}
