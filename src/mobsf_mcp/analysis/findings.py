from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, cast

from mobsf_mcp.models.finding import Finding, Severity

_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "warning": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


def extract_findings(report: Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for section_name, section in report.items():
        if not isinstance(section, Mapping):
            continue
        for rule_id, value in section.items():
            for raw in _iter_candidate_records(rule_id, value):
                finding = _to_finding(section_name, rule_id, raw)
                if finding:
                    findings.append(finding)
    return findings


def _iter_candidate_records(rule_id: str, value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        if any(key in value for key in ("title", "description", "severity", "issue", "rule")):
            yield value
        else:
            for nested_key, nested in value.items():
                if isinstance(nested, Mapping):
                    yield {"_nested_key": nested_key, **nested}
                elif isinstance(nested, list):
                    for item in nested:
                        if isinstance(item, Mapping):
                            yield {"_nested_key": nested_key, **item}
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                yield item
            elif isinstance(item, str):
                yield {"description": item}
    elif isinstance(value, str):
        yield {"description": value}


def _to_finding(section: str, rule_id: str, raw: Mapping[str, Any]) -> Finding | None:
    description = _string(raw.get("description") or raw.get("issue") or raw.get("details"))
    title = _string(
        raw.get("title") or raw.get("name") or raw.get("rule") or raw.get("_nested_key")
    )
    if not title and not description:
        return None
    original_severity = _string(raw.get("severity") or raw.get("level") or raw.get("risk"))
    normalized = (
        _SEVERITY_ALIASES.get(original_severity.lower(), "unknown")
        if original_severity
        else "unknown"
    )
    severity = cast(Severity, normalized)
    path = _string(raw.get("file") or raw.get("path") or raw.get("file_name"))
    return Finding(
        id=_string(raw.get("id") or rule_id) or rule_id,
        title=title or rule_id,
        severity=severity,
        original_severity=original_severity,
        confidence=_string(raw.get("confidence")),
        category=section,
        description=description or "",
        impact=_string(raw.get("impact")) or "",
        recommendation=_string(raw.get("recommendation") or raw.get("solution")) or "",
        affected_file=path,
        affected_component=_string(raw.get("component")),
        source_location=_string(raw.get("location") or raw.get("line")),
        mobsf_reference=_string(raw.get("reference") or raw.get("rule")) or rule_id,
    )


def _string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int, float)):
        return str(value)
    return None
