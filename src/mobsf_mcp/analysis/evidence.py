from __future__ import annotations

from typing import Any

from mobsf_mcp.models.finding import Finding, SourceEvidence


def build_evidence(
    finding: Finding, source_response: dict[str, Any], *, max_bytes: int, context_lines: int
) -> SourceEvidence | None:
    if not finding.affected_file:
        return None
    text = _extract_text(source_response)
    if text is None:
        return None
    lines = text.splitlines()
    line_number = _line_number(finding.source_location)
    if line_number and 1 <= line_number <= len(lines):
        start = max(1, line_number - context_lines)
        end = min(len(lines), line_number + context_lines)
        context = "\n".join(f"{index}: {lines[index - 1]}" for index in range(start, end + 1))
    else:
        context = "\n".join(lines[: context_lines * 2 + 1])
    encoded = context.encode("utf-8", errors="replace")
    truncated = len(encoded) > max_bytes
    if truncated:
        context = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return SourceEvidence(
        file=finding.affected_file,
        line=line_number,
        context=context,
        truncated=truncated,
    )


def _extract_text(payload: dict[str, Any]) -> str | None:
    for key in ("code", "source", "contents", "content", "data"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            nested = _extract_text(value)
            if nested is not None:
                return nested
    return None


def _line_number(location: str | None) -> int | None:
    if not location:
        return None
    digits = "".join(character if character.isdigit() else " " for character in location).split()
    try:
        return int(digits[-1]) if digits else None
    except ValueError:
        return None
