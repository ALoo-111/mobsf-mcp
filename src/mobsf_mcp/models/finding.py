from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]


class SourceEvidence(BaseModel):
    model_config = ConfigDict(extra="ignore")

    file: str
    line: int | None = None
    context: str = ""
    truncated: bool = False


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    title: str
    severity: Severity
    original_severity: str | None = None
    confidence: str | None = None
    category: str | None = None
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    evidence: list[SourceEvidence] = Field(default_factory=list)
    affected_file: str | None = None
    affected_component: str | None = None
    source_location: str | None = None
    mobsf_reference: str | None = None
