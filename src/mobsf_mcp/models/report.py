from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from mobsf_mcp.models.apk import APKMetadata
from mobsf_mcp.models.finding import Finding


class ApplicationMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str | None = None
    package: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None


class SecuritySummary(BaseModel):
    score: float | int | None = None
    risk_level: str = "unknown"
    counts: dict[str, int] = Field(default_factory=dict)


class DynamicAnalysisResult(BaseModel):
    available: bool
    status: Literal["completed", "not_configured", "unsupported", "failed"]
    reason: str | None = None
    report: dict[str, Any] | None = None


class NormalizedReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: Literal["completed", "failed"]
    application: ApplicationMetadata = Field(default_factory=ApplicationMetadata)
    hashes: dict[str, str] = Field(default_factory=dict)
    security: SecuritySummary = Field(default_factory=SecuritySummary)
    findings: list[Finding] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    components: dict[str, Any] = Field(default_factory=dict)
    urls_domains: list[str] = Field(default_factory=list)
    certificates: list[dict[str, Any] | str] = Field(default_factory=list)
    libraries: list[str] = Field(default_factory=list)
    native_libraries: list[str] = Field(default_factory=list)
    secrets: list[dict[str, Any] | str] = Field(default_factory=list)
    network_security: dict[str, Any] = Field(default_factory=dict)
    webviews: list[dict[str, Any] | str] = Field(default_factory=list)
    crypto: list[dict[str, Any] | str] = Field(default_factory=list)
    firebase: list[dict[str, Any] | str] = Field(default_factory=list)
    trackers: list[dict[str, Any] | str] = Field(default_factory=list)
    source_evidence: list[dict[str, Any]] = Field(default_factory=list)
    dynamic_analysis: DynamicAnalysisResult = Field(
        default_factory=lambda: DynamicAnalysisResult(
            available=False,
            status="not_configured",
            reason="No dynamic environment configured",
        )
    )
    limitations: list[str] = Field(default_factory=list)
    recommended_fix_priority: list[str] = Field(default_factory=list)
    raw_report: dict[str, Any] | None = None
    apk: APKMetadata | None = None
