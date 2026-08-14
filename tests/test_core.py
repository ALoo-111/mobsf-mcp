from __future__ import annotations

import zipfile

import httpx
import pytest

from mobsf_mcp.analysis.evidence import build_evidence
from mobsf_mcp.analysis.findings import extract_findings
from mobsf_mcp.analysis.normalizer import normalize_report
from mobsf_mcp.config import ConfigurationError, Settings
from mobsf_mcp.mobsf.client import MobSFClient
from mobsf_mcp.mobsf.exceptions import MobSFAuthenticationError
from mobsf_mcp.models.finding import Finding
from mobsf_mcp.utils.files import validate_apk_path
from mobsf_mcp.utils.hashing import calculate_hashes


def _settings() -> Settings:
    return Settings(mobsf_url="http://mobsf.test", max_apk_size_mb=2)


def _apk(path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")


def test_settings_reject_invalid_url() -> None:
    with pytest.raises(ConfigurationError):
        Settings(mobsf_url="not-a-url").validate()


def test_settings_reads_runtime_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MOBSF_URL", "https://mobsf.live")
    monkeypatch.setenv("MOBSF_API_KEY", "runtime-only-placeholder")
    settings = Settings.from_env(load_file=False)
    assert settings.mobsf_url == "https://mobsf.live"
    assert settings.mobsf_api_key == "runtime-only-placeholder"


def test_validate_apk_and_hashes(tmp_path) -> None:
    path = tmp_path / "sample.apk"
    _apk(path)
    validated = validate_apk_path(str(path), _settings())
    hashes = calculate_hashes(validated)
    assert validated == path.resolve()
    assert set(hashes) == {"md5", "sha1", "sha256"}
    assert all(len(value) in {32, 40, 64} for value in hashes.values())


def test_extract_and_normalize_findings() -> None:
    report = {
        "manifest": {
            "exported_component": {
                "title": "Exported component",
                "severity": "high",
                "description": "Component is exported.",
                "path": "AndroidManifest.xml",
                "line": 12,
                "solution": "Restrict the component.",
            }
        },
        "app_name": "Demo",
        "package_name": "com.example.demo",
    }
    findings = extract_findings(report)
    normalized = normalize_report(report, {"score": 55}, findings=findings)
    assert normalized.application.name == "Demo"
    assert normalized.security.risk_level == "high"
    assert normalized.findings[0].severity == "high"
    assert normalized.findings[0].affected_file == "AndroidManifest.xml"


def test_evidence_is_bounded() -> None:
    finding = Finding(
        id="rule",
        title="Issue",
        severity="high",
        affected_file="src/Main.java",
        source_location="line 3",
    )
    evidence = build_evidence(
        finding,
        {"code": "one\ntwo\nthree\nfour\nfive"},
        max_bytes=12,
        context_lines=1,
    )
    assert evidence is not None
    assert evidence.truncated is True
    assert len(evidence.context.encode()) <= 12


@pytest.mark.asyncio
async def test_client_maps_authentication_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"}, request=request)

    client = MobSFClient(
        _settings(),
        http_client=httpx.AsyncClient(
            base_url="http://mobsf.test", transport=httpx.MockTransport(handler)
        ),
    )
    with pytest.raises(MobSFAuthenticationError):
        await client.search("demo")
    await client.aclose()
