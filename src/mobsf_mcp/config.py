from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv


class ConfigurationError(ValueError):
    """Raised when required or malformed configuration is detected."""


@dataclass(frozen=True)
class Settings:
    mobsf_url: str = "http://127.0.0.1:8000"
    mobsf_api_key: str = ""
    mobsf_timeout: float = 300.0
    mobsf_verify_tls: bool = True
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8001
    max_apk_size_mb: int = 500
    enable_dynamic_analysis: bool = False
    dynamic_analysis_timeout: float = 600.0
    max_response_bytes: int = 50 * 1024 * 1024
    http_client_backend: str = "curl_cffi"
    http_client_http2: bool = False
    source_context_lines: int = 3
    max_source_bytes: int = 64 * 1024

    @classmethod
    def from_env(cls, *, load_file: bool = True) -> Settings:
        if load_file:
            load_dotenv()
        settings = cls(
            mobsf_url=os.getenv("MOBSF_URL", cls.mobsf_url).rstrip("/"),
            mobsf_api_key=os.getenv("MOBSF_API_KEY", ""),
            mobsf_timeout=_float_env("MOBSF_TIMEOUT", cls.mobsf_timeout),
            mobsf_verify_tls=_bool_env("MOBSF_VERIFY_TLS", cls.mobsf_verify_tls),
            mcp_host=os.getenv("MCP_HOST", cls.mcp_host),
            mcp_port=_int_env("MCP_PORT", cls.mcp_port),
            max_apk_size_mb=_int_env("MAX_APK_SIZE_MB", cls.max_apk_size_mb),
            enable_dynamic_analysis=_bool_env(
                "ENABLE_DYNAMIC_ANALYSIS", cls.enable_dynamic_analysis
            ),
            dynamic_analysis_timeout=_float_env(
                "DYNAMIC_ANALYSIS_TIMEOUT", cls.dynamic_analysis_timeout
            ),
            max_response_bytes=_int_env("MAX_RESPONSE_BYTES", cls.max_response_bytes),
            http_client_backend=os.getenv("HTTP_CLIENT_BACKEND", cls.http_client_backend),
            http_client_http2=_bool_env("HTTP_CLIENT_HTTP2", cls.http_client_http2),
            source_context_lines=_int_env("SOURCE_CONTEXT_LINES", cls.source_context_lines),
            max_source_bytes=_int_env("MAX_SOURCE_BYTES", cls.max_source_bytes),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        parsed = urlparse(self.mobsf_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigurationError("MOBSF_URL must be an absolute http(s) URL")
        if self.mobsf_timeout <= 0 or self.dynamic_analysis_timeout <= 0:
            raise ConfigurationError("Timeouts must be positive")
        if not 1 <= self.mcp_port <= 65535:
            raise ConfigurationError("MCP_PORT must be between 1 and 65535")
        if self.max_apk_size_mb <= 0:
            raise ConfigurationError("MAX_APK_SIZE_MB must be positive")
        if self.max_response_bytes <= 0 or self.max_source_bytes <= 0:
            raise ConfigurationError("Response and source limits must be positive")
        valid_backends = {"requests", "httpx", "curl_cffi", "curl-cffi"}
        if self.http_client_backend.strip().lower() not in valid_backends:
            raise ConfigurationError(
                "HTTP_CLIENT_BACKEND must be one of: requests, httpx, curl_cffi"
            )
        if self.source_context_lines < 0:
            raise ConfigurationError("SOURCE_CONTEXT_LINES cannot be negative")


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean")


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
