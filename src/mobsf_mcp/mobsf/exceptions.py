from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class MobSFError(Exception):
    message: str
    status_code: int | None = None
    response_body: Any = None

    def __str__(self) -> str:
        return self.message


class MobSFConnectionError(MobSFError):
    pass


class MobSFAuthenticationError(MobSFError):
    pass


class MobSFScanError(MobSFError):
    pass


class MobSFTimeoutError(MobSFError):
    pass


class MobSFUnsupportedEndpoint(MobSFError):
    pass


class APKValidationError(MobSFError):
    pass


class AnalysisError(MobSFError):
    pass


def error_payload(error: Exception) -> dict[str, Any]:
    if isinstance(error, MobSFError):
        return {
            "type": type(error).__name__,
            "message": str(error),
            "status_code": error.status_code,
        }
    return {"type": type(error).__name__, "message": "Unexpected internal error"}
