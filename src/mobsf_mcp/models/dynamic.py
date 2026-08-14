from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class DynamicCapability(BaseModel):
    model_config = ConfigDict(extra="ignore")

    supported: bool
    reason: str | None = None
    data: dict[str, Any] | None = None
