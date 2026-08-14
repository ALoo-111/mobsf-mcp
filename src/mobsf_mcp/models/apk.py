from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class APKMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")

    path: str
    filename: str
    size_bytes: int = Field(ge=0)
    md5: str
    sha1: str
    sha256: str

    @classmethod
    def from_path(cls, path: Path, *, md5: str, sha1: str, sha256: str) -> APKMetadata:
        stat = path.stat()
        return cls(
            path=str(path),
            filename=path.name,
            size_bytes=stat.st_size,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
        )
