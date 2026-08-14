from __future__ import annotations

import zipfile
from pathlib import Path

from mobsf_mcp.config import Settings
from mobsf_mcp.mobsf.exceptions import APKValidationError


def validate_apk_path(apk_path: str, settings: Settings) -> Path:
    candidate = Path(apk_path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise APKValidationError("APK path does not exist") from exc

    if not resolved.is_file():
        raise APKValidationError("APK path is not a regular file")
    if resolved.suffix.lower() != ".apk":
        raise APKValidationError("Input file must have an .apk extension")
    if resolved.stat().st_size > settings.max_apk_size_mb * 1024 * 1024:
        raise APKValidationError(f"APK exceeds the {settings.max_apk_size_mb} MB size limit")
    if not _looks_like_apk(resolved):
        raise APKValidationError("Input does not have a valid ZIP/APK container signature")
    return resolved


def _looks_like_apk(path: Path) -> bool:
    with path.open("rb") as handle:
        signature = handle.read(4)
    if signature not in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}:
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            return (
                "AndroidManifest.xml" in names
                or "resources.arsc" in names
                or any(name.startswith("classes") and name.endswith(".dex") for name in names)
            )
    except (OSError, zipfile.BadZipFile):
        return False
