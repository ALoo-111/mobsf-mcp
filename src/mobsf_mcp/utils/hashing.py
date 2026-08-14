from __future__ import annotations

import hashlib
from pathlib import Path

_HASH_CHUNK_SIZE = 1024 * 1024


def calculate_hashes(path: Path) -> dict[str, str]:
    digests = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK_SIZE):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}
