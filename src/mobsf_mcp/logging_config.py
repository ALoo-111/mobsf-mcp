from __future__ import annotations

import logging
import sys


class RedactSecretsFilter(logging.Filter):
    """Redact common credential-shaped values from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for key in ("MOBSF_API_KEY", "Authorization", "X-Mobsf-Api-Key"):
            if key in message:
                record.msg = "Sensitive value redacted from log message"
                record.args = ()
                break
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactSecretsFilter())
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), handlers=[handler])
