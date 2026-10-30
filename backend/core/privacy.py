"""Redact obvious secrets from stored raw logs without dropping forensic context."""

from __future__ import annotations

import re

_SECRET_PATTERNS = (
    re.compile(r"(password\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(passwd\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(secret\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(bearer\s+)\S+", re.IGNORECASE),
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)", re.IGNORECASE | re.DOTALL),
)


def redact_secrets(text: str | None) -> str:
    value = text or ""
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", value)
    return value
