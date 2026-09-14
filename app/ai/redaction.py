"""Best-effort privacy filtering at ingestion and every outbound boundary.

Pattern matching is defense in depth, not a guarantee that arbitrary PII is absent.
Never submit regulated raw data without a deployment-specific ingestion policy.
"""

import re
from typing import Any

_SECRET_KEY = re.compile(
    r"(?i)^(?:password|passwd|pwd|secret|(?:api[_-]?)?key|api[_-]?token|"
    r"access[_-]?token|refresh[_-]?token|token|authorization|cookie|"
    r"client[_-]?secret|private[_-]?key|sig|signature|x-amz-signature|"
    r"aws[_-]?secret[_-]?access[_-]?key)$"
)
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [\w ]*PRIVATE KEY-----.*?-----END [\w ]*PRIVATE KEY-----", re.S
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+"), r"\1 [REDACTED]"),
    (
        re.compile(
            r"""(?ix)(["']?\b(?:password|passwd|pwd|secret|api[_-]?key|api[_-]?token|
            access[_-]?token|refresh[_-]?token|token|authorization|cookie|client[_-]?secret|
            aws[_-]?secret[_-]?access[_-]?key|sig|signature|x-amz-signature)["']?\s*[:=]\s*)
            (?:\[REDACTED(?: [A-Z ]+)?\]|"[^"\n]*"|'[^'\n]*'|[^\s,;&}\]]+)"""
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@"), r"\1[REDACTED]@"),
    (
        re.compile(
            r"""(?i)(https://hooks\.(?:slack\.com|slack-gov\.com)/services/)[^\s"']+"""
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(/3/device/)[0-9a-f]{64,200}\b"),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED AWS KEY]"),
    (
        re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
        "[REDACTED KEY]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "[REDACTED JWT]",
    ),
    (
        re.compile(r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
        "[REDACTED EMAIL]",
    ),
    (
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
        "[REDACTED IP]",
    ),
    (re.compile(r"(?<!\w)\+(?:\d[ -]?){9,14}\d(?!\w)"), "[REDACTED PHONE]"),
)


def redact(text: str) -> str:
    """Remove common credential, email, IPv4 and international phone patterns."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_value(value: Any, *, depth: int = 0) -> Any:
    """Filter nested JSON, including entire values associated with secret keys."""
    if depth > 12:
        return "[TRUNCATED NESTING]"
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {
            redact(str(key)): (
                "[REDACTED]"
                if _SECRET_KEY.fullmatch(str(key))
                else redact_value(item, depth=depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_value(item, depth=depth + 1) for item in value]
    return value
