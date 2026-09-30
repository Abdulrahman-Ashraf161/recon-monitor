"""Redaction helpers for anything that gets persisted (P1-002).

Tool output is evidence, but it is also attacker-influenced text: a scanner
that matches a secret writes the secret to stdout, and that stdout is about to
be stored next to the target's asset inventory. Everything written to the
database or to disk by the evidence pipeline goes through here first.
"""

import re

# High-signal patterns for credential material in tool output.
_PATTERNS = [
    # key = value / key: value assignments (JSON, env dumps, config echoes)
    (
        re.compile(
            r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token"
            r"|refresh[_-]?token|auth[_-]?token|password|passwd|pwd|private[_-]?key"
            r'|secret|token|credential)\b(\s*[:=]\s*"?)([^\s",}]{4,})'
        ),
        r"\1\2***REDACTED***",
    ),
    # Authorization / Proxy-Authorization / Cookie headers
    (
        re.compile(
            r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\b"
            r"(\s*:\s*)([^\r\n]{4,})"
        ),
        r"\1\2***REDACTED***",
    ),
    # Bearer / Basic / token schemes
    (re.compile(r"(?i)\b(bearer|basic|token)\s+([A-Za-z0-9._\-+/=]{8,})"), r"\1 ***REDACTED***"),
    # AWS-style access key ids (AKIA/ASIA + 16-40 uppercase alphanumerics)
    (re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{12,40})\b"), "***REDACTED***"),
    # GitHub / Slack / Stripe style tokens
    (
        re.compile(
            r"\b(gh[pousr]_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}"
            r"|sk_live_[A-Za-z0-9]{16,})\b"
        ),
        "***REDACTED***",
    ),
    # PEM blocks
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
        "***REDACTED-PRIVATE-KEY***",
    ),
    # user:pass inside URLs
    (re.compile(r'(://[^/\s:@"]+):([^/\s@"]+)@'), r"\1:***REDACTED***@"),
    # Discord/Slack webhook URLs
    (
        re.compile(r'https://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com)/[^\s"\'<>]+'),
        "***REDACTED-WEBHOOK***",
    ),
]

REDACTED = "***REDACTED***"


def redact_text(text: str, limit: int = 0) -> str:
    """Return ``text`` with credential material masked.

    ``limit`` (optional) truncates the *result* so a huge scanner dump is
    bounded before it ever reaches the disk.
    """
    if not text:
        return ""
    out = str(text)
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    if limit and len(out) > limit:
        out = out[:limit] + f"\n[truncated at {limit} chars]"
    return out


def contains_secret(text: str) -> bool:
    """True when redaction would change ``text`` (i.e. it holds credentials)."""
    if not text:
        return False
    return redact_text(text) != str(text)
