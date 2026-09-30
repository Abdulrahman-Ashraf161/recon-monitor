"""HTTP fingerprinting (TASK-014): deterministic hash of normalized relevant state."""

import hashlib
import json
from typing import Any

RELEVANT_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "via",
    "x-cache",
    "strict-transport-security",
]


def normalize_http_state(entry: dict[str, Any]) -> dict[str, Any]:
    headers = entry.get("headers") or {}
    if isinstance(headers, dict):
        rel = {k.lower(): str(v) for k, v in headers.items() if k.lower() in RELEVANT_HEADERS}
    else:
        rel = {}
    techs = entry.get("technologies") or entry.get("tech") or []
    if isinstance(techs, list):
        techs = sorted([t if isinstance(t, str) else str(t.get("name", t)) for t in techs])
    else:
        techs = []
    return {
        "scheme": (entry.get("scheme") or "").lower(),
        "host": (entry.get("host") or "").lower(),
        "port": entry.get("port", ""),
        "status_code": entry.get("status_code", ""),
        "title": (entry.get("title") or "").strip(),
        "server": (entry.get("server") or entry.get("webserver") or "").strip(),
        "content_type": (entry.get("content_type") or "").split(";")[0].strip().lower(),
        "content_length": entry.get("content_length", ""),
        "ip": entry.get("ip", ""),
        "redirect_chain": entry.get("redirect_chain") or [],
        "technologies": techs,
        "headers": rel,
        "tls": entry.get("tls") or entry.get("tls_info") or {},
    }


def http_fingerprint(entry: dict[str, Any]) -> str:
    norm = normalize_http_state(entry)
    return hashlib.sha256(json.dumps(norm, sort_keys=True, default=str).encode()).hexdigest()[:32]
