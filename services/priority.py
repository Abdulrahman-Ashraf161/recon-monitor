"""Explainable asset priority (TASK-037/038).

Levels: CRITICAL/HIGH/MEDIUM/LOW/INFO based on explicit factors.
Every result returns (level, reasons:list[str]).
"""

ADMIN_HINTS = (
    "admin",
    "internal",
    "manage",
    "console",
    "dashboard",
    "login",
    "auth",
    "token",
    "secret",
    "config",
    "debug",
    "test",
    "staging",
    "dev",
)
INTERESTING_PORTS = {
    22: "ssh",
    3389: "rdp",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongo",
    8443: "alt-https",
    8080: "alt-http",
}

ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _bump(current, candidate):
    return candidate if ORDER[candidate] > ORDER[current] else current


def prioritize_asset(asset_type, value="", change_type="", metadata=None):
    """Generic prioritizer. Returns (level, reasons)."""
    meta = metadata or {}
    level = "LOW"
    reasons = []
    v = (value or "").lower()
    for hint in ADMIN_HINTS:
        if hint in v:
            level = _bump(level, "HIGH")
            reasons.append(f"Name suggests sensitive surface ({hint})")
            break
    ct = (change_type or "").upper()
    if ct in (
        "NEW_API_ENDPOINT",
        "NEW_SECURITY_FINDING",
        "CVE_VALIDATED",
        "NEW_JS_SECRET_CANDIDATE",
    ):
        level = _bump(level, "HIGH")
        reasons.append(f"High-impact change type {ct}")
    if ct in ("NEW_OPEN_PORT", "NEW_HTTP_SERVICE", "NEW_SUBDOMAIN"):
        level = _bump(level, "MEDIUM")
        reasons.append(f"Attack-surface expansion ({ct})")
    if asset_type == "PORT":
        try:
            port_no = int(str(meta.get("port", "") or "").split("/")[0] or 0)
            if port_no in INTERESTING_PORTS:
                level = _bump(level, "HIGH")
                reasons.append(f"Sensitive service port {port_no} ({INTERESTING_PORTS[port_no]})")
        except Exception:
            pass
    if meta.get("severity") in ("CRITICAL", "HIGH"):
        level = _bump(level, meta["severity"])
        reasons.append(f"Source severity {meta['severity']}")
    if meta.get("validation") == "VALIDATED":
        level = _bump(level, "CRITICAL")
        reasons.append("Validated finding")
    if not reasons:
        reasons.append("Routine attack-surface observation")
    return level, reasons


def prioritize_event(event_type, asset_value="", evidence=None):
    ev = evidence or {}
    meta = {
        "port": ev.get("port", ""),
        "severity": ev.get("severity", ""),
        "validation": ev.get("validation", ""),
    }
    return prioritize_asset(ev.get("asset_type", ""), asset_value, event_type, meta)
