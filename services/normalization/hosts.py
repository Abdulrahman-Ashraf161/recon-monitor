"""Hostname normalization + dedup (mandatory before storage)."""

import re

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$", re.IGNORECASE
)


def normalize_hostname(raw: str) -> str | None:
    if not raw:
        return None
    h = raw.strip().lower().rstrip(".")
    try:
        h = h.encode("idna").decode("ascii")
    except Exception:
        return None
    if not _HOST_RE.match(h):
        return None
    return h


def dedup_hostnames(items):
    """items: iterable of (hostname, source). Returns dict hostname -> set(sources)."""
    merged: dict[str, set] = {}
    for raw, source in items:
        h = normalize_hostname(raw)
        if not h:
            continue
        merged.setdefault(h, set()).add(source)
    return {h: sorted(s) for h, s in merged.items()}
