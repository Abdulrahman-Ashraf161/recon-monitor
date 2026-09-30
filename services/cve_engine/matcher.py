"""CVE correlation: product/vendor normalization + affected-version matching.
Version match alone NEVER yields 'validated' — only candidate/potentially_affected.
"""

import re

from packaging.version import InvalidVersion, Version


def normalize_product(name: str) -> str:
    n = (name or "").strip().lower()
    n = re.sub(r"[^a-z0-9+_.-]+", "", n)
    aliases = {"nodejs": "node.js", "ngx": "nginx", "apache2": "httpd", "ms-iis": "iis"}
    return aliases.get(n, n)


def normalize_vendor(name: str) -> str:
    return (name or "").strip().lower()


def _parse(v: str):
    try:
        return Version(v.strip())
    except InvalidVersion:
        m = re.match(r"(\d+(?:\.\d+)*)", (v or "").strip())
        if m:
            try:
                return Version(m.group(1))
            except InvalidVersion:
                return None
        return None


def version_in_range(detected: str, affected_range: str) -> bool:
    """affected_range like '>=1.0,<2.3.4' or '<=1.2.3' or '==1.2.3'. Empty range -> True (unknown scope)."""
    if not affected_range or not affected_range.strip():
        return True
    dv = _parse(detected)
    if dv is None:
        return False
    for clause in affected_range.split(","):
        clause = clause.strip()
        m = re.match(r"(>=|<=|==|>|<|=)?\s*(.+)", clause)
        if not m:
            continue
        op, ver = m.group(1) or "==", m.group(2)
        pv = _parse(ver)
        if pv is None:
            continue
        ok = {
            "==": dv == pv,
            "=": dv == pv,
            ">": dv > pv,
            "<": dv < pv,
            ">=": dv >= pv,
            "<=": dv <= pv,
        }[op]
        if not ok:
            return False
    return True


# Minimal bundled knowledge base (real deployments sync CVEProject/cvelistV5 via sync_cve_database).
# Each entry: product, affected_range, cve_id, severity hint, summary.
BUNDLED_KB = [
    {
        "product": "nginx",
        "affected_range": "<1.25.0",
        "cve_id": "CVE-EXAMPLE-NGINX",
        "severity": "MEDIUM",
        "summary": "Example bundled rule: old nginx line (replace with cvelistV5 sync in production).",
    },
]


def correlate(technology, kb=None):
    """Return list of candidate dicts for a Technology instance."""
    kb = kb if kb is not None else BUNDLED_KB
    prod = normalize_product(technology.product)
    cands = []
    for entry in kb:
        if normalize_product(entry["product"]) != prod:
            continue
        if technology.version and not version_in_range(
            technology.version, entry.get("affected_range", "")
        ):
            continue
        cands.append(entry)
    return cands
