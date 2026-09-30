"""JS intelligence helpers: hashing, beautify (lightweight), secret/route extraction."""

import hashlib
import re

SECRET_PATTERNS = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "generic_api_key",
        re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?"),
    ),
    ("bearer", re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.~+/=]{10,})")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
]
ROUTE_RE = re.compile(
    r"""['"`](/(?:api|v\d|graphql|rest|auth|admin|users|login)[A-Za-z0-9_\-/{}:.?=&%]*)['"`]"""
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def beautify(js: str) -> str:
    # Lightweight: break on ;{} boundaries. Full unminify is done by external tools when present.
    out = re.sub(r";", ";\n", js)
    out = re.sub(r"\{", "{\n", out)
    out = re.sub(r"\}", "\n}\n", out)
    return out[:500000]  # size guard


def extract_routes(js: str, limit=200):
    seen, routes = set(), []
    for m in ROUTE_RE.finditer(js or ""):
        r = m.group(1)
        if r not in seen:
            seen.add(r)
            routes.append(r)
        if len(routes) >= limit:
            break
    return routes


def extract_secret_candidates(js: str, limit=100):
    findings = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(js or ""):
            findings.append(
                {"type": name, "match_preview": m.group(0)[:24] + "***", "full": m.group(0)[:500]}
            )
            if len(findings) >= limit:
                return findings
    return findings


def detect_js_libraries(js: str):
    libs = []
    signatures = [
        "jquery",
        "react",
        "angular",
        "vue",
        "lodash",
        "moment",
        "bootstrap",
        "ember",
        "backbone",
    ]
    low = (js or "").lower()
    for lib in signatures:
        if lib in low:
            m = re.search(re.escape(lib) + r"[^0-9]{0,20}(\d+\.\d+(?:\.\d+)?)", low)
            libs.append({"library": lib, "version": m.group(1) if m else ""})
    return libs
