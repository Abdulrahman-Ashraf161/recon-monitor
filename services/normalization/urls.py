"""URL normalization (raw_url + canonical_url) + API classification (TASK-019/020).

Normalization: scheme/host lowercase, default ports stripped, fragments dropped,
percent-encoding normalized, trailing-slash handling, query params sorted so
semantically identical URLs map to one asset.
Classification uses path + content-type + headers + body signals, not path alone.
"""

from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

API_PATTERNS = [
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/graphql",
    "/rest/",
    "/swagger",
    "/openapi.json",
    "/v1/",
    "/v2/",
    "/wp-json/",
    "/.well-known/openapi",
    "/graphql/",
    "/gql",
]


def canonicalize_url(raw: str) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlparse(raw)
    except Exception:
        return None
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return None
    port = p.port
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host if (not port or port == default) else f"{host}:{port}"
    try:
        path = unquote(p.path or "/")
    except Exception:
        path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    # sort query params for stable identity (TASK-019)
    try:
        qsl = parse_qsl(p.query, keep_blank_values=True)
        query = urlencode(sorted(qsl))
    except Exception:
        query = p.query
    return urlunparse((scheme, netloc, path, "", query, ""))  # fragment always dropped


def classify_api(
    url: str, content_type: str = "", headers: dict[str, str] | None = None, body_hint: str = ""
) -> tuple[bool, str, list[str]]:
    """Evidence-based API classification (TASK-020)."""
    low = (url or "").lower()
    ct = (content_type or "").lower()
    hdrs = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    body = (body_hint or "").lower()
    signals = []
    for pat in API_PATTERNS:
        if pat in low:
            signals.append(f"path:{pat}")
    if "application/json" in ct and ("/api" in low or "graphql" in low or "rest" in low):
        signals.append("content-type:json+path")
    if "graphql" in body or ('"data"' in body and '"errors"' in body):
        signals.append("body:graphql-shape")
    if "swagger" in body or "openapi" in body:
        signals.append("body:openapi-schema")
    if "x-api-version" in hdrs or "x-version" in hdrs:
        signals.append("header:version")
    if not signals:
        return False, "", []
    if "graphql" in low or "body:graphql-shape" in signals:
        api_type = "GraphQL"
    elif "swagger" in low or "openapi" in low or "body:openapi-schema" in signals:
        api_type = "OpenAPI/Swagger"
    elif "/v1/" in low or "/v2/" in low or "header:version" in signals:
        api_type = "Versioned REST"
    else:
        api_type = "REST"
    auth_hints = [
        h for h in ("auth", "login", "token", "admin", "internal", "oauth", "jwt") if h in low
    ]
    return True, api_type, auth_hints
