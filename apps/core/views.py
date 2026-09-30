"""Core views: health probe and cross-asset search (P0-007).

``global_search`` previously ran the query string against **every** asset model
unscoped and returned the hits as JSON, so any authenticated user could
enumerate hosts, CVEs and findings belonging to other tenants, and the response
also acted as an existence oracle for record ids. Results are now restricted to
the caller's authorized targets, and the unauthenticated health probe no longer
publishes per-tool detail.
"""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect, render

# Per-model result rows returned to the search page. A display bound, not a
# processing cap (P3-002).
SEARCH_RESULT_LIMIT = 10

# (label, model, field, target lookup) — the target lookup is the ORM path to
# the owning Target and drives the membership filter.
SEARCH_SOURCES = [
    ("Subdomain", "apps.assets.models", "Subdomain", "hostname", "target"),
    ("IP", "apps.assets.models", "IPAddress", "ip", "target"),
    ("Port", "apps.assets.models", "Port", "ip", "target"),
    ("HTTP", "apps.assets.models", "HTTPService", "url", "target"),
    ("URL", "apps.assets.models", "URLAsset", "canonical_url", "target"),
    ("API", "apps.assets.models", "APIEndpoint", "url", "target"),
    ("JS", "apps.assets.models", "JavaScriptAsset", "js_url", "target"),
    ("Tech", "apps.assets.models", "Technology", "product", "target"),
    ("CVE", "apps.assets.models", "CVE", "cve_id", "target"),
    ("Finding", "apps.assets.models", "SecurityFinding", "title", "target"),
    ("Event", "apps.events.models", "Event", "asset_value", "target"),
]


def home(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    return redirect("login")


def health(request):
    """Liveness/readiness probe.

    Unauthenticated callers get only the coarse status — enough for a load
    balancer, without publishing which recon tooling is installed, its versions
    or per-tool failure detail. Full detail requires an administrator.
    """
    from django.db import connection

    from apps.core.permissions import role_of
    from services.tool_adapters.adapters import tool_health

    db_ok = True
    try:
        with connection.cursor() as c:
            c.execute("SELECT 1")
    except Exception:
        db_ok = False

    is_admin = request.user.is_authenticated and role_of(request.user) == "ADMIN"
    payload = {
        "status": "ok" if db_ok else "degraded",
        "database": "ok" if db_ok else "error",
        "tools": {"ok": 0, "total": 0},
    }
    if is_admin:
        tools = tool_health()
        ok_tools = sum(1 for t in tools if t["status"] == "OK")
        payload["tools"] = {"ok": ok_tools, "total": len(tools), "detail": tools}
        payload["status"] = "ok" if db_ok and ok_tools == len(tools) else "degraded"

    if request.headers.get("Accept", "").startswith("application/json"):
        return JsonResponse(payload)
    return render(request, "core/health.html", payload)


@login_required
def global_search(request):
    from django.utils.module_loading import import_string

    from apps.core.authorization import scope_queryset_for_user

    q = request.GET.get("q", "").strip()
    results = []
    if q:
        user = request.user
        for label, module_path, model_name, field, target_lookup in SEARCH_SOURCES:
            model = import_string(f"{module_path}.{model_name}")
            qs = scope_queryset_for_user(user, model.objects.all(), target_lookup=target_lookup)
            hits = qs.filter(**{f"{field}__icontains": q})[:SEARCH_RESULT_LIMIT]
            for obj in hits:
                results.append(
                    {
                        "type": label,
                        "value": str(getattr(obj, field, obj))[:150],
                        "id": obj.pk,
                    }
                )

    if request.headers.get("Accept", "").startswith("application/json"):
        return JsonResponse({"q": q, "results": results})
    return render(request, "core/search.html", {"q": q, "results": results})
