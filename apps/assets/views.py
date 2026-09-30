"""Asset inventory list/detail views with search, filters, pagination.

Target scoping (Tasks 7/20/22):
- List views share scoped_list_view(): validated ?target= scoping (Task 22),
  identical query-param names, paginated results. Global (unscoped) lists are
  cross-target BY DESIGN while SINGLE_TENANT_ALL_TARGETS=True (single-tenant
  install: every authenticated viewer may see every target).
- Detail views enforce the caller's target context server-side (Task 7):
  explicit ?target= OR the picker's session target; mismatch -> 403.
"""

from django.conf import settings as djsettings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, render

from apps.core.permissions import require_viewer

from .models import (
    CVE,
    APIEndpoint,
    HTTPService,
    IPAddress,
    JavaScriptAsset,
    Port,
    SecurityFinding,
    Subdomain,
    Technology,
    URLAsset,
)


def scoped_queryset(request, qs, target_field="target"):
    """Validate ``?target=`` **and** restrict to targets the caller may read.

    P0-008 (P2-009): with no ``?target=`` the previous implementation returned
    the queryset unchanged, so the "All targets (overview)" page listed every
    asset in the installation to any authenticated user — the target *picker*
    was correctly scoped, but the table underneath it was not. An unpinned
    list is now restricted to the caller's authorized targets, and an explicit
    ``?target=`` is validated against the same authorization, so an unowned id
    is refused (empty + notice) rather than silently answered.

    Returns (queryset, target_id, notice). Invalid or nonexistent ids yield
    qs.none() + a visible notice — never a 500, never silent wrong data.
    """
    from apps.core.authorization import (
        CAP_READ,
        authorized_target_ids,
        get_authorized_target,
        global_admin_override,
    )

    target_id = request.GET.get("target", "")
    if not target_id:
        # No pinned target: the overview may only span targets this user may read.
        if global_admin_override(request.user):
            return qs, "", ""
        allowed = authorized_target_ids(request.user)
        if not allowed:
            return qs.none(), "", ""
        return qs.filter(**{f"{target_field}_id__in": allowed}), "", ""
    if not target_id.isdigit():
        messages.warning(request, "Invalid target selected — showing nothing.")
        return qs.none(), target_id, "Invalid target — showing nothing."
    try:
        target = get_authorized_target(request.user, int(target_id), capability=CAP_READ)
    except Http404:
        messages.warning(request, "Target not found — showing nothing.")
        return qs.none(), target_id, "Target not found — showing nothing."
    except PermissionDenied:
        messages.warning(request, "You do not have access to that target.")
        return qs.none(), target_id, "Not authorized for that target."
    return qs.filter(**{f"{target_field}_id": target.pk}), str(target.pk), ""


def _filtered(request, qs, target_field="target"):
    """Backwards-compatible wrapper (Task 20): same return shape as before."""
    qs, target_id, _notice = scoped_queryset(request, qs, target_field)
    return qs, target_id


def _paginate(request, qs, per_page=25):
    paginator = Paginator(qs, per_page)
    return paginator.get_page(request.GET.get("page", 1))


def _ctx_targets(request, target_id):
    """Target-picker context, limited to the targets this user may switch to.

    P0-002: offering every target in the picker and then denying the request
    leaks the full target inventory (and their names) to non-members.
    """
    from apps.core.authorization import authorized_targets

    return {"targets": authorized_targets(request.user), "target_id": target_id}


def _deny_on_context_mismatch(request, obj):
    """Task 7 + P0-002/P0-003: authorize, then enforce target context.

    Two independent checks, both required:

    1. **Membership** (P0-002) — the caller must be authorized for the target
       that owns the object. Without this, naming the right ``?target=`` was
       enough to read any target's data, which is a straight IDOR.
    2. **Context** (Task 7) — the caller's active context must not point at a
       different target, which closes "IDOR by omission" on detail URLs.

    Context never substitutes for membership, and membership never substitutes
    for context.
    """
    from apps.core.authorization import CAP_READ, require_capability

    target = getattr(obj, "target", None)
    if target is not None:
        require_capability(request.user, target, capability=CAP_READ)

    ctx = (
        request.GET.get("target", "")
        or request.session.get("active_target_id", "")
        or request.session.get("current_target_id", "")
    )
    if ctx and str(getattr(obj, "target_id", "")) != str(ctx):
        raise PermissionDenied(
            "Cross-target access denied: this object belongs to another target. "
            "Switch targets with the target picker and retry."
        )
    if not ctx and not getattr(djsettings, "SINGLE_TENANT_ALL_TARGETS", True):
        raise PermissionDenied("Target context required.")


def scoped_list_view(
    request,
    model,
    template,
    order_by=None,
    search_lookup=None,
    exact_filters=None,
    extra_context=None,
):
    """Task 20: one shared list implementation for all asset types.

    - model: asset model (must have target FK for scoping).
    - order_by: field name(s) for deterministic ordering.
    - search_lookup: ORM lookup for the ?q= box (e.g. "hostname__icontains").
    - exact_filters: {query_param: ORM lookup or None}; None preserves params
      that are accepted-but-unfiltered (e.g. subdomain ?status= quirk).
    Query-param names and context keys are identical to the pre-refactor views.
    """
    qs = model.objects.select_related("target").all()
    if order_by:
        qs = (
            qs.order_by(*order_by) if isinstance(order_by, (list, tuple)) else qs.order_by(order_by)
        )
    qs, target_id, notice = scoped_queryset(request, qs)
    applied = {}
    for param, lookup in (exact_filters or {}).items():
        v = request.GET.get(param, "")
        applied[param] = v
        if v and lookup:
            qs = qs.filter(**{lookup: v})
    q = ""
    if search_lookup:
        q = request.GET.get("q", "")
        if q:
            qs = qs.filter(**{search_lookup: q})
    page = _paginate(request, qs)
    ctx = {"page": page, "q": q, **_ctx_targets(request, target_id), **applied}
    if notice:
        ctx["target_notice"] = notice
    if extra_context:
        ctx.update(extra_context() if callable(extra_context) else extra_context)
    return render(request, template, ctx)


@require_viewer
def asset_index(request):
    from .models import Asset

    qs = Asset.objects.select_related("target").order_by("-last_seen")
    atype = request.GET.get("type", "")
    if atype:
        qs = qs.filter(asset_type=atype)
    qs, target_id = _filtered(request, qs)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(value__icontains=q)
    page = _paginate(request, qs)
    ctx = {"page": page, "q": q, "atype": atype, **_ctx_targets(request, target_id)}
    return render(request, "assets/index.html", ctx)


@require_viewer
def asset_detail(request, pk):
    from .models import Asset

    a = get_object_or_404(Asset, pk=pk)
    _deny_on_context_mismatch(request, a)
    return render(request, "assets/detail.html", {"asset": a})


@require_viewer
def subdomain_list(request):
    return scoped_list_view(
        request,
        Subdomain,
        "assets/subdomains.html",
        order_by="hostname",
        search_lookup="hostname__icontains",
        exact_filters={"status": None, "source": "sources__icontains"},
    )


@require_viewer
def port_list(request):
    return scoped_list_view(
        request,
        Port,
        "assets/ports.html",
        order_by=("ip", "port"),
        search_lookup="ip__icontains",
        exact_filters={"state": "state"},
    )


@require_viewer
def http_list(request):
    return scoped_list_view(
        request,
        HTTPService,
        "assets/http.html",
        order_by="-last_seen",
        search_lookup="url__icontains",
        exact_filters={"status": "status_code"},
    )


@require_viewer
def url_list(request):
    return scoped_list_view(
        request,
        URLAsset,
        "assets/urls.html",
        order_by="-last_seen",
        search_lookup="canonical_url__icontains",
        exact_filters={"source": "source"},
    )


@require_viewer
def api_list(request):
    return scoped_list_view(
        request,
        APIEndpoint,
        "assets/apis.html",
        order_by="-last_seen",
        search_lookup="url__icontains",
    )


@require_viewer
def js_list(request):
    from apps.jobs.models import JSAnalysisJob

    qs = JavaScriptAsset.objects.select_related("target").order_by("-last_seen")
    qs, target_id, notice = scoped_queryset(request, qs)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(js_url__icontains=q)
    page = _paginate(request, qs)
    js_ids = [j.id for j in page]
    latest = {}
    for aj in JSAnalysisJob.objects.filter(js_id__in=js_ids).order_by("-created_at"):
        latest.setdefault(aj.js_id, aj)
    for j in page:
        j.latest_job = latest.get(j.id)
    # Task 8: totals honor the same target scope as the list itself.
    # P3-001: an unpinned page must not fall back to an installation-wide count
    # -- the totals are restricted to the caller's authorized targets, exactly
    # like the rows above.
    if target_id and str(target_id).isdigit():
        js_scope = JavaScriptAsset.objects.filter(target_id=int(target_id))
        job_scope = JSAnalysisJob.objects.filter(js__target_id=int(target_id))
    else:
        from apps.core.authorization import (
            authorized_target_ids,
            global_admin_override,
        )

        if global_admin_override(request.user):
            allowed = None  # global administrator: portfolio-wide totals
        else:
            allowed = authorized_target_ids(request.user)
            if not allowed:
                js_scope = JavaScriptAsset.objects.none()
                job_scope = JSAnalysisJob.objects.none()
        if allowed is not None:
            js_scope = JavaScriptAsset.objects.filter(target_id__in=allowed)
            job_scope = JSAnalysisJob.objects.filter(js__target_id__in=allowed)
        else:
            js_scope = JavaScriptAsset.objects.all()
            job_scope = JSAnalysisJob.objects.all()
    totals = {
        "total": js_scope.count(),
        "queued": job_scope.filter(status="QUEUED").count(),
        "running": job_scope.filter(status="RUNNING").count(),
        "completed": job_scope.filter(status="COMPLETED").count(),
        "failed": job_scope.filter(status="FAILED").count(),
    }
    ctx = {
        "page": page,
        **_ctx_targets(request, target_id),
        "q": q,
        "latest": latest,
        "totals": totals,
    }
    if notice:
        ctx["target_notice"] = notice
    return render(request, "assets/js.html", ctx)


@require_viewer
def js_scan_detail(request, pk):

    js = get_object_or_404(JavaScriptAsset, pk=pk)
    _deny_on_context_mismatch(request, js)
    jobs = js.analysis_jobs.order_by("-created_at")[:10]
    job_id = request.GET.get("job", "")
    job = None
    if job_id:
        job = js.analysis_jobs.filter(pk=job_id).first()
    if job is None:
        job = jobs[0] if jobs else None
    return render(
        request,
        "assets/js_scan.html",
        {"js": js, "jobs": jobs, "job": job, "logs": job.logs.all()[:300] if job else []},
    )


@require_viewer
def js_diff(request, pk):
    js = get_object_or_404(JavaScriptAsset, pk=pk)
    _deny_on_context_mismatch(request, js)
    versions = list(js.versions.all()[:10])
    diff_lines = []
    if len(versions) >= 2:
        import difflib

        old = versions[1].content.splitlines()
        new = versions[0].content.splitlines()
        diff_lines = list(difflib.unified_diff(old, new, lineterm="", n=3))[:2000]
    return render(
        request, "assets/js_diff.html", {"js": js, "versions": versions, "diff": diff_lines}
    )


@require_viewer
def tech_list(request):
    return scoped_list_view(
        request,
        Technology,
        "assets/tech.html",
        order_by="product",
        search_lookup="product__icontains",
    )


@require_viewer
def cve_list(request):
    return scoped_list_view(
        request,
        CVE,
        "assets/cves.html",
        order_by="-first_seen",
        search_lookup="cve_id__icontains",
        exact_filters={"status": "status"},
    )


@require_viewer
def finding_list(request):
    return scoped_list_view(
        request,
        SecurityFinding,
        "assets/findings.html",
        order_by="-first_seen",
        exact_filters={"severity": "severity", "status": "status"},
    )


@require_viewer
def ip_list(request):
    return scoped_list_view(request, IPAddress, "assets/ips.html", order_by="ip")
