"""Asset inventory list/detail views with search, filters, pagination (target-scoped)."""
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, render

from apps.core.permissions import require_viewer
from apps.targets.models import Target

from .models import (APIEndpoint, CVE, HTTPService, IPAddress, JavaScriptAsset,
                     JavaScriptVersion, Port, SecurityFinding, Subdomain, Technology,
                     URLAsset)


def _filtered(request, qs, target_field="target"):
    target_id = request.GET.get("target", "")
    if target_id:
        qs = qs.filter(**{f"{target_field}_id": target_id})
    return qs, target_id


def _paginate(request, qs, per_page=25):
    paginator = Paginator(qs, per_page)
    return paginator.get_page(request.GET.get("page", 1))


def _ctx_targets(target_id):
    return {"targets": Target.objects.all(), "target_id": target_id}


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
    ctx = {"page": page, "q": q, "atype": atype, **_ctx_targets(target_id)}
    return render(request, "assets/index.html", ctx)


@require_viewer
def asset_detail(request, pk):
    from .models import Asset

    a = get_object_or_404(Asset, pk=pk)
    _deny_on_context_mismatch(request, a)
    return render(request, "assets/detail.html", {"asset": a})


def _deny_on_context_mismatch(request, obj):
    """TASK-042/078: when caller supplies explicit target context, enforce it server-side."""
    ctx = request.GET.get("target", "")
    if ctx and str(getattr(obj, "target_id", "")) != str(ctx):
        raise PermissionDenied("cross-target access denied")


@require_viewer
def subdomain_list(request):
    qs = Subdomain.objects.select_related("target").order_by("hostname")
    qs, target_id = _filtered(request, qs)
    for f, lookup in (("status", None), ("source", "sources__icontains"), ("q", "hostname__icontains")):
        v = request.GET.get(f, "")
        if v and lookup:
            qs = qs.filter(**{lookup: v})
    page = _paginate(request, qs)
    return render(request, "assets/subdomains.html", {"page": page, **_ctx_targets(target_id),
                                                     "q": request.GET.get("q", "")})


@require_viewer
def port_list(request):
    qs = Port.objects.select_related("target").order_by("ip", "port")
    qs, target_id = _filtered(request, qs)
    state = request.GET.get("state", "")
    if state:
        qs = qs.filter(state=state)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(ip__icontains=q)
    return render(request, "assets/ports.html", {"page": _paginate(request, qs), **_ctx_targets(target_id),
                                                 "state": state, "q": q})


@require_viewer
def http_list(request):
    qs = HTTPService.objects.select_related("target").order_by("-last_seen")
    qs, target_id = _filtered(request, qs)
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status_code=status)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(url__icontains=q)
    return render(request, "assets/http.html", {"page": _paginate(request, qs), **_ctx_targets(target_id),
                                                "status": status, "q": q})


@require_viewer
def url_list(request):
    qs = URLAsset.objects.select_related("target").order_by("-last_seen")
    qs, target_id = _filtered(request, qs)
    source = request.GET.get("source", "")
    if source:
        qs = qs.filter(source=source)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(canonical_url__icontains=q)
    return render(request, "assets/urls.html", {"page": _paginate(request, qs), **_ctx_targets(target_id),
                                                "source": source, "q": q})


@require_viewer
def api_list(request):
    qs = APIEndpoint.objects.select_related("target").order_by("-last_seen")
    qs, target_id = _filtered(request, qs)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(url__icontains=q)
    return render(request, "assets/apis.html", {"page": _paginate(request, qs), **_ctx_targets(target_id), "q": q})


@require_viewer
def js_list(request):
    from apps.jobs.models import JSAnalysisJob

    qs = JavaScriptAsset.objects.select_related("target").order_by("-last_seen")
    qs, target_id = _filtered(request, qs)
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
    totals = {
        "total": JavaScriptAsset.objects.count(),
        "queued": JSAnalysisJob.objects.filter(status="QUEUED").count(),
        "running": JSAnalysisJob.objects.filter(status="RUNNING").count(),
        "completed": JSAnalysisJob.objects.filter(status="COMPLETED").count(),
        "failed": JSAnalysisJob.objects.filter(status="FAILED").count(),
    }
    return render(request, "assets/js.html", {"page": page, **_ctx_targets(target_id), "q": q,
                                              "latest": latest, "totals": totals})


@require_viewer
def js_scan_detail(request, pk):
    from apps.jobs.models import JSAnalysisJob

    js = get_object_or_404(JavaScriptAsset, pk=pk)
    _deny_on_context_mismatch(request, js)
    jobs = js.analysis_jobs.order_by("-created_at")[:10]
    job_id = request.GET.get("job", "")
    job = None
    if job_id:
        job = js.analysis_jobs.filter(pk=job_id).first()
    if job is None:
        job = jobs[0] if jobs else None
    return render(request, "assets/js_scan.html",
                  {"js": js, "jobs": jobs, "job": job,
                   "logs": job.logs.all()[:300] if job else []})


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
    return render(request, "assets/js_diff.html", {"js": js, "versions": versions, "diff": diff_lines})


@require_viewer
def tech_list(request):
    qs = Technology.objects.select_related("target").order_by("product")
    qs, target_id = _filtered(request, qs)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(product__icontains=q)
    return render(request, "assets/tech.html", {"page": _paginate(request, qs), **_ctx_targets(target_id), "q": q})


@require_viewer
def cve_list(request):
    qs = CVE.objects.select_related("target").order_by("-first_seen")
    qs, target_id = _filtered(request, qs)
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status=status)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(cve_id__icontains=q)
    return render(request, "assets/cves.html", {"page": _paginate(request, qs), **_ctx_targets(target_id),
                                                "status": status, "q": q})


@require_viewer
def finding_list(request):
    qs = SecurityFinding.objects.select_related("target").order_by("-first_seen")
    qs, target_id = _filtered(request, qs)
    sev = request.GET.get("severity", "")
    if sev:
        qs = qs.filter(severity=sev)
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status=status)
    return render(request, "assets/findings.html", {"page": _paginate(request, qs), **_ctx_targets(target_id),
                                                    "severity": sev, "status": status})


@require_viewer
def ip_list(request):
    qs = IPAddress.objects.select_related("target").order_by("ip")
    qs, target_id = _filtered(request, qs)
    return render(request, "assets/ips.html", {"page": _paginate(request, qs), **_ctx_targets(target_id)})
