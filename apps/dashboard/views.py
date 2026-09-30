"""Target-aware dashboard (TASK-040), secured for enforced membership (P0-004).

``?target=<id>`` scopes everything; without it the dashboard shows an *overview
of the targets the user is a member of* — never a global inventory.

The previous implementation had two defects that this module removes:

1. ``Target.objects.get(pk=int(target_id))`` authorized nothing, so any
   authenticated user could pass another tenant's id in the query string and
   read that target's events, jobs and asset counts.
2. A denied/unknown target silently fell through to the "global" branch, whose
   counts and event/job feeds were **unscoped** — so the failure mode of the
   per-target view was a full cross-tenant data leak rather than a 403.

Every user-facing query in this file now resolves through
:mod:`apps.core.authorization`.
"""

from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import render

from apps.assets.models import (
    CVE,
    HTTPService,
    IPAddress,
    JavaScriptAsset,
    Port,
    SecurityFinding,
    Subdomain,
)
from apps.core.authorization import (
    CAP_READ,
    authorized_target_ids,
    authorized_targets,
    get_authorized_target,
    scope_queryset_for_user,
)
from apps.core.target_scoping import TargetAssetService, TargetEventService
from apps.events.models import Event
from apps.jobs.models import ScanJob

# Dashboard feeds are display windows, not processing limits (P3-002): these are
# UI/pagination bounds on a single rendered page.
FEED_LIMIT = 30
JOB_FEED_LIMIT = 10
TARGET_PICKER_LIMIT = 20


@login_required
def dashboard(request):
    target_id = request.GET.get("target", "") or request.session.get("active_target_id", "")

    target = None
    if target_id:
        # Raises 404 for unknown ids and 403 for unauthorized ones. It must
        # NOT fall through to the overview: that would turn "you may not see
        # target B" into "here is every target".
        target = get_authorized_target(request.user, target_id, capability=CAP_READ)
        request.session["active_target_id"] = target.pk

    if target is not None:
        return render(request, "dashboard/index.html", _target_context(request, target))

    return render(request, "dashboard/index.html", _overview_context(request))


def _target_context(request, target):
    """Counts + feeds for exactly one authorized target."""
    events = TargetEventService.recent(target, FEED_LIMIT)
    jobs = (
        ScanJob.objects.filter(target=target)
        .select_related("target", "scan_run")
        .order_by("-created_at")[:JOB_FEED_LIMIT]
    )
    findings_by_sev = list(
        SecurityFinding.objects.filter(target=target)
        .values("severity")
        .annotate(n=Count("id"))
        .order_by("severity")
    )
    job_counts = {
        s: ScanJob.objects.filter(target=target, status=s).count()
        for s, _ in ScanJob.STATUS_CHOICES
    }
    return {
        "counts": TargetAssetService.counts(target),
        "events": events,
        "jobs": jobs,
        "targets": [target],
        "active_target": target,
        "target_id": str(target.pk),
        "findings_by_sev": findings_by_sev,
        "job_counts": job_counts,
        "is_overview": False,
    }


def _overview_context(request):
    """Portfolio view across *authorized targets only* (P0-004).

    Every queryset below is filtered to the caller's target ids, so a user with
    membership in one target sees counts for that target and nothing else.
    """
    user = request.user
    ids = authorized_target_ids(user)

    def scoped(qs):
        return qs.filter(target_id__in=ids)

    events = scope_queryset_for_user(user, Event.objects.select_related("target")).order_by(
        "-created_at"
    )[:FEED_LIMIT]
    jobs = scope_queryset_for_user(
        user, ScanJob.objects.select_related("target", "scan_run")
    ).order_by("-created_at")[:JOB_FEED_LIMIT]
    counts = {
        "targets": len(ids),
        "subdomains": scoped(Subdomain.objects.filter(is_active=True)).count(),
        "ips": scoped(IPAddress.objects.filter(is_active=True)).count(),
        "ports": scoped(Port.objects.filter(state="open")).count(),
        "http": scoped(HTTPService.objects).count(),
        "js": scoped(JavaScriptAsset.objects).count(),
        "cves": scoped(CVE.objects.exclude(status="not_affected")).count(),
        "findings": scoped(
            SecurityFinding.objects.exclude(status="RESOLVED").exclude(status="FALSE_POSITIVE")
        ).count(),
    }
    findings_by_sev = list(
        scoped(SecurityFinding.objects.values("severity"))
        .annotate(n=Count("id"))
        .order_by("severity")
    )
    job_counts = {
        s: scope_queryset_for_user(user, ScanJob.objects.filter(status=s)).count()
        for s, _ in ScanJob.STATUS_CHOICES
    }
    return {
        "counts": counts,
        "events": events,
        "jobs": jobs,
        "targets": list(authorized_targets(user)[:TARGET_PICKER_LIMIT]),
        "active_target": None,
        "target_id": "",
        "findings_by_sev": findings_by_sev,
        "job_counts": job_counts,
        "is_overview": True,
    }
