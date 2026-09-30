from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from apps.core.permissions import audit, require_admin, require_operator, require_viewer

from .forms import TargetForm
from .models import Target


@require_viewer
def target_list(request):
    from apps.core.authorization import authorized_targets

    # P0-003: the default manager is NOT automatically membership-scoped --
    # `TargetScopedManager.get_queryset()` only applies a filter when `.for_user()`
    # is called explicitly, so `Target.objects.all()` here would expose every
    # target in the installation to any logged-in viewer. `authorized_targets()`
    # is the same helper the API viewset uses, so the HTML and JSON surfaces
    # cannot drift apart again.
    qs = authorized_targets(request.user).order_by("root_domain")
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status=status)
    q = request.GET.get("q", "")
    if q:
        qs = qs.filter(root_domain__icontains=q)
    return render(request, "targets/list.html", {"targets": qs, "status": status, "q": q})


@require_viewer
def target_detail(request, pk):
    from datetime import timedelta

    from django.utils import timezone

    from apps.core.authorization import get_authorized_target
    from apps.jobs.models import JSAnalysisJob

    # P3-001: a role check is not authorization. The detail page renders this
    # target's assets, pipeline and scan history, so it is only served to a
    # user who holds a membership row on it.
    t = get_authorized_target(request.user, pk, capability="read")
    # pipeline visibility: latest job per stage + running counts
    pipeline_stages = ["subdomain_enum", "dns", "ports", "http", "urls", "nuclei", "reconcile"]
    pipeline = []
    for stage in pipeline_stages:
        latest = t.jobs.filter(job_type=stage).order_by("-created_at").first()
        running = t.jobs.filter(job_type=stage, status__in=["QUEUED", "RUNNING"]).count()
        pipeline.append(
            {
                "stage": stage,
                "status": latest.status if latest else "IDLE",
                "running": running,
                "updated": latest.created_at if latest else None,
            }
        )
    js_running = JSAnalysisJob.objects.filter(target=t, status__in=["QUEUED", "RUNNING"]).count()
    pipeline.append(
        {
            "stage": "js_analysis",
            "status": f"{js_running} RUNNING" if js_running else "IDLE",
            "running": js_running,
            "updated": None,
        }
    )
    last_change = t.events.order_by("-created_at").first()
    ctx = {
        "target": t,
        "overview": {
            "subdomains": t.subdomains.filter(is_active=True).count(),
            "ips": t.ips.filter(is_active=True).count(),
            "ports": t.ports.filter(state="open").count(),
            "http": t.http_services.count(),
            "urls": t.urls.count(),
            "apis": t.api_endpoints.count(),
            "js": t.js_assets.count(),
            "techs": t.technologies.count(),
            "cves": t.cves.exclude(status="not_affected").count(),
            "findings": t.findings.exclude(status="RESOLVED")
            .exclude(status="FALSE_POSITIVE")
            .count(),
            "running_jobs": t.jobs.filter(status__in=["QUEUED", "RUNNING"]).count(),
            "last_change": last_change.created_at if last_change else None,
        },
        "pipeline": pipeline,
        "new_24h": t.events.filter(created_at__gte=timezone.now() - timedelta(hours=24)).count(),
        "subdomains": t.subdomains.filter(is_active=True).order_by("hostname")[:50],
        "subdomain_count": t.subdomains.filter(is_active=True).count(),
        "ports": t.ports.filter(state="open").order_by("ip", "port")[:50],
        "http": t.http_services.order_by("-last_seen")[:20],
        "urls": t.urls.order_by("-last_seen")[:20],
        "apis": t.api_endpoints.order_by("-last_seen")[:20],
        "js": t.js_assets.order_by("-last_seen")[:20],
        "techs": t.technologies.order_by("product")[:30],
        "cves": t.cves.order_by("-first_seen")[:20],
        "findings": t.findings.order_by("-first_seen")[:20],
        "events": t.events.order_by("-created_at")[:30],
        "jobs": t.jobs.order_by("-created_at")[:20],
        "rules": t.scope_rules.all(),
    }
    return render(request, "targets/detail.html", ctx)


@require_viewer
def target_changes(request, target_id):
    from apps.events.views import changes as changes_view

    return changes_view(request, target_id=target_id)


@require_operator
def target_create(request):
    if request.method == "POST":
        form = TargetForm(request.POST)
        if form.is_valid():
            t = form.save()
            # P0-002: the creator must hold a membership row, otherwise the
            # target is orphaned -- it has no owner, the creator is redirected
            # straight to a page that 403s, and the target never appears in their
            # (membership-scoped) target list. Verified: without this the create
            # flow produced a target with 0 memberships that nobody could read.
            from apps.core.authorization import grant_membership
            from apps.targets.models import TargetMembership

            grant_membership(request.user, t, role=TargetMembership.ROLE_OWNER)
            audit(request, "target.created", t, new=t.root_domain)
            from apps.jobs.tasks import baseline_target

            baseline_target.delay(t.id)
            return redirect("target-detail", pk=t.pk)
    else:
        form = TargetForm()
    return render(request, "targets/form.html", {"form": form, "title": "Add target"})


@require_operator
def target_edit(request, pk):

    from apps.core.authorization import get_authorized_target

    # P3-001: editing a target changes its scope, authorization and schedule;
    # only a member with the manage capability may do it.
    t = get_authorized_target(request.user, pk, capability="manage")
    old = t.status
    if request.method == "POST":
        form = TargetForm(request.POST, instance=t)
        if form.is_valid():
            form.save()
            audit(request, "target.edited", t, old=old, new=t.status)
            return redirect("target-detail", pk=t.pk)
    else:
        form = TargetForm(instance=t)
    return render(request, "targets/form.html", {"form": form, "title": f"Edit {t.root_domain}"})


@require_operator
@require_POST
def target_pause(request, pk):
    """P2-007: pause goes through the lifecycle module, never a raw assignment.

    P0-013: pause is a real kill switch, not a label flip.

    * QUEUED jobs are resumable -> PAUSED (resume re-queues them).
    * RUNNING jobs stay RUNNING: the cooperative kill switch is the only
      authority on their final state. The worker's next `check()` re-reads
      the database, sees `is_scannable()==False`, terminates the tool's
      subprocess group, and finalizes the job as CANCELLED.
    * The live execution root(s) are tripped (cancel_requested_at) so the
      run is not left looking "live" for stall detection or the next
      dispatch; a run with no live job left is finalized now (P1-001).
    """
    from django.core.exceptions import PermissionDenied

    from apps.core.authorization import require_capability

    from .target_lifecycle import InvalidTransition, transition_to

    t = get_object_or_404(Target, pk=pk)
    require_capability(request.user, t, "operate")
    try:
        transition_to(
            t,
            new_status=Target.STATUS_PAUSED,
            reason="paused by operator",
            actor=request.user,
            halt_reason="TARGET_PAUSED",
        )
    except InvalidTransition as e:
        raise PermissionDenied(str(e)) from e
    audit(request, "target.paused", t)
    return redirect("target-detail", pk=pk)


@require_operator
@require_POST
def target_resume(request, pk):
    """P2-007: resume re-queues paused work through the lifecycle module."""
    from django.core.exceptions import PermissionDenied

    from apps.core.authorization import require_capability

    from .target_lifecycle import InvalidTransition, transition_to

    t = get_object_or_404(Target, pk=pk)
    require_capability(request.user, t, "operate")
    try:
        transition_to(
            t, new_status=Target.STATUS_ACTIVE, reason="resumed by operator", actor=request.user
        )
    except InvalidTransition as e:
        raise PermissionDenied(str(e)) from e
    audit(request, "target.resumed", t)
    return redirect("target-detail", pk=pk)


@require_admin
@require_POST
def target_delete(request, pk):
    """P2-005: removal is ARCHIVE by default; hard delete needs a confirmation.

    Archiving is a soft delete: every historical artifact (ScanRuns, ScanJobs,
    ToolExecutions, AssetObservations, events, audit history) survives, and the
    target simply stops being scannable. A hard delete is still possible for
    genuine data-removal requests, but only with an explicit
    ``confirm=PURGE`` token -- and it returns a manifest of exactly what was
    destroyed, which is recorded in the audit log.
    """
    from django.core.exceptions import PermissionDenied

    from apps.core.authorization import require_capability

    from .target_lifecycle import (
        PURGE_CONFIRMATION,
        InvalidTransition,
        purge_target,
        transition_to,
    )

    t = get_object_or_404(Target, pk=pk)
    require_capability(request.user, t, "manage")
    confirm = request.POST.get("confirm", "")
    reason = (request.POST.get("reason") or "").strip()
    try:
        if confirm == PURGE_CONFIRMATION:
            manifest = purge_target(
                t,
                confirmation=confirm,
                reason=reason or "hard delete by administrator",
                actor=request.user,
            )
            audit(
                request,
                "target.purged",
                t,
                old=t.root_domain,
                new=f"destroyed={sum(v for v in manifest.values() if v)} records",
            )
            return redirect("target-list")
        if confirm:
            raise PermissionDenied(
                f"confirmation must be exactly {PURGE_CONFIRMATION!r} to hard delete; "
                "omit it to archive"
            )
        transition_to(
            t,
            new_status=Target.STATUS_ARCHIVED,
            reason=reason or "archived by administrator",
            actor=request.user,
        )
    except InvalidTransition as e:
        raise PermissionDenied(str(e)) from e
    except ValueError as e:
        raise PermissionDenied(str(e)) from e
    audit(request, "target.archived", t, old=t.status, new="ARCHIVED")
    return redirect("target-detail", pk=pk)


@require_operator
@require_POST
def target_scan(request, pk):
    """P2-006: manual scans go through the canonical ScanRun orchestration.

    The view no longer fires loose per-stage tasks: it authorizes the *target*,
    verifies it is scannable, and dispatches ``manual_scan``, which creates one
    execution root that every stage joins, so jobs, tool executions and
    observations all hang off a single traceable run with accurate status.
    """
    from django.core.exceptions import PermissionDenied

    from apps.core.authorization import require_capability

    t = get_object_or_404(Target, pk=pk)
    require_capability(request.user, t, "operate")
    if not t.is_scannable:
        # Refused here rather than queued: a paused/expired/archived target must
        # not start new work (P0-013/P0-014).
        audit(request, "job.refused", t, new=t.blocking_reason() or "not scannable")
        raise PermissionDenied(f"Target is not scannable: {t.blocking_reason() or 'unknown'}")
    audit(
        request,
        "job.started",
        t,
        new="baseline" if t.baseline_status != "BASELINE_COMPLETE" else "scan",
    )
    from apps.jobs import tasks as jt

    async_result = jt.manual_scan.delay(t.id, requested_by=str(request.user.pk))
    return redirect(f"{reverse('target-detail', args=[pk])}?run={async_result.id}")


@require_viewer
def scan_run_detail(request, pk):
    """P2-006: expose the status of an execution root (accurate scan status)."""
    from django.shortcuts import get_object_or_404 as _g

    from apps.core.authorization import get_authorized_target
    from apps.jobs.models import ScanRun

    run = _g(ScanRun.all_objects.select_related("target"), pk=pk)
    get_authorized_target(request.user, run.target_id, capability="read")
    return render(
        request,
        "jobs/run_detail.html",
        {
            "run": run,
            "jobs": run.jobs.order_by("created_at")[:200],
            "tool_executions": run.tool_executions.order_by("-started_at")[:100],
        },
    )
