import logging

from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.authorization import (
    require_capability,
    scope_queryset_for_user,
)
from apps.core.permissions import audit, require_operator, require_viewer

from .models import JobLog, ScanJob

logger = logging.getLogger(__name__)


def _authorized_job(request, pk, capability="read"):
    """Fetch a ScanJob the caller is authorized for, or 403/404.

    P2-004: role checks alone are not authorization. ``get_object_or_404`` on
    the unscoped manager served *any* job to any viewer, exposing another
    target's hosts, tool commands and logs by guessing an id.
    """
    from django.core.exceptions import PermissionDenied

    job = get_object_or_404(ScanJob.all_objects.select_related("target"), pk=pk)
    if job.target_id is None:
        # A target-less system job is installation-wide; a global admin may
        # inspect it, nobody else needs to.
        from apps.core.authorization import global_admin_override

        if not global_admin_override(request.user):
            raise PermissionDenied("You do not have access to this job.")
        return job
    try:
        require_capability(request.user, job.target, capability)
    except PermissionDenied:
        logger.warning(
            "job access denied",
            extra={
                "operation": "job_access",
                "status": "DENIED",
                "user_id": getattr(request.user, "pk", None),
                "job_id": job.pk,
                "target_id": job.target_id,
                "capability": capability,
            },
        )
        raise
    return job


@require_viewer
def job_list(request):
    # P2-004: the job list is scoped to the targets this user may read.
    qs = scope_queryset_for_user(
        request.user, ScanJob.all_objects.select_related("target")
    ).order_by("-created_at")
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status=status)
    jtype = request.GET.get("type", "")
    if jtype:
        qs = qs.filter(job_type=jtype)
    page = Paginator(qs, 25).get_page(request.GET.get("page", 1))
    return render(request, "jobs/list.html", {"page": page, "status": status, "jtype": jtype})


@require_viewer
def job_detail(request, pk):
    job = _authorized_job(request, pk, capability="read")
    logs = job.logs.order_by("created_at")[:500]
    return render(request, "jobs/detail.html", {"job": job, "logs": logs})


@require_operator
@require_POST
def job_cancel(request, pk):
    job = _authorized_job(request, pk, capability="operate")
    job.status = ScanJob.STATUS_CANCELLED
    job.save(update_fields=["status"])
    audit(request, "job.cancelled", job)
    return redirect("job-detail", pk=pk)


@require_operator
@require_POST
def job_retry(request, pk):
    from . import tasks as jt

    job = _authorized_job(request, pk, capability="operate")
    audit(request, "job.retried", job)
    mapping = {
        "subdomain_enum": jt.discover_subdomains,
        "dns": jt.resolve_dns,
        "ports": jt.scan_ports,
        "http": jt.probe_http,
        "urls": jt.discover_urls,
        "nuclei": jt.run_nuclei,
        "reconcile": jt.reconcile_target,
    }
    task = mapping.get(job.job_type)
    if task:
        task.delay(job.target_id)
    return redirect("job-list")


@require_viewer
def log_list(request):
    # P2-004: logs are target data too (tool commands, hosts, errors).
    qs = scope_queryset_for_user(
        request.user,
        JobLog.objects.select_related("job", "job__target"),
        target_lookup="job__target_id",
    ).order_by("-created_at")
    level = request.GET.get("level", "")
    if level:
        qs = qs.filter(level=level)
    tool = request.GET.get("tool", "")
    if tool:
        qs = qs.filter(tool=tool)
    page = Paginator(qs, 50).get_page(request.GET.get("page", 1))
    return render(request, "jobs/logs.html", {"page": page, "level": level, "tool": tool})
