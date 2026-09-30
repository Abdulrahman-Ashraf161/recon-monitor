import logging

from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render

from apps.core.permissions import audit, require_operator, require_viewer

from .models import Baseline, CVESyncState, ExportJob

logger = logging.getLogger(__name__)


def _safe_export_path(target, file_path):
    """Resolve a stored export path, or ``None`` if it escapes the export root.

    P1-015: export files are named after target-owned data, so a stored path
    must never be trusted blindly. The resolved real path must stay inside the
    target's export directory -- otherwise a traversal (``../``), an absolute
    path, or a symlink planted by another process would turn a download into
    arbitrary file disclosure.
    """
    import os

    from .exports import export_dir

    try:
        root = os.path.realpath(export_dir(target))
        candidate = os.path.realpath(file_path)
    except (TypeError, ValueError, OSError):
        return None
    if os.path.commonpath([root, candidate]) != root:
        logger.warning(
            "export path outside export root refused",
            extra={
                "operation": "export_path_check",
                "status": "DENIED",
                "target_id": getattr(target, "pk", None),
            },
        )
        return None
    return candidate


@login_required
def monitoring_index(request):
    return render(
        request,
        "monitoring/index.html",
        {
            "baselines": Baseline.objects.select_related("target").all(),
            "cve_state": CVESyncState.objects.all(),
        },
    )


@login_required
def workers(request):
    """Worker/queue visibility: inspect active workers when possible (eager-aware)."""
    from django.conf import settings as djsettings

    info = {
        "eager": getattr(djsettings, "CELERY_TASK_ALWAYS_EAGER", True),
        "broker": getattr(djsettings, "CELERY_BROKER_URL", ""),
        "queues": ["recon", "js_analysis", "cve", "notifications"],
        "routes": getattr(djsettings, "CELERY_TASK_ROUTES", {}),
        "beat": getattr(djsettings, "CELERY_BEAT_SCHEDULE", {}),
        "active": [],
        "registered": [],
        "error": "",
    }
    if not info["eager"]:
        try:
            from config.celery import app as celery_app

            insp = celery_app.control.inspect(timeout=5)
            info["active"] = insp.active() or {}
            info["registered"] = sorted((insp.registered() or {}).get("celery@worker", []) or [])
        except Exception as e:
            info["error"] = str(e)[:300]
    else:
        info["error"] = (
            "Eager mode: tasks execute in-process (no separate workers). Set CELERY_TASK_ALWAYS_EAGER=False with Redis for real workers."
        )
    return render(request, "monitoring/workers.html", info)


@require_viewer
def export_index(request, target_id):
    # P1-015: authorization is per *target*, not per role. A viewer who is not a
    # member of this target must not even see its export list.
    from apps.core.authorization import get_authorized_target

    t = get_authorized_target(request.user, target_id, capability="read")
    jobs = t.exports.order_by("-created_at")[:30]
    return render(
        request,
        "monitoring/exports.html",
        {"target": t, "jobs": jobs, "types": ExportJob.EXPORT_TYPES},
    )


@require_operator
def export_create(request, target_id):

    # P1-015: the capability (operate) is checked against *this* target.
    from apps.core.authorization import get_authorized_target

    t = get_authorized_target(request.user, target_id, capability="operate")
    if request.method == "POST":
        etype = request.POST.get("export_type", "subdomains")
        fmt = request.POST.get("format", "txt")
        valid_types = {v for v, _ in ExportJob.EXPORT_TYPES}
        if etype not in valid_types:
            # Reject an unknown type up front instead of queueing a job that can
            # only ever fail.
            raise Http404("unknown export type")
        if etype == "snapshot":
            fmt = "zip"
        if fmt not in ("txt", "json", "csv", "zip"):
            fmt = "txt"
        filters = {}
        if request.POST.get("active_only"):
            filters["active_only"] = True
        if request.POST.get("since"):
            filters["since"] = request.POST.get("since")
        job = ExportJob.objects.create(
            target=t, export_type=etype, format=fmt, filters=filters, created_by=request.user
        )
        audit(request, "export.created", job, new=f"{etype}.{fmt}")
        from apps.monitoring.tasks import generate_export

        generate_export.delay(job.id)
        return redirect("export-index", target_id=t.id)
    return redirect("export-index", target_id=t.id)


@require_viewer
def export_history(request):
    # P1-015: history is scoped to the targets this user may read -- a global
    # list of every export leaked the existence and type of other targets' work.
    from apps.core.authorization import scope_queryset_for_user

    jobs = scope_queryset_for_user(
        request.user, ExportJob.all_objects.select_related("target")
    ).order_by("-created_at")[:50]
    return render(request, "monitoring/export_history.html", {"jobs": jobs})


@require_viewer
def export_download(request, pk):
    import os

    from apps.core.authorization import user_can_access_target

    # P1-015: a guessed ExportJob pk must not bypass authorization. The job is
    # fetched unscoped, then the *target* capability is enforced explicitly --
    # relying on a request-scoped manager here would be a security boundary
    # implemented by ambient session state.
    job = get_object_or_404(ExportJob.all_objects.select_related("target"), pk=pk)
    if not user_can_access_target(request.user, job.target, capability="read"):
        from django.core.exceptions import PermissionDenied

        logger.warning(
            "export download denied",
            extra={
                "operation": "export_download",
                "status": "DENIED",
                "user_id": request.user.pk,
                "target_id": job.target_id,
                "export_job_id": job.pk,
            },
        )
        raise PermissionDenied("You do not have access to this target.")
    if job.status != ExportJob.STATUS_COMPLETED or not job.file_path:
        raise Http404("export not ready")
    # P1-015: the stored path must still resolve inside the export root, so a
    # tampered/legacy row cannot be turned into arbitrary file disclosure.
    safe = _safe_export_path(job.target, job.file_path)
    if safe is None or not os.path.exists(safe):
        raise Http404("export not ready")
    return FileResponse(open(safe, "rb"), as_attachment=True)
