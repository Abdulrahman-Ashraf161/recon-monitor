"""Target-aware dashboard (TASK-040): ?target=<id> scopes everything; otherwise global overview."""
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import render

from apps.assets.models import (CVE, HTTPService, IPAddress, JavaScriptAsset, Port,
                                SecurityFinding, Subdomain)
from apps.core.target_scoping import TargetAssetService, TargetEventService
from apps.events.models import Event
from apps.jobs.models import ScanJob
from apps.targets.models import Target


@login_required
def dashboard(request):
    target_id = request.GET.get("target", "") or request.session.get("active_target_id", "")
    target = None
    if target_id:
        try:
            target = Target.objects.get(pk=int(target_id))
            request.session["active_target_id"] = target.pk
        except Exception:
            target = None
    if target is not None:
        counts = TargetAssetService.counts(target)
        events = TargetEventService.recent(target, 30)
        jobs = ScanJob.objects.filter(target=target).select_related("target").order_by("-created_at")[:10]
        findings_by_sev = list(SecurityFinding.objects.filter(target=target).values("severity").annotate(n=Count("id")).order_by("severity"))
        job_counts = {s: ScanJob.objects.filter(target=target, status=s).count() for s, _ in ScanJob.STATUS_CHOICES}
        targets = [target]
    else:
        events = Event.objects.select_related("target").order_by("-created_at")[:30]
        jobs = ScanJob.objects.select_related("target").order_by("-created_at")[:10]
        counts = {
            "targets": Target.objects.count(),
            "subdomains": Subdomain.objects.filter(is_active=True).count(),
            "ips": IPAddress.objects.filter(is_active=True).count(),
            "ports": Port.objects.filter(state="open").count(),
            "http": HTTPService.objects.count(),
            "js": JavaScriptAsset.objects.count(),
            "cves": CVE.objects.exclude(status="not_affected").count(),
            "findings": SecurityFinding.objects.exclude(status="RESOLVED").exclude(status="FALSE_POSITIVE").count(),
        }
        findings_by_sev = list(SecurityFinding.objects.values("severity").annotate(n=Count("id")).order_by("severity"))
        job_counts = {s: ScanJob.objects.filter(status=s).count() for s, _ in ScanJob.STATUS_CHOICES}
        targets = list(Target.objects.all()[:20])
    ctx = {
        "counts": counts, "events": events, "jobs": jobs, "targets": targets,
        "active_target": target, "target_id": str(getattr(target, "pk", "") or ""),
        "findings_by_sev": findings_by_sev, "job_counts": job_counts,
    }
    return render(request, "dashboard/index.html", ctx)
