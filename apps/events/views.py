"""Event list / "What's New" views, secured for enforced membership (P0-005).

Both views previously built an **unscoped** ``Event.objects...`` chain and
applied ``?target=<id>`` straight into ``filter(target_id=...)``. That let any
authenticated viewer pass another tenant's target id and read their change
feed, and it rendered ``Target.objects.all()`` as the picker — disclosing the
whole target inventory.

Now:
* the base queryset is restricted to the caller's authorized targets
  (:func:`apps.core.authorization.scope_queryset_for_user`);
* an explicit ``?target=`` / ``<target_id>`` is authorized with
  :func:`apps.core.authorization.get_authorized_target` (403/404 on failure)
  rather than silently ignored;
* the target picker lists :func:`authorized_targets`.
"""

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count
from django.shortcuts import render

from apps.core.authorization import (
    CAP_READ,
    authorized_targets,
    get_authorized_target,
    scope_queryset_for_user,
)
from apps.events.models import Event

PAGE_SIZE = 30
SUMMARY_LIMIT = 20


def _since_filter(qs, since):
    from datetime import timedelta

    from django.utils import timezone

    now = timezone.now()
    mapping = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "today": timedelta(hours=24),
    }
    if since in mapping:
        return qs.filter(created_at__gte=now - mapping[since])
    return qs


def _base_queryset(request):
    """Events the viewer is allowed to see, newest first."""
    return scope_queryset_for_user(request.user, Event.objects.select_related("target")).order_by(
        "-created_at"
    )


def _resolve_target(request, target_id):
    """Authorize an explicit target selection.

    Returns ``None`` when no target was requested, the Target when authorized,
    and raises 403/404 when the id is not permitted. An unauthorized id must
    never degrade into "no filter", which would widen the result set.
    """
    if not target_id:
        return None
    return get_authorized_target(request.user, target_id, capability=CAP_READ)


@login_required
def event_list(request):
    etype = request.GET.get("type", "")
    sev = request.GET.get("severity", "")
    target_id = request.GET.get("target", "")
    target = _resolve_target(request, target_id)

    qs = _base_queryset(request)
    if target is not None:
        qs = qs.filter(target=target)
    if etype:
        qs = qs.filter(event_type=etype)
    if sev:
        qs = qs.filter(severity=sev)

    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get("page", 1))
    return render(
        request,
        "events/list.html",
        {
            "page": page,
            "etype": etype,
            "severity": sev,
            "target_id": str(target.pk) if target is not None else "",
            "target": target,
            "targets": authorized_targets(request.user),
            "event_types": sorted({e for e, _ in Event.EVENT_TYPES}),
        },
    )


@login_required
def changes(request, target_id=None):
    """Per-target or authorized-portfolio What's New with time-range filters."""
    target_id = target_id or request.GET.get("target", "")
    target = _resolve_target(request, target_id)

    qs = _base_queryset(request)
    if target is not None:
        qs = qs.filter(target=target)

    since = request.GET.get("since", "24h")
    if since == "since_baseline" and target is not None:
        if target.baseline_completed_at:
            qs = qs.filter(created_at__gte=target.baseline_completed_at)
    else:
        qs = _since_filter(qs, since)

    etype = request.GET.get("type", "")
    if etype:
        qs = qs.filter(event_type=etype)

    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get("page", 1))
    summary = list(qs.values("event_type").annotate(n=Count("id")).order_by("-n")[:SUMMARY_LIMIT])

    return render(
        request,
        "events/changes.html",
        {
            "page": page,
            "since": since,
            "etype": etype,
            "target_id": str(target.pk) if target is not None else "",
            "target": target,
            "targets": authorized_targets(request.user),
            "summary": summary,
            "event_types": sorted({e for e, _ in Event.EVENT_TYPES}),
        },
    )
