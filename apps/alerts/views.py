from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render

from apps.events.models import Alert


@login_required
def alerts_index(request):
    from apps.core.authorization import scope_queryset_for_user

    # P0-003/P0-005/P2-004: the default manager applies NO filter of its own --
    # membership scoping only happens when `.for_user()` is called explicitly --
    # so this queryset was an unfiltered cross-tenant read. An Alert carries the
    # event and (through it) the target domain and the asset value, so this page
    # disclosed another tenant's target names and asset inventory to any
    # logged-in user. Scoped with the same helper the API and export views use.
    qs = scope_queryset_for_user(
        request.user, Alert.objects.select_related("event", "event__target")
    ).order_by("-created_at")
    status = request.GET.get("status", "")
    if status:
        qs = qs.filter(status=status)
    sev = request.GET.get("severity", "")
    if sev:
        qs = qs.filter(event__severity=sev)
    page = Paginator(qs, 30).get_page(request.GET.get("page", 1))
    return render(
        request,
        "alerts/index.html",
        {
            "page": page,
            "status": status,
            "severity": sev,
            "statuses": [s for s, _ in Alert.STATUS_CHOICES],
        },
    )
