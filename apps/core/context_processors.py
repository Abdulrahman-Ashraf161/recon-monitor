"""Target context processor (TASK-039): persistent target selector.

Provides `all_targets` + `active_target` to every template.
Active target resolved from ?target=, session, or single-target shortcut.
"""
from apps.targets.models import Target


def target_context(request):
    targets = Target.objects.all().order_by("root_domain")[:200]
    active = None
    tid = request.GET.get("target") or request.session.get("active_target_id")
    if tid:
        try:
            active = Target.objects.get(pk=int(tid))
            request.session["active_target_id"] = active.pk
        except Exception:
            active = None
    return {"all_targets": targets, "active_target": active}
