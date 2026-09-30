"""Target context processor (TASK-039): persistent target selector.

Provides `all_targets` + `active_target` to every template.

P3-001: this processor used ``Target.objects.all()[:200]`` and
``Target.objects.get(pk=tid)`` with no authorization, so two leaks escaped
through *every* page that renders the sidebar:

1. the target picker listed the whole installation's target inventory — names
   included — to any authenticated user;
2. ``?target=<someone else's id>`` pinned that target in the session.

The picker now shows only the targets the caller may read, and an unowned
``active_target_id`` is ignored (and cleared) rather than adopted.
"""

from apps.core.authorization import authorized_targets
from apps.targets.models import Target


def target_context(request):
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return {"all_targets": Target.objects.none(), "active_target": None}

    # Picker entries are limited to authorized targets; the [:200] cap is a UI
    # display limit on the dropdown only and never limits data access.
    targets = authorized_targets(user).order_by("root_domain")[:200]

    active = None
    tid = request.GET.get("target") or request.session.get("active_target_id")
    if tid and str(tid).isdigit():
        candidate = authorized_targets(user).filter(pk=int(tid)).first()
        if candidate is not None:
            active = candidate
            request.session["active_target_id"] = active.pk
        else:
            # An id the caller may not read must not stick to the session.
            request.session.pop("active_target_id", None)
    return {"all_targets": targets, "active_target": active}
