from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.shortcuts import redirect, render

from apps.core.permissions import audit, require_admin, require_viewer

from .forms import ScopeRuleForm
from .models import ScopeRule


@require_viewer
def scope_index(request):
    from apps.core.authorization import (
        authorized_targets,
        get_authorized_target,
        scope_queryset_for_user,
    )

    # P0-003/P0-008: both the rule list AND the target picker in the template
    # context must be membership-scoped. The default manager only filters when
    # `.for_user()` is called explicitly, so an unfiltered queryset here leaked
    # every target's domain and every scope rule to any logged-in viewer.
    qs = scope_queryset_for_user(request.user, ScopeRule.objects.select_related("target")).order_by(
        "target__root_domain", "rule_type"
    )
    target_id = request.GET.get("target", "")
    if target_id:
        # A target the user cannot read must not even be accepted as a filter,
        # and must not be echoed back as an existing scope context. Only
        # Http404/PermissionDenied from the lookup are converted; a genuine bug
        # (TypeError, etc.) must still surface rather than look like a 403.
        try:
            t = get_authorized_target(request.user, target_id, capability="read")
        except (Http404, PermissionDenied) as exc:
            raise PermissionDenied("You do not have access to this target.") from exc
        qs = qs.filter(target_id=t.pk)
    targets = authorized_targets(request.user)
    return render(
        request,
        "scope/index.html",
        {"rules": qs, "targets": targets, "target_id": target_id},
    )


@require_admin
def scope_add(request):
    if request.method == "POST":
        form = ScopeRuleForm(request.POST)
        if form.is_valid():
            rule = form.save(commit=False)
            rule.created_by = request.user
            rule.save()
            from services.event_engine.engine import emit_event

            emit_event(
                "SCOPE_CHANGED",
                target=rule.target,
                asset_value=rule.value,
                source="scope-ui",
                evidence={
                    "action": "added",
                    "rule_type": rule.rule_type,
                    "value": rule.value,
                    "actor": request.user.username,
                },
            )
            audit(request, "scope.changed", rule, new=f"+{rule.rule_type}={rule.value}")
            return redirect("scope-index")
    else:
        form = ScopeRuleForm()
    return render(request, "scope/form.html", {"form": form})


@require_admin
def scope_delete(request, pk):
    from django.shortcuts import get_object_or_404

    rule = get_object_or_404(ScopeRule, pk=pk)
    if request.method == "POST":
        from services.event_engine.engine import emit_event

        emit_event(
            "SCOPE_CHANGED",
            target=rule.target,
            asset_value=rule.value,
            source="scope-ui",
            evidence={
                "action": "removed",
                "rule_type": rule.rule_type,
                "value": rule.value,
                "actor": request.user.username,
            },
        )
        audit(request, "scope.changed", rule, old=f"-{rule.rule_type}={rule.value}")
        rule.delete()
        return redirect("scope-index")
    return render(request, "scope/confirm_delete.html", {"rule": rule})
