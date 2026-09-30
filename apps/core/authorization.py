"""Centralized target-level authorization (P0-002).

This module is the SINGLE source of truth for "may this user touch this
target?". Views, API viewsets, websocket consumers, export views and Celery
dispatch all resolve access here — never with an ad-hoc
``get_object_or_404(Target, pk=pk)``.

Role model
----------
``OWNER``   manage the target and its members, run scans, pause/resume/
            archive/delete, read all target data.
``OPERATOR`` run scans and operate monitoring actions; no membership admin,
            no archive/delete.
``VIEWER``  read-only target access.

A global administrator (superuser, or an explicit staff user holding the
``GLOBAL_TARGET_ADMIN`` profile role) has an explicit, auditable override.

Two failure modes are deliberately distinct:

* :func:`user_can_access_target` — boolean, for filtering.
* :func:`get_authorized_target` — raises ``Http404`` when the object does not
  exist and ``PermissionDenied`` when it exists but the user is not a member.
  Returning 404 for *existing but unauthorized* objects would leak existence;
  returning 403 for *nonexistent* ids would leak nothing but be noisier. We
  return 403 for unauthorized-existing and 404 for genuinely missing, which is
  the conventional Django split and does not disclose other tenants' content.
"""

import logging

from django.core.exceptions import PermissionDenied
from django.http import Http404

logger = logging.getLogger(__name__)

# Capability names, used by callers instead of comparing role strings.
CAP_READ = "read"
CAP_OPERATE = "operate"
CAP_MANAGE = "manage"


def global_admin_override(user):
    """True when `user` bypasses per-target membership entirely.

    Resolution order (all deliberate, all explicit):

    1. unauthenticated            -> False
    2. ``is_superuser``           -> True (Django's own hard override)
    3. profile role == ADMIN **and** the deployment opted in with
       ``GLOBAL_TARGET_ADMIN_OVERRIDE`` (default OFF) **and** the profile's own
       ``is_global_target_admin`` flag is set -> True

    A user with *any* target-scoped role (including OWNER) never gets the
    override: ownership is per-target, never global.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_superuser", False):
        return True
    from django.conf import settings

    if not getattr(settings, "GLOBAL_TARGET_ADMIN_OVERRIDE", False):
        return False
    profile = getattr(user, "profile", None)
    if profile is None:
        # No profile row yet: no explicit global-admin grant.
        return False
    return bool(getattr(profile, "role", "") == "ADMIN") and bool(
        getattr(profile, "is_global_target_admin", False)
    )


def effective_role(user, target):
    """Return the highest role `user` holds on `target`, or None."""
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    if global_admin_override(user):
        from apps.targets.models import TargetMembership

        return TargetMembership.ROLE_OWNER
    if target is None:
        return None
    from apps.targets.models import TargetMembership

    # `uniq_membership_user_target` means at most one row per (user, target),
    # so ordering is only a tie-break safety net. Rank explicitly rather than
    # ordering by the role string: "-role" sorts VIEWER > OPERATOR > OWNER
    # alphabetically, i.e. it would pick the WEAKEST role if the constraint
    # were ever relaxed.
    rows = TargetMembership.objects.filter(user_id=user.pk, target_id=getattr(target, "pk", target))
    best = None
    best_rank = -1
    for row in rows.only("role"):
        rank = TargetMembership.ROLE_RANK.get(row.role, 0)
        if rank > best_rank:
            best, best_rank = row.role, rank
    return best


def _rank(user, target):
    from apps.targets.models import TargetMembership

    if global_admin_override(user):
        return TargetMembership.ROLE_RANK[TargetMembership.ROLE_OWNER]
    role = effective_role(user, target)
    if role is None:
        return 0
    return TargetMembership.ROLE_RANK.get(role, 0)


def user_can_access_target(user, target, capability=CAP_READ):
    """Boolean authorization check. `capability` is read/operate/manage."""
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if target is None:
        return False
    from apps.targets.models import TargetMembership

    need = {
        CAP_READ: TargetMembership.ROLE_RANK[TargetMembership.ROLE_VIEWER],
        CAP_OPERATE: TargetMembership.ROLE_RANK[TargetMembership.ROLE_OPERATOR],
        CAP_MANAGE: TargetMembership.ROLE_RANK[TargetMembership.ROLE_OWNER],
    }.get(capability, TargetMembership.ROLE_RANK[TargetMembership.ROLE_VIEWER])
    return _rank(user, target) >= need


def get_authorized_target(user, target_id, capability=CAP_READ, include_archived=True):
    """Fetch a Target the user is authorized for, or raise.

    Raises ``Http404`` when the target does not exist, ``PermissionDenied``
    when it exists but the user lacks the capability.
    """
    from apps.targets.models import Target

    try:
        tid = int(target_id)
    except (TypeError, ValueError):
        # `from None`: a 404 must not reveal that the id was merely unparseable
        # rather than absent, and the traceback adds nothing to a 404.
        raise Http404("Target not found") from None
    try:
        target = Target.objects.get(pk=tid)
    except Target.DoesNotExist:
        # Same reasoning: do not chain a DoesNotExist into the 404.
        raise Http404("Target not found") from None
    if not include_archived and target.is_archived:
        raise Http404("Target not found")
    if not user_can_access_target(user, target, capability=capability):
        logger.warning(
            "target access denied",
            extra={
                "operation": "authorize_target",
                "status": "DENIED",
                "user_id": getattr(user, "pk", None),
                "target_id": target.pk,
                "capability": capability,
            },
        )
        raise PermissionDenied("You do not have access to this target.")
    return target


def authorized_targets(user, include_archived=True):
    """Queryset of every target `user` may read. Never returns all targets to a
    non-administrator."""
    from apps.targets.models import Target

    qs = Target.objects.for_user(user)
    if not include_archived:
        qs = qs.filter(status=Target.STATUS_ACTIVE)
    return qs


def authorized_target_ids(user, include_archived=True):
    return list(
        authorized_targets(user, include_archived=include_archived).values_list("id", flat=True)
    )


def require_capability(user, target, capability):
    """Imperative guard for call sites that already hold a target instance."""
    if not user_can_access_target(user, target, capability=capability):
        raise PermissionDenied("You do not have access to this target.")


def scope_queryset_for_user(
    user,
    queryset,
    target_lookup="target_id",
    capability=CAP_READ,
    user_field="user_id",
    membership_user_field="user",
):
    """Restrict an arbitrary target-owned queryset to authorized targets.

    Works for both direct ``target_id`` ownership and indirect ownership
    (e.g. ``Alert.event.target_id``, ``JobLog.job.target_id``) by passing the
    appropriate `target_lookup` (a Django ORM path).
    """
    if global_admin_override(user):
        return queryset
    if user is None or not getattr(user, "is_authenticated", False):
        return queryset.none()
    ids = authorized_target_ids(user)
    if not ids:
        return queryset.none()
    return queryset.filter(**{f"{target_lookup}__in": ids})


def require_websocket_target_access(user, target_id):
    """Consumer-side guard: raise PermissionDenied when the socket may not join
    ``target_<target_id>``. Called BEFORE ``group_add`` (P0-006)."""
    return get_authorized_target(user, target_id, capability=CAP_READ)


def grant_membership(user, target, role):
    """Create or update a membership row (idempotent)."""
    from apps.targets.models import TargetMembership

    obj, created = TargetMembership.objects.update_or_create(
        user=user, target=target, defaults={"role": role}
    )
    return obj, created


def revoke_membership(user, target):
    from apps.targets.models import TargetMembership

    return TargetMembership.objects.filter(user=user, target=target).delete()
