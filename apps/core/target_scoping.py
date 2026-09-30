"""Target-scoped querying: make safe querying the default (TASK-005, P0-008).

This module is the single place that answers two questions:

1. **Which target owns this object?** (:func:`ownership_of`,
   :func:`ownership_query_path`) — directly via a ``target`` FK, indirectly via
   a parent that has one (``Alert.job``, ``JobLog.job``, ``JavaScriptVersion.js``),
   or not at all (system rows).
2. **Which rows may this user see?** (:func:`for_user`,
   :meth:`TargetScopedQuerySet.for_user`) — membership-scoped, default-deny.

The previous implementation inferred ownership in :func:`get_object_for_target`
by probing a hard-coded list of attribute names (``js``, ``event``,
``scan_run``) with ``getattr``, which issued a database query per attribute,
missed every model not on that list, and — because ``Alert`` owns a *direct*
``target`` FK — disagreed with the querysets used elsewhere. Ownership is now
declared once per model in :data:`OWNERSHIP_PATHS` and resolved uniformly.

Usage:
    from apps.core.target_scoping import TargetScopedManager, for_user
    class Subdomain(models.Model):
        objects = TargetScopedManager()
"""

from typing import Any

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models

# --- Ownership classification (P0-008) ---------------------------------------

OWNERSHIP_DIRECT = "direct"  # model has its own `target` FK
OWNERSHIP_INDIRECT = "indirect"  # reaches a target through a parent relation
OWNERSHIP_USER = "user"  # scoped to a user, not a target
OWNERSHIP_GLOBAL = "global"  # system row with no target (e.g. Target itself)

# ORM path from each model to its owning Target. Direct models map to
# "target"; indirect models name the chain. Models absent from this mapping are
# classified by :func:`classify_model` from their FKs, and
# ``tests/test_target_isolation.py`` asserts the mapping stays complete.
OWNERSHIP_PATHS = {
    # --- direct ---
    "TargetMembership": "target",
    "ScopeRule": "target",
    "Asset": "target",
    "Subdomain": "target",
    "DNSRecord": "target",
    "IPAddress": "target",
    "Port": "target",
    "HTTPService": "target",
    "URLAsset": "target",
    "APIEndpoint": "target",
    "JavaScriptAsset": "target",
    "JavaScriptFinding": "target",
    "Technology": "target",
    "CVE": "target",
    "SecurityFinding": "target",
    "Event": "target",
    "Alert": "target",
    "ScanJob": "target",
    "JSAnalysisJob": "target",
    "ScanRun": "target",
    "ToolExecution": "target",
    "AssetObservation": "target",
    "Baseline": "target",
    "ExportJob": "target",
    "AuditLog": "target",
    # --- indirect: parent owns the target ---
    "JavaScriptVersion": "js__target",
    "JobLog": "job__target",
    "JSAnalysisLog": "job__target",
    # --- user-scoped ---
    "Profile": None,  # user-owned; no target
    # --- global system rows ---
    "Target": None,
    "CVESyncState": None,
    "DiscordBatch": None,
}

# Relations that may carry ownership when a model is not listed above. Order is
# irrelevant now (it is only a fallback for unmapped models) but must be
# complete for correctness.
_FALLBACK_PARENTS = ("js", "job", "event", "scan_run", "target")


def ownership_query_path(model):
    """ORM path from `model` to its owning Target, or None.

    None means the model is not target-owned (user-scoped or global), and a
    queryset over it must not be filtered by target.
    """
    return classify_model(model)[1]


def classify_model(model):
    """Classify how (or whether) `model` is owned by a target.

    Returns ``(kind, query_path)``. Mapped models use the declaration; unknown
    models are classified from their own FKs so a new model is never silently
    treated as global.
    """
    name = model.__name__ if isinstance(model, type) else type(model).__name__
    if name in OWNERSHIP_PATHS:
        path = OWNERSHIP_PATHS[name]
        if path is None:
            kind = OWNERSHIP_USER if name == "Profile" else OWNERSHIP_GLOBAL
            return kind, None
        return (OWNERSHIP_DIRECT if path == "target" else OWNERSHIP_INDIRECT), path

    fields = {f.name for f in model._meta.get_fields() if getattr(f, "many_to_one", False)}
    if "target" in fields:
        return OWNERSHIP_DIRECT, "target"
    for parent in _FALLBACK_PARENTS:
        if parent in fields:
            return OWNERSHIP_INDIRECT, f"{parent}__target"
    if "user" in fields:
        return OWNERSHIP_USER, None
    return OWNERSHIP_GLOBAL, None


def ownership_of(obj):
    """Resolve the target id owning `obj`.

    Returns ``None`` for user-scoped and global rows. Raises
    :class:`ValidationError` when a relationship chain is broken, because a
    half-linked row must not be treated as unowned (that would read as
    "not tenant data").
    """
    model = type(obj)
    kind, path = classify_model(model)
    if kind in (OWNERSHIP_USER, OWNERSHIP_GLOBAL):
        return None
    value = obj
    for attr in path.split("__"):
        value = getattr(value, attr, None)
        if value is None:
            raise ValidationError(f"{model.__name__} has a broken ownership chain at '{path}'")
    return getattr(value, "pk", value)


class OwnershipError(ValidationError):
    """Raised when a cross-target reference is rejected."""


class TargetScopedQuerySet(models.QuerySet[Any]):
    def for_target(self, target):
        """Filter by target instance or id. Raises if target is None."""
        if target is None:
            raise ValidationError("target context is required")
        tid = getattr(target, "pk", target)
        return self.filter(target_id=tid)

    def for_user(self, user, capability=None):
        """Restrict to targets `user` may read. Default-deny.

        Global administrators keep full visibility; unauthenticated callers and
        users with no memberships get ``.none()`` rather than everything.
        """
        from apps.core.authorization import (
            authorized_target_ids,
            global_admin_override,
            user_can_access_target,
        )

        if global_admin_override(user):
            return self
        if user is None or not getattr(user, "is_authenticated", False):
            return self.none()
        if capability is None:
            ids = authorized_target_ids(user)
            return self.filter(target_id__in=ids) if ids else self.none()
        # Capability variant: filter by authorized target, then narrow.
        from apps.targets.models import Target

        allowed = [
            t.pk
            for t in Target.all_objects.all()
            if user_can_access_target(user, t, capability=capability)
        ]
        return self.filter(target_id__in=allowed) if allowed else self.none()

    def active(self):
        if "is_active" in [f.name for f in self.model._meta.get_fields()]:
            return self.filter(is_active=True)
        if "state" in [f.name for f in self.model._meta.get_fields()]:
            return self.exclude(state__in=["INACTIVE", "REMOVED"])
        return self


class TargetScopedManager(models.Manager[Any]):
    def get_queryset(self):
        return TargetScopedQuerySet(self.model, using=self._db)

    def for_target(self, target):
        return self.get_queryset().for_target(target)

    def for_user(self, user, capability=None):
        return self.get_queryset().for_user(user, capability=capability)


def for_target(queryset, target):
    """Helper for querysets that already exist."""
    if target is None:
        raise ValidationError("target context is required")
    tid = getattr(target, "pk", target)
    return queryset.filter(target_id=tid)


def for_user(queryset, user, capability=None):
    """Membership-scope an arbitrary queryset, following indirect ownership.

    Works for a model with a direct ``target`` FK and for one that reaches its
    target through a parent, because the query path comes from
    :func:`classify_model` rather than being guessed per call site.
    """
    from apps.core.authorization import authorized_target_ids, global_admin_override

    if global_admin_override(user):
        return queryset
    if user is None or not getattr(user, "is_authenticated", False):
        return queryset.none()
    kind, path = classify_model(queryset.model)
    if kind in (OWNERSHIP_USER, OWNERSHIP_GLOBAL):
        # Not tenant data: a global row (e.g. the Target list) is filtered by
        # the caller with `authorized_targets`, and a user-scoped row by its
        # owner. Refusing to guess here is deliberate.
        raise ValidationError(f"{queryset.model.__name__} is not target-owned; scope it explicitly")
    ids = authorized_target_ids(user)
    if not ids:
        return queryset.none()
    head, _, tail = path.rpartition("__")
    if head:
        return queryset.filter(**{f"{head}__{tail}__in": ids})
    return queryset.filter(**{f"{tail}__in": ids})


def get_object_for_target(model, pk, target):
    """Fetch a single object, enforcing that it belongs to `target`.

    Ownership is resolved through :func:`ownership_of`, so direct and indirect
    models are handled by the same code path. A genuine cross-target request
    raises :class:`PermissionDenied`; a missing row raises ``Http404``.
    """
    from django.http import Http404

    try:
        obj = model.objects.get(pk=pk)
    except model.DoesNotExist:
        # `from None`: a 404 should not carry a DoesNotExist chain that would
        # confirm the row's absence in a traceback.
        raise Http404(f"{model.__name__} not found") from None
    tid = getattr(target, "pk", target)
    try:
        owner_tid = ownership_of(obj)
    except OwnershipError:
        owner_tid = None
    if owner_tid != tid:
        raise PermissionDenied("cross-target access denied")
    return obj


def validate_no_cross_target(obj, field_name, other):
    """Ensure obj and other belong to the same target. Used in model clean().

    Resolves ownership through :func:`ownership_of` so an indirect relation
    (``Alert.job``, ``JobLog.job``) is checked as strictly as a direct ``target``
    FK. Rows with no owner (system rows) never block the reference.
    """
    if other is None:
        return True
    try:
        t1 = ownership_of(obj)
        t2 = ownership_of(other)
    except ValidationError:
        # A broken chain is not evidence of a cross-target conflict; the
        # database constraint is the backstop. Do not mask a real ValueError.
        return True
    if t1 is not None and t2 is not None and t1 != t2:
        raise OwnershipError(
            f"Cross-target relationship rejected: {type(obj).__name__} "
            f"(target {t1}) cannot reference {type(other).__name__} (target {t2})"
        )
    return True


class TargetAssetService:
    """Service helpers for asset access (TASK-005)."""

    @staticmethod
    def list(model, target, **filters):
        return model.objects.filter(target_id=getattr(target, "pk", target), **filters)

    # Task 17: dashboard calls counts() on every render (11 sequential
    # COUNTs). Cache per target for 60s in the default cache. Values may lag
    # writes by up to the TTL — the dashboard labels them "as of ~1 min ago".
    # Call invalidate_counts(target) after bulk ingest if fresher data matters.
    COUNTS_TTL = 60

    @staticmethod
    def _counts_key(target):
        return f"target_counts:{getattr(target, 'pk', target)}"

    @staticmethod
    def invalidate_counts(target):
        from django.core.cache import cache

        cache.delete(TargetAssetService._counts_key(target))

    @staticmethod
    def counts(target, use_cache=True):
        from django.core.cache import cache

        from apps.assets.models import (
            CVE,
            APIEndpoint,
            HTTPService,
            IPAddress,
            JavaScriptAsset,
            Port,
            SecurityFinding,
            Subdomain,
            Technology,
            URLAsset,
        )
        from apps.events.models import Event

        tid = getattr(target, "pk", target)
        key = TargetAssetService._counts_key(target)
        if use_cache:
            cached = cache.get(key)
            if cached is not None:
                return cached
        result = {
            "subdomains": Subdomain.objects.filter(target_id=tid, is_active=True).count(),
            "ips": IPAddress.objects.filter(target_id=tid, is_active=True).count(),
            "ports": Port.objects.filter(target_id=tid, state="open").count(),
            "http": HTTPService.objects.filter(target_id=tid).count(),
            "urls": URLAsset.objects.filter(target_id=tid).count(),
            "apis": APIEndpoint.objects.filter(target_id=tid).count(),
            "js": JavaScriptAsset.objects.filter(target_id=tid).count(),
            "technologies": Technology.objects.filter(target_id=tid).count(),
            "cves": CVE.objects.filter(target_id=tid).exclude(status="not_affected").count(),
            "findings": SecurityFinding.objects.filter(target_id=tid)
            .exclude(status="RESOLVED")
            .exclude(status="FALSE_POSITIVE")
            .count(),
            "events": Event.objects.filter(target_id=tid).count(),
        }
        if use_cache:
            cache.set(key, result, TargetAssetService.COUNTS_TTL)
        return result


class TargetEventService:
    @staticmethod
    def recent(target, limit=30):
        from apps.events.models import Event

        return (
            Event.objects.filter(target_id=getattr(target, "pk", target))
            .select_related("target")
            .order_by("-created_at")[:limit]
        )

    @staticmethod
    def timeline(target, limit=100):
        return TargetEventService.recent(target, limit)


class TargetReportService:
    @staticmethod
    def assert_single_target(objects, target):
        tid = getattr(target, "pk", target)
        for o in objects:
            if getattr(o, "target_id", tid) != tid:
                raise PermissionDenied("Report would mix targets — rejected")
        return True
