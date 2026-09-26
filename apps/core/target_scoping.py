"""Target-scoped querying: make safe querying the default (TASK-005).

Usage:
    from apps.core.target_scoping import TargetScopedQuerySet, TargetScopedManager, for_target
    class Subdomain(models.Model):
        objects = TargetScopedManager()
"""
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models


class TargetScopedQuerySet(models.QuerySet):
    def for_target(self, target):
        """Filter by target instance or id. Raises if target is None."""
        if target is None:
            raise ValidationError("target context is required")
        tid = getattr(target, "pk", target)
        return self.filter(target_id=tid)

    def active(self):
        if "is_active" in [f.name for f in self.model._meta.get_fields()]:
            return self.filter(is_active=True)
        if "state" in [f.name for f in self.model._meta.get_fields()]:
            return self.exclude(state__in=["INACTIVE", "REMOVED"])
        return self


class TargetScopedManager(models.Manager):
    def get_queryset(self):
        return TargetScopedQuerySet(self.model, using=self._db)

    def for_target(self, target):
        return self.get_queryset().for_target(target)


def for_target(queryset, target):
    """Helper for querysets that already exist."""
    if target is None:
        raise ValidationError("target context is required")
    tid = getattr(target, "pk", target)
    return queryset.filter(target_id=tid)


def get_object_for_target(model, pk, target):
    """Fetch single object enforcing ownership. Raises PermissionDenied on mismatch."""
    try:
        obj = model.objects.get(pk=pk)
    except model.DoesNotExist:
        from django.http import Http404
        raise Http404(f"{model.__name__} not found")
    tid = getattr(target, "pk", target)
    obj_tid = getattr(obj, "target_id", None)
    if obj_tid is None:
        # indirect ownership: try common chains js->js.target, event->target
        for attr in ("js", "event", "scan_run"):
            rel = getattr(obj, attr, None)
            if rel is not None and getattr(rel, "target_id", None) == tid:
                return obj
        raise PermissionDenied("cross-target access denied")
    if obj_tid != tid:
        raise PermissionDenied("cross-target access denied")
    return obj


def validate_no_cross_target(obj, field_name, other):
    """Ensure obj.target == other.target. Used in model clean()."""
    t1 = getattr(obj, "target_id", None)
    t2 = getattr(other, "target_id", None) if other is not None else None
    if t1 is not None and t2 is not None and t1 != t2:
        raise ValidationError(
            f"Cross-target relationship rejected: {type(obj).__name__} "
            f"(target {t1}) cannot reference {type(other).__name__} (target {t2})"
        )


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
            .exclude(status="RESOLVED").exclude(status="FALSE_POSITIVE").count(),
            "events": Event.objects.filter(target_id=tid).count(),
        }
        if use_cache:
            cache.set(key, result, TargetAssetService.COUNTS_TTL)
        return result


class TargetEventService:
    @staticmethod
    def recent(target, limit=30):
        from apps.events.models import Event
        return (Event.objects.filter(target_id=getattr(target, "pk", target))
                .select_related("target").order_by("-created_at")[:limit])

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
