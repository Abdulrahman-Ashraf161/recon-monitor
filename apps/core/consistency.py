"""Cross-model target-consistency enforcement (P0-011).

Remediation: a relational database can only guarantee that a foreign key points
at a *row*, never that two rows agree on a common parent. The previous code
relied on ``Model.clean()``, which Django calls only from ``full_clean()`` and
therefore only for forms/DRF serializers — every direct ``.save()`` in a
service helper, task, or shell could silently persist a cross-target record
(``ToolExecution`` on Target B attached to a ``ScanRun`` on Target A, an
``Alert`` for a different target than its ``Event``, ...).

This module defines the rule once, as a mixin, and enforces it on ``save()``
*and* ``clean()`` so the guarantee holds on every write path.

Rules
-----
1. Every record that carries a ``target`` plus a FK to a target-scoped parent
   must have matching targets.
2. Records that carry no target at all must have a parent (there is no
   legitimate "orphan" execution) — except where the schema explicitly allows
   it (e.g. ``Event.target`` is nullable for global/aggregate events).
3. Violations raise :class:`ExecutionConsistencyError` (a ``ValueError``) so
   callers can distinguish a programming error from a validation error.

The rule is also enforced on the two ORM write paths that never call
``save()`` — ``bulk_create()`` and ``update()`` — via
:class:`ConsistentTargetScopedManager`. Both silently persisted cross-target
rows when only ``save()`` was guarded. Cross-table equality is not expressible
as a portable SQL ``CHECK`` constraint, so raw SQL remains the documented trust
boundary.
"""

from typing import ClassVar

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.core.target_scoping import TargetScopedManager, TargetScopedQuerySet


class ExecutionConsistencyError(ValueError):
    """A cross-model target relationship would have been violated."""


class TargetConsistencyMixin:
    """Enforce same-target rules for related rows.

    Subclasses declare either:

    * ``RELATED_TARGET_FKS = {"scan_run": "scan_run", ...}`` — a mapping of
      attribute name to a message label, checked against ``self.target_id``; or
    * ``REQUIRED_PARENT_FKS = ("scan_run",)`` — parents that must be present.

    Mappings are ``{field_name: label}`` so the error message is actionable.
    """

    RELATED_TARGET_FKS: ClassVar[dict[str, str]] = {}
    REQUIRED_PARENT_FKS: ClassVar[tuple[str, ...]] = ()

    def _parent_target_ids(self):
        """``{field: (label, target_id)}`` for every present, target-scoped parent.

        Parents that carry no target of their own are skipped: there is nothing
        for them to contradict.
        """
        found = {}
        for field, label in (self.RELATED_TARGET_FKS or {}).items():
            if not hasattr(self, f"{field}_id"):
                # Field is not a concrete relation on this model — nothing to check.
                continue
            if getattr(self, f"{field}_id", None) is None:
                continue
            parent_target_id = getattr(getattr(self, field), "target_id", None)
            if parent_target_id is None:
                continue
            found[field] = (label, parent_target_id)
        return found

    def missing_required_parents(self):
        return [
            label
            for field, label in (self.RELATED_TARGET_FKS or {}).items()
            if field in (self.REQUIRED_PARENT_FKS or ())
            and hasattr(self, f"{field}_id")
            and getattr(self, f"{field}_id", None) is None
        ]

    def inherited_target_id(self):
        """Target id this record should adopt when its own target is null.

        Returns the id only when every present, target-scoped parent agrees —
        an ambiguous or contradictory set of parents is a violation, not
        something to guess at, so this returns ``None`` and
        :meth:`_consistency_violations` reports the conflict instead.
        """
        if getattr(self, "target_id", None) is not None:
            return None
        candidates = {tid for _, tid in self._parent_target_ids().values()}
        if len(candidates) == 1:
            return next(iter(candidates))
        return None

    def _consistency_violations(self):
        """Side-effect free: validation must never mutate the instance."""
        problems = []
        for label in self.missing_required_parents():
            problems.append(f"{label} is required")

        own_target_id = getattr(self, "target_id", None)
        parents = self._parent_target_ids()
        if own_target_id is None:
            # The record's own target is optional (e.g. Event.target is
            # nullable for genuinely global events). If it hangs off a
            # target-scoped parent, save() adopts that target explicitly; if the
            # parents disagree there is no defensible target, so fail loudly.
            distinct = {tid for _, tid in parents.values()}
            if len(distinct) > 1:
                detail = ", ".join(f"{label} is on target {tid}" for label, tid in parents.values())
                problems.append(f"this record has no target but its parents disagree ({detail})")
        else:
            for label, parent_target_id in parents.values():
                if parent_target_id != own_target_id:
                    problems.append(
                        f"{label} belongs to target {parent_target_id} but this record "
                        f"is on target {own_target_id}"
                    )
        return problems

    def check_target_consistency(self):
        problems = self._consistency_violations()
        if problems:
            raise ExecutionConsistencyError("; ".join(problems))
        return True

    def clean(self):
        super().clean()
        problems = self._consistency_violations()
        if problems:
            raise ValidationError("; ".join(problems))

    def save(self, *args, **kwargs):
        # Enforced on every write path — not just full_clean().
        self.check_target_consistency()
        # Deliberate, explicit normalization (not a validator side effect):
        # a record with no target of its own but exactly one agreed parent
        # target inherits it.
        if hasattr(self, "target_id"):
            inherited = self.inherited_target_id()
            if inherited is not None:
                self.target_id = inherited
        return super().save(*args, **kwargs)


class ConsistencyEnforcingQuerySetMixin:
    """Mixin closing the ORM paths that bypass ``Model.save()``.

    ``save()`` is the normal enforcement point, but two queryset methods write
    to the table without ever calling it, and both silently persisted
    cross-target rows before this was added:

    * ``bulk_create()`` — a batch of unsaved instances
    * ``update()`` — a set-based ``UPDATE`` that can re-point ``target`` or a
      parent FK of many rows at once

    The invariant is cross-table, so no portable SQL ``CHECK`` constraint can
    express it; these are the practical backstops. A raw ``cursor.execute`` or a
    third-party bulk loader is still outside the ORM and remains the documented
    trust boundary.
    """

    def _consistency_field_names(self):
        """Column/attribute names whose bulk modification can break the rule."""
        names = {"target", "target_id"}
        for field in self.model.RELATED_TARGET_FKS or {}:
            names.add(field)
            names.add(f"{field}_id")
        for field in self.model.REQUIRED_PARENT_FKS or ():
            names.add(f"{field}_id")
        return names

    def bulk_create(self, objs, *args, **kwargs):
        for obj in objs:
            obj.check_target_consistency()
        created = super().bulk_create(objs, *args, **kwargs)
        # bulk_create skips save(), so apply the same explicit inheritance
        # save() would have applied, then persist the ids it needs for the
        # caller (observations reference their own rows by id).
        # strict=False is correct here: `objs` and `created` are the same list
        # by construction (bulk_create returns one row per input object), so a
        # length mismatch would be a Django bug, not caller error. Truncating
        # would leave a row without its inherited target, which is exactly the
        # cross-target leak this class exists to prevent -- so assert instead of
        # silently pairing the wrong objects.
        if len(objs) != len(created):  # pragma: no cover - Django invariant
            raise ValueError(
                f"bulk_create returned {len(created)} rows for {len(objs)} objects; "
                "refusing to pair them by position (would skip target inheritance)"
            )
        for obj, row in zip(objs, created, strict=True):
            if getattr(obj, "target_id", None) is None:
                inherited = obj.inherited_target_id()
                if inherited is not None:
                    obj.target_id = inherited
                    self.model._base_manager.filter(pk=row.pk).update(target_id=inherited)
        return created

    def update(self, **kwargs):
        if self._consistency_field_names() & set(kwargs):
            self._assert_update_consistent(kwargs)
        return super().update(**kwargs)

    def _assert_update_consistent(self, kwargs):
        """Dry-run the update on every affected row and validate the result."""
        import copy

        for row in self.all_objects_iterator():
            candidate = copy.copy(row)
            for key, value in kwargs.items():
                attr = key.removesuffix("_id")
                if attr != key and hasattr(candidate, attr):
                    setattr(candidate, attr, value)
                else:
                    setattr(candidate, key, value)
            candidate.check_target_consistency()

    def all_objects_iterator(self):
        # _base_manager is always unfiltered: a set-based update must validate
        # every row it will touch, not just the ones currently in scope.
        return self.model._base_manager.filter(pk__in=self.values("pk")).iterator()


class ConsistentTargetScopedQuerySet(ConsistencyEnforcingQuerySetMixin, TargetScopedQuerySet):
    """Target-scoped querying plus cross-model consistency enforcement."""


class ConsistentTargetScopedManager(TargetScopedManager):
    """Default manager for models that carry a target.

    Combines membership scoping (P0-008) with the cross-target write guard
    (P0-011) so ``objects`` and ``all_objects`` on a consistent model differ
    only in *read* scope, never in *write* safety.
    """

    def get_queryset(self):
        return ConsistentTargetScopedQuerySet(self.model, using=self._db)


class HeartbeatMixin(models.Model):
    """Cooperative liveness heartbeat (P1-006).

    Long-running work calls :meth:`beat` on a bounded cadence. The heartbeat is
    the *primary* liveness signal for stall detection: a run that is silent for
    longer than ``settings.JOB_STALL_SECONDS`` is stalled, regardless of how
    healthy its process tree looks.

    ``beat()`` deliberately never propagates a storage error into the caller's
    execution path: losing a heartbeat must not kill real work. The failure is
    logged and persisted on the record instead, so a later stall check can see
    the gap and the operator can see why liveness evidence disappeared.
    """

    class Meta:
        abstract = True

    heartbeat_at = models.DateTimeField(null=True, blank=True, db_index=True)

    def _beat_model(self):
        return type(self)

    def beat(self, commit=True):
        now = timezone.now()
        self.heartbeat_at = now
        if not commit or not self.pk:
            return now
        try:
            # _base_manager is always unfiltered — never the scoped default.
            self._beat_model()._base_manager.filter(pk=self.pk).update(heartbeat_at=now)
        # Deliberately broad: a storage outage must not abort real work. The
        # failure is logged with target/task context and written to the record
        # so the gap is still visible to stall detection and to an operator.
        except Exception as exc:  # pragma: no cover
            import logging

            logging.getLogger(__name__).error(
                "liveness heartbeat write failed: %s",
                exc.__class__.__name__,
                extra={
                    "target_id": getattr(self, "target_id", None),
                    "task_id": self.pk,
                    "operation": "heartbeat",
                    "status": "ERROR",
                },
            )
            self._record_heartbeat_failure(exc)
        return now

    def _record_heartbeat_failure(self, exc):
        stats_field = self._stats_field_name()
        if not stats_field or stats_field not in {f.name for f in self._meta.concrete_fields}:
            return
        stats = dict(getattr(self, stats_field, None) or {})
        stats["last_heartbeat_error"] = f"{exc.__class__.__name__}"
        try:
            self._beat_model()._base_manager.filter(pk=self.pk).update(**{stats_field: stats})
            setattr(self, stats_field, stats)
        # Best effort by design: recording why the heartbeat failed is itself
        # a second write to the same unavailable store, so there is nowhere
        # left to report to. Swallowing here is intentional — the original
        # work must keep running — and the caller already logged the cause.
        except Exception:
            pass

    @staticmethod
    def _stats_field_name():
        return "stats"

    def liveness_at(self):
        return self.heartbeat_at
