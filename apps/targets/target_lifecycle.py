"""Centralized target lifecycle: legal transitions and their side effects.

P2-005 / P2-007
---------------
The target model declared ``ALLOWED_STATUS_TRANSITIONS`` and
``ALLOWED_AUTH_TRANSITIONS``, but every writer went around them: views assigned
``target.status = ...`` directly, so a PAUSED target could be flipped to
ARCHIVED without the required work-cancellation side effects, and an
unauthorised assignment could resurrect an expired engagement. Validation
scattered across call sites is not validation.

This module is the single entry point for changing a target's lifecycle state.
It:

1. **rejects illegal transitions** (``InvalidTransition``) before any write, so
   an out-of-policy change is impossible rather than merely discouraged;
2. **runs the required side effects** for each transition — in-flight work is
   halted through the same kill switch the pause path uses (P0-013), queued work
   is re-queued on resume, and authorization changes raise the matching
   authorization events (P0-014);
3. **stamps the transition** (``status_changed_at`` / ``archived_at``) and
   records an audit line, so "who disabled this target, and when" is always
   answerable.

Archive vs delete (P2-005)
--------------------------
Archiving is the **default** removal path and is a soft delete: assets, ScanRuns,
events, AssetObservations, ToolExecutions and audit history all survive, and the
target simply stops being scannable. Hard deletion still exists for genuine
data-removal requests, but it is only reachable through
:func:`purge_target`, which requires an explicit confirmation token, stops all
in-flight work first, and returns a manifest of exactly what was destroyed so
the caller can record it.
"""

import logging

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


class InvalidTransition(Exception):
    """Raised when a lifecycle change is not permitted by the model policy."""

    def __init__(self, current, requested, kind="status"):
        self.current = current
        self.requested = requested
        self.kind = kind
        super().__init__(f"illegal {kind} transition: {current} -> {requested}")


def _now():
    return timezone.now()


def is_legal_status_transition(current, requested):
    from apps.targets.models import Target

    if current == requested:
        return True  # idempotent
    return requested in Target.ALLOWED_STATUS_TRANSITIONS.get(current, set())


def is_legal_auth_transition(current, requested):
    from apps.targets.models import Target

    if current == requested:
        return True
    return requested in Target.ALLOWED_AUTH_TRANSITIONS.get(current, set())


def halt_in_flight_work(target, reason):
    """Stop running work and mark the execution roots cancelled (P0-013)."""
    from apps.jobs.tasks import _halt_work

    return _halt_work(target, reason)


@transaction.atomic
def transition_to(
    target, new_status=None, new_auth=None, reason="", actor=None, halt_reason=None, force=False
):
    """Move a target's lifecycle state, enforcing the policy and side effects.

    ``force=True`` bypasses the transition table (operator escape hatch used by
    repair tooling); it is still audited. Returns the target.
    """
    from apps.targets.models import Target
    from services.event_engine.engine import emit_event

    changed = []

    if new_status is not None and new_status != target.status:
        if not force and not is_legal_status_transition(target.status, new_status):
            raise InvalidTransition(target.status, new_status, "status")
        previous = target.status
        target.status = new_status
        changed.append(("status", previous, new_status))
        if new_status == Target.STATUS_ARCHIVED and not target.archived_at:
            target.archived_at = _now()
        if new_status == Target.STATUS_ACTIVE and previous == Target.STATUS_ARCHIVED:
            # Un-archiving must not silently un-pause: archived_at is cleared,
            # status is ACTIVE, and the target is scannable again only if it is
            # also AUTHORIZED.
            target.archived_at = None

    if new_auth is not None and new_auth != target.authorization_status:
        if not force and not is_legal_auth_transition(target.authorization_status, new_auth):
            raise InvalidTransition(target.authorization_status, new_auth, "authorization")
        previous_auth = target.authorization_status
        target.authorization_status = new_auth
        changed.append(("authorization", previous_auth, new_auth))

    if not changed:
        return target

    fields = ["status", "authorization_status", "archived_at", "updated_at"]
    target.save(update_fields=fields)

    # --- side effects -------------------------------------------------------
    # Work must be halted whenever the target stops being scannable -- which
    # includes an *authorization* change (expiry/withdrawal), not just a status
    # change. Keying this on `new_status` alone let a target keep running live
    # tools after its authorization lapsed.
    if new_status is not None and new_status != Target.STATUS_ACTIVE:
        halt_in_flight_work(target, halt_reason or f"TARGET_{new_status}")
    elif new_status is None and not target.is_scannable:
        halt_in_flight_work(target, halt_reason or f"AUTH_{target.authorization_status}")
    if new_status == Target.STATUS_ACTIVE:
        # Resume: make queued work runnable again.
        from apps.jobs.models import ScanJob

        ScanJob.all_objects.filter(target=target, status=ScanJob.STATUS_PAUSED).update(
            status=ScanJob.STATUS_QUEUED
        )

    # --- events + audit ----------------------------------------------------
    try:
        if new_auth == Target.AUTH_EXPIRED:
            emit_event(
                "AUTHORIZATION_EXPIRED",
                target=target,
                asset_value=target.root_domain,
                source="lifecycle",
                evidence={"reason": reason, "actor": str(actor or "")},
            )
        elif new_auth == Target.AUTH_AUTHORIZED:
            emit_event(
                "AUTHORIZATION_REAUTHORIZED",
                target=target,
                asset_value=target.root_domain,
                source="lifecycle",
                evidence={"reason": reason, "actor": str(actor or "")},
            )
        if new_status == Target.STATUS_ARCHIVED:
            emit_event(
                "TARGET_ARCHIVED",
                target=target,
                asset_value=target.root_domain,
                source="lifecycle",
                evidence={"reason": reason, "actor": str(actor or "")},
            )
    except Exception as e:
        logger.error(
            "lifecycle event emission failed for %s: %s",
            target.root_domain,
            e,
            extra={"target_id": target.pk, "operation": "transition_to", "status": "ERROR"},
        )

    logger.info(
        "target lifecycle transition",
        extra={
            "target_id": target.pk,
            "operation": "transition_to",
            "status": "OK",
            "changes": [{"kind": k, "from": a, "to": b} for k, a, b in changed],
            "actor": str(actor or ""),
        },
    )
    return target


# --------------------------------------------------------------------------
# P2-005: archive (soft delete) and explicit purge (hard delete)
# --------------------------------------------------------------------------


def archive_target(target, reason="", actor=None):
    """Soft-delete a target. All historical evidence survives."""
    return transition_to(
        target,
        new_status=target.STATUS_ARCHIVED,
        reason=reason or "archived by operator",
        actor=actor,
    )


def restore_target(target, reason="", actor=None):
    return transition_to(
        target,
        new_status=target.STATUS_ACTIVE,
        reason=reason or "restored by operator",
        actor=actor,
    )


PURGE_CONFIRMATION = "PURGE"


@transaction.atomic
def purge_target(target, confirmation=None, reason="", actor=None):
    """Hard-delete a target. Requires an explicit confirmation token.

    P2-005: hard deletion is irreversible and cascades to every historical
    artifact. It therefore (a) requires ``confirmation == PURGE_CONFIRMATION``,
    (b) stops all in-flight work first so nothing keeps writing, and (c) returns
    a manifest of exactly what is destroyed, so the caller can record it in the
    audit log. Callers should prefer :func:`archive_target`.
    """
    from apps.assets.models import (
        CVE,
        APIEndpoint,
        DNSRecord,
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
    from apps.jobs.models import AssetObservation, ScanJob, ScanRun, ToolExecution

    if confirmation != PURGE_CONFIRMATION:
        raise ValueError(
            f"hard delete requires confirmation == {PURGE_CONFIRMATION!r} (got {confirmation!r}); "
            "use archive_target for a reversible removal"
        )

    # Stop work first: a running worker must not recreate rows mid-purge.
    halt_in_flight_work(target, "TARGET_PURGED")

    manifest = {}
    for label, model in [
        ("subdomains", Subdomain),
        ("dns_records", DNSRecord),
        ("ips", IPAddress),
        ("ports", Port),
        ("http_services", HTTPService),
        ("urls", URLAsset),
        ("api_endpoints", APIEndpoint),
        ("javascript", JavaScriptAsset),
        ("technologies", Technology),
        ("cves", CVE),
        ("security_findings", SecurityFinding),
        ("scan_runs", ScanRun),
        ("scan_jobs", ScanJob),
        ("tool_executions", ToolExecution),
        ("asset_observations", AssetObservation),
        ("events", Event),
    ]:
        try:
            manifest[label] = model.all_objects.filter(target=target).count()
        except Exception:
            manifest[label] = None
    from apps.monitoring.models import Baseline, ExportJob

    # P2-005/P2-007: the manifest is the audit record of exactly what a
    # destructive purge destroyed. Record each count independently and mark a
    # failure as None, exactly as the loop above does -- a bare `pass` here
    # dropped both keys silently, producing a manifest that looked complete
    # while omitting what was destroyed.
    for label, model in (("baselines", Baseline), ("exports", ExportJob)):
        try:
            manifest[label] = model.all_objects.filter(target=target).count()
        except Exception:
            manifest[label] = None

    logger.warning(
        "target purged",
        extra={
            "target_id": target.pk,
            "operation": "purge_target",
            "status": "DESTRUCTIVE",
            "reason": reason,
            "actor": str(actor or ""),
            "manifest": manifest,
        },
    )
    target.delete()
    return manifest
