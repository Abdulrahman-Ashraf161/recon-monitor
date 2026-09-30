"""Ambient execution context for scan provenance (P0-009 / P1-005).

Problem this solves
-------------------
``ScanRun``/``ScanJob``/``ToolExecution``/``AssetObservation`` were modelled but
never populated: the pipeline threaded a free-form ``run_id`` string that
nothing could constrain, and the ingest layer had no way to know which
execution it was running under. As a result "which scan found this asset?" was
unanswerable, and the kill switch had no execution root to act on.

Approach
--------
A :mod:`contextvars` based ambient context. The orchestrator enters a context
for the duration of a stage, and anything that persists an asset while the
context is active automatically records a traceable ``AssetObservation``
against the canonical ``ScanRun``, the ``ScanJob`` and the ``ToolExecution``.

Why contextvars rather than a parameter on every function
---------------------------------------------------------
* ``contextvars`` is the only nesting-safe option: a Celery worker may process
  concurrent greenlets/threads, and a thread-local would leak one scan's
  provenance into another's rows.
* The ingest layer has ~8 public functions called from ~6 modules. Threading
  ``scan_run=`` through all of them is a wide, easily-forgotten change; a
  missing argument would silently produce untraceable rows — exactly the bug
  class this taskbook is about.
* Provenance is a *cross-cutting* concern (observability), not a data
  dependency, so ambient is the honest model.

The context is **additive**: with no active context, ingestion behaves exactly
as before and records nothing. Provenance can therefore never break the scan.
"""

import contextlib
import contextvars
from dataclasses import dataclass, field

from django.db import models


@dataclass
class ScanContext:
    """The execution currently in scope."""

    target_id: int
    scan_run: object | None = None
    job: object | None = None
    tool_execution: object | None = None
    asset_type: str = ""
    # Suppress observation recording (e.g. inside bulk backfills/migration
    # repair commands) without tearing down the context.
    record: bool = True
    extras: dict[str, object] = field(default_factory=dict)


_current: contextvars.ContextVar[object | None] = contextvars.ContextVar(
    "recon_scan_context", default=None
)

# P1-003/P1-004: evidence losses in the current task context. Both lost
# ToolExecution rows and lost AssetObservation rows land here so a stage can
# refuse to report a clean success on an incomplete audit trail. Lives in this
# module (not in apps.jobs.tasks) so the ingest layer can report losses without
# importing the orchestrator.
_EVIDENCE_LOSSES: list[dict[str, object]] = []


def note_evidence_loss(kind: str, detail: str, target_id=None, job=None) -> None:
    """Record a lost evidence row (P1-003/P1-004).

    ``kind`` is ``"tool_execution"`` or ``"asset_observation"``. Losses are
    logged with full context *and* counted, so the stage that produced them
    degrades instead of reporting success over a broken audit trail.
    """
    import logging

    logging.getLogger(__name__).error(
        "evidence row lost: kind=%s detail=%s",
        kind,
        detail,
        extra={
            "target_id": target_id,
            "task_id": getattr(job, "pk", None),
            "operation": f"record_{kind}",
            "status": "ERROR",
        },
    )
    _EVIDENCE_LOSSES.append(
        {
            "kind": kind,
            "detail": str(detail)[:200],
            "target_id": target_id,
        }
    )


def evidence_failures(reset: bool = False):
    """Evidence rows lost in the current task context (P1-003/P1-004)."""
    if reset:
        _EVIDENCE_LOSSES.clear()
    return list(_EVIDENCE_LOSSES)


def current_context():
    return _current.get()


def has_context():
    return _current.get() is not None


@contextlib.contextmanager
def scan_context(ctx: ScanContext):
    """Install ``ctx`` for the duration of the block (nesting-safe)."""
    token = _current.set(ctx)
    try:
        yield ctx
    finally:
        _current.reset(token)


@contextlib.contextmanager
def tool_context(tool_execution, **ctx_fields):
    """Bind a ``ToolExecution`` to the current context, restoring it after."""
    ctx = current_context()
    if ctx is None:
        yield None
        return
    previous = ctx.tool_execution
    ctx.tool_execution = tool_execution
    for key, value in ctx_fields.items():
        setattr(ctx, key, value)
    try:
        yield ctx
    finally:
        ctx.tool_execution = previous


def record_observation(
    asset_type, asset_value, asset_id=None, observed=True, evidence=None, metadata=None
):
    """Append a traceable observation row if a context is active.

    Returns the created row, or ``None`` when there is no active context (the
    normal case for management commands and migrations) or when the row could
    not be written. Never raises -- losing provenance must not fail a scan --
    but the loss is **not silent** (P1-004): it is logged with full context and
    counted in :func:`evidence_failures`, so the running stage degrades to
    PARTIAL instead of claiming success over an untraceable execution.
    """
    ctx = current_context()
    if ctx is None or not ctx.record or ctx.scan_run is None:
        return None
    import hashlib
    import json

    from apps.jobs.models import AssetObservation

    try:
        mh = ""
        if metadata:
            mh = hashlib.sha256(
                json.dumps(metadata, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]
        return AssetObservation.objects.create(
            target_id=ctx.target_id,
            scan_run=ctx.scan_run,
            job=ctx.job,
            tool_execution=ctx.tool_execution,
            asset_type=asset_type,
            asset_id=asset_id,
            asset_value=str(asset_value)[:2048],
            observed=observed,
            metadata_hash=mh,
            evidence=evidence or {},
        )
    except Exception as exc:
        note_evidence_loss(
            "asset_observation", exc.__class__.__name__, target_id=ctx.target_id, job=ctx.job
        )
        return None


def record_observations(
    asset_type, rows, asset_key="value", id_key=None, observed_key=None, evidence=None
):
    """Record a batch of observations from already-persisted assets.

    ``rows`` is an iterable of model instances or dicts. Only rows that the
    caller has already decided were persisted should be passed in, so the
    ``observed`` flag is honest.
    """
    ctx = current_context()
    if ctx is None or not ctx.record or ctx.scan_run is None:
        return 0
    written = 0
    for row in rows:
        if isinstance(row, models.Model):
            value = getattr(row, asset_key, "") if asset_key else str(row)
            rid = getattr(row, "pk", None) if id_key is None else getattr(row, id_key, None)
        elif isinstance(row, dict):
            value = row.get(asset_key, "")
            rid = row.get(id_key or "id")
        else:
            value, rid = str(row), None
        if not value:
            continue
        obs = observed_key is None
        if isinstance(row, dict) and observed_key:
            obs = bool(row.get(observed_key, True))
        if (
            record_observation(asset_type, value, asset_id=rid, observed=obs, evidence=evidence)
            is not None
        ):
            written += 1
    return written
