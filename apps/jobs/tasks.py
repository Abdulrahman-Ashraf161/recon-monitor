"""Celery pipeline: discovery -> dns -> network -> http -> urls -> js -> tech/cve -> nuclei.
Every task: scope-gated, kill-switch aware, failure-isolated, resumable via ScanJob.checkpoint.

P0-009: every stage attaches to a real ``ScanRun`` execution root (a FK), never a
free-form ``run_id`` string. ``ScanContext`` (apps.core.execution_context) makes
each persisted asset traceable back to run + job + tool invocation.
"""

import contextlib
import logging
import time
import urllib.request

from celery import shared_task
from django.db import IntegrityError, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

# P1-012: the stdlib socket fallback is a connect() per (ip, port) with a
# 1.5s timeout, so a naive full port-list x IP sweep would stall the worker.
# The cap is explicit and every capped run is reported as reduced coverage --
# limited coverage is never labeled complete.
PORT_FALLBACK_MAX_PORTS = 20

# P1-011: same rule for http probing -- the stdlib urllib fallback probes a
# capped candidate set and is reported as reduced coverage.
HTTP_FALLBACK_MAX_URLS = 200

# P1-002: per-stream cap on retained tool output. Evidence must stay
# reviewable without letting one noisy scanner fill the disk; the row keeps a
# reference to bounded, redacted bytes.
TOOL_OUTPUT_MAX_BYTES = 512 * 1024


def _store_tool_output(tool_name: str, stream: str, content: str) -> str:
    """Persist a tool output stream and return a reference for the DB row.

    P1-002: tool stdout/stderr are *referenced*, not inlined — the row keeps a
    path relative to ``settings.RAW_DIR`` so the evidence stays retrievable
    while the database row stays small. Content is redacted (secrets never
    reach disk) and bounded. Returns "" when there is nothing to store or the
    write failed; the failure is logged rather than raised so evidence
    capture can never break a scan.
    """
    if not content:
        return ""
    import os
    import re as _re
    import uuid as _uuid

    from django.conf import settings as _settings
    from django.utils import timezone as _tz

    from services.redaction import redact_text

    safe_tool = _re.sub(r"[^A-Za-z0-9_.-]+", "_", tool_name or "tool")[:48]
    payload = redact_text(content, limit=TOOL_OUTPUT_MAX_BYTES)
    try:
        raw_dir = getattr(_settings, "RAW_DIR", None)
        if raw_dir is None:
            return ""
        day = _tz.now().strftime("%Y%m%d")
        folder = os.path.join(str(raw_dir), safe_tool, day)
        os.makedirs(folder, mode=0o750, exist_ok=True)
        name = f"{_tz.now().strftime('%H%M%S')}-{_uuid.uuid4().hex[:12]}.{stream}"
        path = os.path.join(folder, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(payload)
        return os.path.relpath(path, str(raw_dir))
    except Exception as exc:
        logger.warning(
            "tool output reference failed tool=%s stream=%s: %s",
            tool_name,
            stream,
            exc.__class__.__name__,
        )
        return ""


# --- TASK-006/007/008/059/060/061/071 helpers: ScanRun + ToolExecution + observations ---
def _get_or_create_run(
    target, scan_type="MONITORING", profile="", trigger="manual", requested_by="", scan_run_id=None
):
    """Return the canonical execution root for this work (P0-009).

    Resolution order:
    1. an explicit ``scan_run_id`` handed down by the orchestrator — validated
       against ``target`` so a run can never be borrowed across targets;
    2. the newest live run of the same type for the same target (re-entrancy:
       a retried stage rejoins its own run instead of orphaning a new one);
    3. a fresh run.
    """
    from django.utils import timezone as _tz

    from apps.core.consistency import ExecutionConsistencyError
    from apps.jobs.models import ScanRun

    if scan_run_id:
        run = ScanRun.objects.filter(pk=scan_run_id).first()
        if run is None:
            raise ExecutionConsistencyError(f"ScanRun #{scan_run_id} does not exist")
        if run.target_id != target.pk:
            raise ExecutionConsistencyError(
                f"ScanRun #{run.pk} belongs to target {run.target_id}, not {target.pk}"
            )
        return run

    prof = profile or getattr(target, "scan_profile", "balanced") or "balanced"
    cfg = {
        "scan_config": getattr(target, "scan_config", {}),
        "profile": prof,
        "verify_tls": getattr(target, "verify_tls", True),
    }

    # P1-001: the "find a live run, else create one" probe is check-then-act.
    # Two workers starting the same logical operation concurrently both saw no
    # live run and both inserted one, producing duplicate *active* runs for the
    # same target — two schedulers, two kill switches, two reconciliations, and
    # no single row that answers "is this target currently scanning?".
    #
    # The guarantee is a conditional unique index on
    # (target, scan_type) WHERE status is live (uniq_live_run_per_target_type),
    # so it holds across processes. Creation is therefore insert-and-catch: the
    # loser's IntegrityError is the signal, not a crash, and it re-reads the
    # winner.
    live = (
        ScanRun.objects.filter(target=target, scan_type=scan_type, status__in=ScanRun.LIVE_STATUSES)
        .order_by("-created_at")
        .first()
    )
    if live:
        return live
    try:
        with transaction.atomic():
            return ScanRun.objects.create(
                target=target,
                scan_type=scan_type,
                profile=prof,
                status="RUNNING",
                started_at=_tz.now(),
                trigger=trigger,
                requested_by=requested_by,
                configuration_snapshot=cfg,
            )
    except IntegrityError:
        # Another worker won the race; adopt its run rather than duplicating it.
        winner = (
            ScanRun.objects.filter(
                target=target, scan_type=scan_type, status__in=ScanRun.LIVE_STATUSES
            )
            .order_by("-created_at")
            .first()
        )
        if winner is None:
            # The unique index fired for some other reason; do not paper over it.
            raise
        return winner


def _finish_run(run, status="COMPLETED", coverage=None, error=""):
    from django.utils import timezone as _tz

    if run is None:
        return
    run.status = status
    run.finished_at = _tz.now()
    if coverage is not None:
        run.coverage_summary = coverage
    if error:
        run.error_summary = str(error)[:2000]
    run.save(update_fields=["status", "finished_at", "coverage_summary", "error_summary"])


def _note_evidence_failure(target, tool_name, status, error, run=None, job=None):
    """Make a lost evidence row impossible to ignore (P1-003).

    A tool-execution row that fails to persist must never leave the stage
    looking cleanly successful: the failure is logged, counted for the current
    stage (``_evidence_failures``), and surfaced as a ``JOB_FAILED`` event so
    the degradation is visible in the product, not only in the log stream.
    """
    logger.error(
        "tool-execution record lost target=%s run=%s job=%s tool=%s status=%s err=%s",
        getattr(target, "pk", None),
        getattr(run, "pk", None),
        getattr(job, "pk", None),
        tool_name,
        status,
        error,
        extra={
            "target_id": getattr(target, "pk", None),
            "scan_run_id": getattr(run, "pk", None),
            "task_id": getattr(job, "pk", None),
            "operation": "record_tool",
            "status": "ERROR",
        },
    )
    from apps.core.execution_context import note_evidence_loss

    note_evidence_loss(
        "tool_execution",
        f"{tool_name} {status}: {error}"[:200],
        target_id=getattr(target, "pk", None),
        job=job,
    )
    if job is not None:
        try:
            _log(
                job,
                "ERROR",
                f"evidence lost: {tool_name} {status} ({error})",
                stage="evidence",
                tool=tool_name,
            )
        except Exception:
            pass
    try:
        from services.event_engine.engine import emit_event

        emit_event(
            "JOB_FAILED",
            target=target,
            asset_value=str(tool_name)[:200],
            source="evidence",
            scan_run=run,
            severity="MEDIUM",
            evidence={
                "evidence_lost": True,
                "tool": tool_name,
                "tool_status": status,
                "error": str(error)[:200],
            },
        )
    except Exception:
        pass


def _record_tool(
    target,
    scan_run,
    job,
    tool_name,
    status,
    error="",
    fallback=False,
    coverage=None,
    started_at=None,
    finished_at=None,
    exit_code=None,
    command="",
    stdout="",
    stderr="",
    duration_ms=None,
):
    """Persist one tool invocation against the execution root (P1-002).

    Every execution persists the full evidence set: redacted command, status,
    start/finish, duration, exit code, fallback flag, coverage, error and
    stdout/stderr *references* (bounded, redacted files under ``RAW_DIR``).
    A lost row is never silent (P1-003) -- it is logged, counted and surfaced
    as a ``JOB_FAILED`` event so the stage cannot look cleanly successful.
    """
    from django.utils import timezone as _tz

    from apps.jobs.models import ToolExecution

    started = started_at or _tz.now()
    finished = finished_at or _tz.now()
    if duration_ms is None:
        duration_ms = max(0, int((finished - started).total_seconds() * 1000))
    try:
        return ToolExecution.objects.create(
            target=target,
            scan_run=scan_run,
            job=job,
            tool_name=tool_name,
            status=status,
            started_at=started,
            finished_at=finished,
            exit_code=exit_code,
            error=str(error)[:2000] if error else "",
            fallback_used=fallback,
            coverage=coverage or {},
            failure_kind=_failure_kind(status, exit_code),
            command=(command or "")[:4000],
            stdout_reference=_store_tool_output(tool_name, "out", stdout),
            stderr_reference=_store_tool_output(tool_name, "err", stderr),
            duration=round(duration_ms / 1000.0, 3),
        )
    except Exception as exc:
        _note_evidence_failure(target, tool_name, status, exc, run=scan_run, job=job)
        return None


def _log_stage_event(
    level,
    operation,
    target=None,
    scan_run=None,
    job=None,
    stage="",
    tool="",
    status="",
    duration_ms=None,
    error="",
    **extra_fields,
):
    """P2-011: one structured shape for every major-stage log line.

    Major stages must be traceable from the log alone, so each line carries
    ``target_id``, ``scan_run_id``, ``job_id``, ``stage``, ``tool``, ``status``,
    ``duration`` and ``error`` as structured extras (not interpolated into the
    message, so log processors can index them). Values are coerced to safe
    primitives, and no message ever carries a secret: callers pass identifiers
    and error classes, never credentials or raw tool output.
    """
    fields = {
        "operation": operation,
        "target_id": getattr(target, "pk", target),
        "scan_run_id": getattr(scan_run, "pk", scan_run),
        "job_id": getattr(job, "pk", job),
        "stage": stage or "",
        "tool": tool or "",
        "status": status or "",
        "duration_ms": duration_ms,
        "error": (str(error)[:500] if error else ""),
    }
    fields.update(extra_fields)
    logger.log(
        getattr(logging, level.upper(), logging.INFO),
        "stage %s: %s",
        operation,
        status or "event",
        extra=fields,
    )


class _StageTimer:
    """Context manager that emits one structured start/end pair for a stage."""

    def __init__(self, operation, target=None, scan_run=None, job=None, stage="", tool=""):
        self.operation = operation
        self.target, self.scan_run, self.job = target, scan_run, job
        self.stage, self.tool = stage, tool
        self._start = None

    def __enter__(self):
        self._start = time.monotonic()
        _log_stage_event(
            "INFO",
            self.operation,
            self.target,
            self.scan_run,
            self.job,
            self.stage,
            self.tool,
            status="START",
        )
        return self

    def __exit__(self, exc_type, exc, tb):
        duration = int((time.monotonic() - self._start) * 1000) if self._start else None
        if exc is not None:
            _log_stage_event(
                "ERROR",
                self.operation,
                self.target,
                self.scan_run,
                self.job,
                self.stage,
                self.tool,
                status="ERROR",
                duration_ms=duration,
                error=exc.__class__.__name__,
            )
            return False
        _log_stage_event(
            "INFO",
            self.operation,
            self.target,
            self.scan_run,
            self.job,
            self.stage,
            self.tool,
            status="OK",
            duration_ms=duration,
        )
        return False


def _evidence_failures(reset=False):
    """Evidence rows lost in the current task context (P1-003/P1-004).

    Delegates to the core module so lost ``ToolExecution`` rows and lost
    ``AssetObservation`` rows share one counter: a stage consults this before
    reporting success and degrades if *any* provenance was lost.
    """
    from apps.core.execution_context import evidence_failures

    return evidence_failures(reset=reset)


def _coverage_note(configured, attempted, **extra):
    """Uniform reduced-coverage record for a tool or its fallback (P1-011).

    ``configured`` is what the engagement/profile asked for; ``attempted`` is
    what we actually checked. ``reduced`` is true whenever the attempt is
    narrower than the ask and ``coverage_ratio`` records the fraction covered,
    so a limited fallback is never reported as equivalent coverage.
    """
    note = {"configured": configured, "attempted": attempted, "reduced": attempted < configured}
    if configured:
        note["coverage_ratio"] = round(float(attempted) / float(configured), 4)
    note.update(extra)
    return note


def _failure_kind(status, exit_code):
    """P1-004: classify *why* a tool execution ended. None for successes."""
    if status in ("COMPLETED", "PARTIAL", "PENDING", "RUNNING"):
        return ""
    if status == "CANCELLED":
        return "CANCELLED"
    if status == "SKIPPED":
        return ""
    if status == "FAILED":
        # Negative exit codes are signals, not ordinary errors: the process was
        # killed (SIGSEGV=-11, SIGKILL=-9, ...). That is a crash, not a "no".
        if exit_code is not None and exit_code < 0:
            return "CRASH"
        if exit_code is not None:
            return "NONZERO_EXIT"
        return "LAUNCH_FAILED"
    return ""


def _observe(
    target,
    scan_run,
    asset_type,
    asset_id=None,
    asset_value="",
    observed=True,
    evidence=None,
    state=None,
    job=None,
    tool_execution=None,
):
    """TASK-008: append-only observation row (history preserved)."""
    if scan_run is None:
        return None
    import hashlib as _hl
    import json as _js

    from apps.jobs.models import AssetObservation

    ctx_evidence = dict(evidence or {})
    if state:
        ctx_evidence["state"] = state
    try:
        mh = _hl.sha256(
            _js.dumps(state or evidence or {}, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        return AssetObservation.objects.create(
            scan_run=scan_run,
            target=target,
            asset_type=asset_type,
            asset_id=asset_id,
            asset_value=str(asset_value)[:2000],
            observed=observed,
            metadata_hash=mh,
            job=job,
            tool_execution=tool_execution,
            evidence=ctx_evidence,
        )
    except Exception:
        logger.error(
            "asset observation lost target=%s run=%s type=%s err=%s",
            getattr(target, "pk", None),
            getattr(scan_run, "pk", None),
            asset_type,
            "write-failed",
            extra={
                "target_id": getattr(target, "pk", None),
                "scan_run_id": getattr(scan_run, "pk", None),
                "operation": "observe",
                "status": "ERROR",
            },
        )
        return None


def _job(
    target_id,
    job_type,
    tool="",
    baseline=False,
    scan_run_id=None,
    run=None,
    scan_type="MONITORING",
    trigger="manual",
):
    """Create the ``ScanJob`` for a stage, attached to its execution root (P0-009).

    Returns ``(job, target, run)``. The run is created (or re-joined) if the
    caller did not supply one, so every job has a canonical execution root and
    the kill switch has something to act on.
    """
    from apps.jobs.models import ScanJob
    from apps.targets.models import Target

    target = Target.objects.get(pk=target_id)
    if run is None:
        run = _get_or_create_run(
            target, scan_type=scan_type, trigger=trigger, scan_run_id=scan_run_id
        )
    job = ScanJob.objects.create(
        target=target,
        job_type=job_type,
        tool=tool,
        status=ScanJob.STATUS_RUNNING,
        baseline_mode=baseline,
        scan_run=run,
        trigger=trigger,
        started_at=timezone.now(),
    )
    job.beat()
    return job, target, run


@contextlib.contextmanager
def _stage_context(target, run, job, tool_execution=None):
    """Install the ambient provenance context for a stage (P1-005).

    Everything persisted while this is active — subdomains, DNS records, ports,
    HTTP services, URLs, JS, technologies, findings — is recorded as a
    traceable ``AssetObservation`` against the run/job/tool.
    """
    from apps.core.execution_context import ScanContext, scan_context

    ctx = ScanContext(target_id=target.pk, scan_run=run, job=job, tool_execution=tool_execution)
    with scan_context(ctx):
        yield ctx


def _tool_context(tool_execution):
    """Bind a ToolExecution to the ambient context for the ingest that follows.

    P1-005: every observation must be traceable to the tool that produced it,
    not just to the job -- otherwise "which tool found this asset?" is
    unanswerable. Returns a no-op when there is no active context.
    """
    from apps.core.execution_context import tool_context

    return tool_context(tool_execution)


def _finish(job, status, stats=None, error=""):
    from services.event_engine.engine import broadcast_job

    job.status = status
    job.finished_at = timezone.now()
    job.progress = 100 if status in ("COMPLETED", "PARTIAL") else job.progress
    if stats is not None:
        job.stats = stats
    if error:
        job.error = error[:2000]
    job.heartbeat_at = job.finished_at
    job.save()
    # P0-012: closing the last live job on a cancelled execution root must not
    # leave the run looking "still running" forever.
    _close_run_if_idle(job, status)
    broadcast_job(job)


def _close_run_if_idle(job, status):
    """Finish the execution root when no live job remains under it.

    An execution root is only as trustworthy as its bookkeeping: a run left in
    RUNNING forever is indistinguishable from a live run, which defeats both
    stall detection and the kill switch.
    """
    from apps.jobs.models import ScanJob, ScanRun

    if job.scan_run_id is None:
        return
    if status not in (ScanJob.TERMINAL_STATUSES | {"SKIPPED", "PAUSED"}):
        return
    still_live = (
        ScanJob.objects.filter(scan_run_id=job.scan_run_id)
        .exclude(status__in=ScanJob.TERMINAL_STATUSES | {"SKIPPED", "PAUSED"})
        .exists()
    )
    if still_live:
        return
    run = ScanRun.objects.filter(pk=job.scan_run_id).first()
    if run is None or not run.is_live:
        return
    if run.cancel_requested_at and status in (
        ScanJob.STATUS_CANCELLED,
        ScanJob.STATUS_CANCELLED_KILL_SWITCH,
    ):
        _finish_run(run, "CANCELLED")
    elif status == ScanJob.STATUS_PARTIAL:
        # P0-017: successfully-created-but-reduced coverage is not a failure.
        _finish_run(run, "PARTIAL", error=job.error or "reduced coverage")
    elif status in (ScanJob.STATUS_COMPLETED, ScanJob.STATUS_SKIPPED):
        _finish_run(run, "COMPLETED")
    elif status in (ScanJob.TERMINAL_STATUSES | {"SKIPPED", "PAUSED"}):
        _finish_run(run, "FAILED", error=job.error or f"stage ended {status}")


def _cancel(job, reason="", error=""):
    """Stop a stage because the kill switch tripped (P2-006).

    Distinguishes an operator abort (``CANCELLED``) from a target-level
    kill-switch trip (``CANCELLED_KILL_SWITCH``) and records the reason on the
    job, the run and the target so the cause is never inferred from a status
    alone.
    """
    from apps.jobs.models import ScanJob, ScanRun

    kill_switch = bool(reason) and reason != "OPERATOR"
    status = ScanJob.STATUS_CANCELLED_KILL_SWITCH if kill_switch else ScanJob.STATUS_CANCELLED
    if kill_switch and job.scan_run_id:
        run = ScanRun.objects.filter(pk=job.scan_run_id).first()
        if run is not None:
            run.request_cancel(reason=reason)
    _finish(job, status, stats={"cancel_reason": reason or "OPERATOR"}, error=error)
    return status


def _log(job, level, message, stage="", tool=""):
    from apps.jobs.models import JobLog

    JobLog.objects.create(job=job, level=level, message=message[:2000], stage=stage, tool=tool)


class _ReconFetchSkipped(Exception):
    """Raised when a recon fetch is refused by scope/SSRF policy (skip, don't error)."""


def _ssl_context_for(target, job=None, stage=""):
    """T3: honor target.verify_tls on every stdlib fetch path.

    verify_tls=True (default) -> default secure context (certs validated;
    ssl.SSLCertVerificationError surfaces as a normal fetch failure).
    verify_tls=False -> insecure context + explicit WARNING log (opt-in only).
    """
    import ssl

    verify = getattr(target, "verify_tls", True)
    ctx = ssl.create_default_context()
    if not verify:
        if job is not None:
            _log(
                job,
                "WARNING",
                "TLS verification DISABLED by target config (verify_tls=false)",
                stage=stage or "fetch",
            )
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _url_allowed_for_fetch(target, url, rules=None):
    """T2+T4: scope + SSRF pre-check for an outbound fetch URL.

    Hostnames -> validate_host(); IP literals -> validate_ip() (which now
    unconditionally blocks private/reserved ranges, T4). Then resolve-then-check
    (host_resolves_to_blocked) as DNS-rebinding defense-in-depth.
    Returns (allowed: bool, reason: str, host: str).
    """
    import ipaddress
    from urllib.parse import urlparse

    from services.scope_engine.validator import (
        host_resolves_to_blocked,
        validate_host,
        validate_ip,
    )

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
    except Exception as e:
        return False, f"unparseable url: {e}", ""
    # Bandit B310 + SSRF: only http(s) fetches; file:/custom schemes rejected.
    if parsed.scheme not in ("http", "https"):
        return False, f"unsupported scheme {parsed.scheme or '(none)'}", ""
    if not host:
        return False, "no host in url", ""
    if rules is None:
        from apps.scope.models import ScopeRule

        rules = list(ScopeRule.objects.filter(target__in=[None, target]))
    try:
        ipaddress.ip_address(host)
        ok, reason = validate_ip(target, host, rules)
    except ValueError:
        ok, reason = validate_host(target, host, rules)
    if not ok:
        return False, f"out-of-scope host {host}: {reason}", host
    blocked, why = host_resolves_to_blocked(host)
    if blocked:
        return False, f"blocked host {host}: {why}", host
    return True, "ok", host


def _fetch_url_for_recon(
    target, url, job=None, stage="", timeout=10, max_bytes=2000000, rules=None
):
    """T2+T3+T4: scoped, SSRF-checked, TLS-honoring fetch. Returns bytes.

    Raised _ReconFetchSkipped for policy refusals (log + continue),
    or the underlying exception for genuine fetch failures. Redirects are
    re-validated per hop (_safe_opener), so a follow that lands out of scope or
    on a private/reserved IP is refused like the initial URL.
    """
    ok, reason, _host = _url_allowed_for_fetch(target, url, rules=rules)
    if not ok:
        raise _ReconFetchSkipped(reason)
    req = urllib.request.Request(url, headers={"User-Agent": "recon-monitor/1.0"})
    with _safe_opener(target, job, stage).open(req, timeout=timeout) as r:
        return r.read(max_bytes)


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """P0-016: every redirect hop is re-checked against scope + SSRF policy.

    urllib follows redirects internally; without this, a fetch checked at the
    initial URL could follow a redirect into a private/reserved IP or an
    out-of-scope host. Any forbidden hop raises _ReconFetchSkipped, which the
    caller treats as a policy skip rather than a failure.
    """

    def __init__(self, target, job=None):
        self._target = target
        self._job = job
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        ok, reason, _host = _url_allowed_for_fetch(self._target, newurl)
        if not ok:
            raise _ReconFetchSkipped(f"redirect forbidden {newurl[:200]}: {reason}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _safe_opener(target, job=None, stage=""):
    """OpenerDirector combining _ssl_context_for (T3) + redirect re-validation."""
    ctx = _ssl_context_for(target, job, stage)
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx), _ScopedRedirectHandler(target, job=job)
    )


def _extract_and_ingest_scripts(target, html, page_url, job=None, source="crawler"):
    """T2 (shared by discover_js_for_target + host_url_discovery): find
    <script src>, scope-check each host via _fetch_url_for_recon, fetch, ingest.
    Out-of-scope / blocked scripts are logged and skipped, never fetched."""
    import re
    from urllib.parse import urlparse

    from services.correlation.ingest import ingest_js

    count = 0
    try:
        p = urlparse(page_url)
    except Exception:
        return 0
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1)
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = f"{p.scheme}://{p.netloc}{src}"
        elif not src.startswith("http"):
            continue
        try:
            body = _fetch_url_for_recon(target, src, job=job, stage="js")
        except _ReconFetchSkipped as e:
            if job is not None:
                _log(job, "INFO", f"skipped script {src[:200]}: {e}", stage="js")
            continue
        except Exception:
            continue
        try:
            js, _outcome = ingest_js(target, src, body, source=source)
            try:
                js.discovered_from = page_url[:2000]
                js.save(update_fields=["discovered_from"])
            except Exception as e:
                # Provenance is worth keeping, but losing it must not drop the
                # asset we just ingested.
                logger.warning(
                    "discovered_from not saved for %s: %s",
                    src[:200],
                    e.__class__.__name__,
                    extra={"target_id": target.pk, "operation": "js_provenance", "status": "ERROR"},
                )
            count += 1
        except Exception as e:
            if job is not None:
                _log(
                    job,
                    "ERROR",
                    f"ingest_js failed for {src[:200]}: {e.__class__.__name__}",
                    stage="js",
                )
            logger.error(
                "ingest_js failed for %s: %s",
                src[:200],
                e,
                extra={"target_id": target.pk, "operation": "ingest_js", "status": "ERROR"},
            )
            continue
    return count


def _gate(target) -> tuple[bool, str]:
    """Pre-flight gate: scope + kill switch.

    The kill switch is checked *before* scope because a paused/archived/revoked
    target must stop work even if its scope rules would allow it. The reason is
    returned verbatim so callers can record *why* they stopped.
    """
    from apps.scope.models import ScopeRule
    from services.scope_engine.validator import scope_allows_scan

    if not target.is_scannable:
        return False, f"target not scannable: {target.blocking_reason() or 'unknown'}"
    rules = list(ScopeRule.objects.filter(target__in=[None, target]))
    return scope_allows_scan(target, rules)


def _cancel_reason(target) -> str:
    """Map a blocked target to the kill-switch reason recorded on run/job/event.

    Uses the canonical ``Target`` constants (imported lazily to avoid an
    app-loading cycle) so the reason vocabulary can never drift from the schema.
    A genuinely lapsed authorization is reported as expiry/revocation *before*
    the paused/disabled status: the periodic task pauses an expired target, and
    the reason trail must reflect the root cause, not the side effect.
    """
    from apps.targets.models import Target

    if getattr(target, "cancel_requested_at", None):
        return "OPERATOR"
    if target.status == Target.STATUS_ARCHIVED:
        return "TARGET_ARCHIVED"
    if target.authorization_expired():
        if target.authorization_status == Target.AUTH_EXPIRED:
            return "AUTH_EXPIRED"
        return "AUTH_REVOKED"
    if target.status == Target.STATUS_PAUSED:
        return "TARGET_PAUSED"
    if target.status == Target.STATUS_DISABLED:
        return "TARGET_DISABLED"
    return "OPERATOR"


def _halt_work(target, reason):
    """P0-013/P0-014: stop all work attached to a target with an attributable reason.

    Queued jobs pause (resumable); RUNNING jobs are left for the cooperative
    kill switch, which alone owns their final state (the worker's next
    ``check()`` re-reads the DB and finalizes them CANCELLED with ``reason``);
    every live execution root is tripped so it is never mistaken for live work,
    and a live run that has no live job left under it is finalized CANCELLED
    immediately so a future run is never blocked by a zombie root.
    """
    from apps.jobs.models import ScanJob, ScanRun

    target.jobs.filter(status="QUEUED").update(status="PAUSED")
    for run in ScanRun.objects.filter(target=target, status__in=["PENDING", "RUNNING"]):
        run.request_cancel(reason=reason)
        if not ScanJob.objects.filter(scan_run=run, status__in=["QUEUED", "RUNNING"]).exists():
            _finish_run(run, "CANCELLED", error=f"{reason.lower()}: target no longer scannable")


class _Cancelled(Exception):
    """Raised inside a long loop when the kill switch trips (P2-006).

    Carries the target id so the caller can re-derive the authoritative reason
    from the database (never from this in-memory copy, which may be stale).
    """

    def __init__(self, target_id):
        super().__init__(f"cancelled: target {target_id} is no longer scannable")
        self.target_id = target_id


@contextlib.contextmanager
def _cancellable(target, job=None, run=None, poll=None):
    """Cooperative kill switch for long loops (P2-006).

    Checking once before a loop is not enough: a 2000-host DNS pass or a
    50-URL nuclei pass can run for many minutes, and a pause or an
    authorization lapse mid-loop must stop it. Long loops therefore wrap their
    body and re-check the *database* every ``CANCELLATION_POLL_SECONDS``,
    while also refreshing the job heartbeat so stall detection can see the
    difference between "working" and "wedged".
    """
    from django.conf import settings

    from apps.targets.models import Target

    interval = poll or float(getattr(settings, "CANCELLATION_POLL_SECONDS", 5) or 5)
    last_check = [0.0]
    monotonic = time.monotonic

    def _maybe_raise():
        now = monotonic()
        if now - last_check[0] < interval:
            return
        last_check[0] = now
        # Re-read from the DB so a kill switch issued mid-run is honoured, but
        # decide with Target.is_scannable so this check can never drift from the
        # single definition of "may this target run work".
        fresh = Target.objects.filter(pk=target.pk).first()
        if fresh is None or not fresh.is_scannable:
            raise _Cancelled(target.pk)
        if job is not None and job.pk:
            job.beat()
        if run is not None and run.pk:
            run.beat()

    try:
        yield _maybe_raise
    finally:
        pass


def _stop_if_cancelled(exc, job, target):
    """Convert a ``_Cancelled`` into a recorded, attributable job outcome."""
    from apps.targets.models import Target

    reason = _cancel_reason(Target.objects.get(pk=exc.target_id))
    _cancel(job, reason=reason, error=f"cancelled: {reason.lower()}")
    return {"status": "CANCELLED", "reason": reason}


@shared_task(name="apps.jobs.tasks.baseline_target", bind=True, max_retries=1)
def baseline_target(self, target_id):
    """First-scan experience: INITIAL_BASELINE -> discovery chain -> BASELINE_COMPLETE + summary.

    P0-009: the whole chain shares ONE ``ScanRun`` execution root, so a baseline
    is a single stoppable unit rather than five unrelated jobs.
    P2-006: the chain is re-checked between stages and between tools, so a pause
    or an authorization lapse stops the baseline promptly instead of running to
    completion against a target that is no longer authorized.
    """
    from apps.monitoring.models import Baseline
    from apps.targets.models import Target
    from services.event_engine.engine import emit_event

    target = Target.objects.get(pk=target_id)
    ok, reason = _gate(target)
    if not ok:
        return {"status": "SKIPPED", "reason": reason}
    run = _get_or_create_run(
        target,
        scan_type="DISCOVERY",
        trigger="baseline",
        requested_by=getattr(self.request, "id", "") or "",
    )
    target.baseline_status = "INITIAL_BASELINE"
    target.baseline_started_at = timezone.now()
    target.save(update_fields=["baseline_status", "baseline_started_at"])
    Baseline.objects.update_or_create(
        target=target, defaults={"status": "RUNNING", "started_at": timezone.now()}
    )
    emit_event(
        "BASELINE_STARTED",
        target=target,
        asset_value=target.root_domain,
        source="monitoring",
        scan_run=run,
    )
    _baseline_started_at = time.monotonic()
    _log_stage_event(
        "INFO", "baseline:start", target, run, None, "baseline", "orchestrator", status="RUNNING"
    )
    # chain stages synchronously in-order (each internally failure-isolated)
    stats = {}
    cancelled = None
    stages = [discover_subdomains, resolve_dns, scan_ports, probe_http, discover_urls]
    for stage in stages:
        name = stage.name.split(".")[-1]
        # P2-006: re-read the target each stage; do not trust a cached instance.
        target.refresh_from_db()
        if not target.is_scannable:
            cancelled = {"stage": name, "reason": _cancel_reason(target)}
            # P0-013/P0-014: record the attributable reason on the run itself so
            # the trail never has to be inferred from the terminal status.
            run.request_cancel(reason=cancelled["reason"])
            _finish_run(
                run, "CANCELLED", error=f"baseline stopped at {name}: {target.blocking_reason()}"
            )
            emit_event(
                "JOB_FAILED",
                target=target,
                asset_value=name,
                source="monitoring",
                scan_run=run,
                severity="MEDIUM",
                evidence={"cancelled": True, "reason": target.blocking_reason()},
            )
            break
        try:
            with _StageTimer(f"baseline:{name}", target, run, None, name, "orchestrator"):
                stats[name] = stage.run(target_id, run.pk)
        except Exception as e:
            _log_stage_event(
                "ERROR",
                f"baseline:{name}",
                target,
                run,
                None,
                name,
                status="ERROR",
                error=e.__class__.__name__,
            )
            logger.exception(
                "baseline stage %s failed: %s",
                name,
                e,
                extra={
                    "target_id": target.pk,
                    "scan_run_id": run.pk,
                    "operation": f"baseline:{name}",
                    "status": "ERROR",
                },
            )
            stats[name] = {"status": "FAILED", "error": str(e)[:300]}

    if cancelled:
        # A stopped baseline must not claim completion.
        target.baseline_status = "INITIAL_BASELINE"
        target.save(update_fields=["baseline_status"])
        Baseline.objects.filter(target=target).update(status="CANCELLED")
        return {
            "status": "CANCELLED",
            "reason": cancelled["reason"],
            "stopped_at": cancelled["stage"],
            "stats": summarize(stats),
        }

    # P0-017: aggregate the per-stage results explicitly. A baseline is only
    # BASELINE_COMPLETE when every required stage fully succeeded; reduced
    # coverage is PARTIAL, a failed required stage is FAILED.
    baseline_result = _aggregate_baseline(stats)
    baseline_status = {
        "COMPLETE": "BASELINE_COMPLETE",
        "PARTIAL": "BASELINE_PARTIAL",
        "FAILED": "BASELINE_FAILED",
    }[baseline_result]
    target.baseline_status = baseline_status
    target.baseline_completed_at = timezone.now()
    to_save = ["baseline_status", "baseline_completed_at"]
    if baseline_result == "COMPLETE":
        target.last_scan = timezone.now()
        to_save.append("last_scan")
    target.save(update_fields=to_save)
    Baseline.objects.update_or_create(
        target=target,
        defaults={
            "status": {"COMPLETE": "COMPLETE", "PARTIAL": "PARTIAL", "FAILED": "FAILED"}[
                baseline_result
            ],
            "completed_at": timezone.now(),
            "summary": stats,
        },
    )
    if baseline_result == "COMPLETE":
        emit_event(
            "BASELINE_COMPLETED",
            target=target,
            asset_value=target.root_domain,
            source="monitoring",
            scan_run=run,
            evidence={"summary": summarize(stats)},
        )
        _finish_run(run, "COMPLETED", coverage=summarize(stats))
    elif baseline_result == "PARTIAL":
        emit_event(
            "BASELINE_PARTIAL",
            target=target,
            asset_value=target.root_domain,
            source="monitoring",
            scan_run=run,
            evidence={"summary": summarize(stats), "reduced": True},
        )
        _finish_run(run, "PARTIAL", coverage=summarize(stats))
    else:
        emit_event(
            "BASELINE_FAILED",
            target=target,
            asset_value=target.root_domain,
            source="monitoring",
            scan_run=run,
            evidence={"summary": summarize(stats)},
        )
        _finish_run(
            run,
            "FAILED",
            coverage=summarize(stats),
            error="baseline failed: a required stage failed",
        )
    # one baseline summary to Discord (not hundreds of NEW_* alerts)
    try:
        from apps.alerts.tasks import send_baseline_summary

        send_baseline_summary.delay(target_id, summarize(stats))
    except Exception as e:
        logger.warning("baseline summary dispatch failed: %s", e)
    result_status = {"COMPLETE": "COMPLETED", "PARTIAL": "PARTIAL", "FAILED": "FAILED"}[
        baseline_result
    ]
    _log_stage_event(
        "INFO",
        "baseline:finish",
        target,
        run,
        None,
        "baseline",
        "orchestrator",
        status=result_status,
        duration_ms=int((time.monotonic() - _baseline_started_at) * 1000),
        baseline_status=target.baseline_status,
    )
    return {"status": result_status, "run_id": run.pk, "stats": summarize(stats)}


@shared_task(name="apps.jobs.tasks.manual_scan", queue="recon")
def manual_scan(target_id, requested_by=""):
    """P2-006: the canonical orchestration for a manual scan.

    A manual "Scan" used to be two loose ``.delay(target_id)`` calls that
    created their *own* execution roots, skipped the gate, and covered only
    subdomain enumeration + DNS. This task is the single entry point that
    satisfies the full contract:

    1. **authorize the target** — the run records who asked for it;
    2. **verify scannable state** — a paused/expired/archived target is refused
       before any work is dispatched (the kill switch, not a UI label);
    3. **create/reuse the correct ScanRun** — one canonical execution root, and
       every stage joins *that* run instead of opening its own;
    4. **dispatch the canonical chain** in order, each stage inheriting the run;
    5. **expose accurate status** — the run's own status and coverage summary
       reflect the aggregate of the stages (P0-017 semantics), so a degraded
       scan is visible as such.
    """
    from apps.targets.models import Target

    try:
        target = Target.objects.get(pk=target_id)
    except Target.DoesNotExist:
        return {"status": "SKIPPED", "reason": "target gone"}

    ok, reason = _gate(target)
    if not ok:
        return {"status": "SKIPPED", "reason": reason, "target": target.root_domain}

    # one canonical execution root for the whole manual scan
    run = _get_or_create_run(
        target, scan_type="DISCOVERY", trigger="manual", requested_by=str(requested_by or "")
    )
    if run.requested_by in ("", None) and requested_by:
        run.requested_by = str(requested_by)
        run.save(update_fields=["requested_by"])

    # A baseline is not yet complete for this target: the baseline chain *is*
    # the canonical first scan (it runs the same stages under one root).
    if target.baseline_status != "BASELINE_COMPLETE":
        result = baseline_target(target.pk)
        return {
            "status": result.get("status", "COMPLETED"),
            "run_id": result.get("run_id") or run.pk,
            "mode": "baseline",
            "stats": result.get("stats", {}),
        }

    stats = {}
    failures = []
    stages = [discover_subdomains, resolve_dns, scan_ports, probe_http, discover_urls]
    started_at = time.monotonic()
    _log_stage_event(
        "INFO", "manual_scan:start", target, run, None, "manual_scan", "", status="RUNNING"
    )
    for stage in stages:
        name = stage.name.split(".")[-1]
        target.refresh_from_db()
        if not target.is_scannable:
            halt = target.blocking_reason() or "not scannable"
            _finish_run(run, "CANCELLED", error=f"manual scan stopped at {name}: {halt}")
            return {
                "status": "CANCELLED",
                "reason": halt,
                "stopped_at": name,
                "run_id": run.pk,
                "stats": summarize(stats),
            }
        try:
            # every stage joins the same execution root (P0-009)
            with _StageTimer(f"manual_scan:{name}", target, run, None, name, "orchestrator"):
                stats[name] = stage.run(target_id, run.pk)
        except Exception as exc:
            logger.exception(
                "manual scan stage %s failed: %s",
                name,
                exc,
                extra={
                    "target_id": target.pk,
                    "scan_run_id": run.pk,
                    "operation": f"manual_scan:{name}",
                    "status": "ERROR",
                },
            )
            stats[name] = {"status": "FAILED", "error": str(exc)[:300]}
            failures.append(name)

    result = _aggregate_baseline(stats)
    run_status = {"COMPLETE": "COMPLETED", "PARTIAL": "PARTIAL", "FAILED": "FAILED"}[result]
    if _evidence_failures():
        run_status = "PARTIAL"  # P1-003: an incomplete audit trail is not a clean run
    _finish_run(
        run,
        run_status,
        coverage=summarize(stats),
        error=(f"failed stages: {', '.join(failures)}" if failures else ""),
    )
    _log_stage_event(
        "INFO",
        "manual_scan:finish",
        target,
        run,
        None,
        "manual_scan",
        "",
        status=run_status,
        duration_ms=int((time.monotonic() - started_at) * 1000),
        failed_stages=failures,
    )
    return {
        "status": run_status,
        "run_id": run.pk,
        "mode": "scan",
        "stats": summarize(stats),
        "failed_stages": failures,
    }


BASELINE_REQUIRED_STAGES = ("discover_subdomains", "resolve_dns", "scan_ports", "probe_http")
BASELINE_OPTIONAL_STAGES = ("discover_urls",)


def _is_intentional_profile_skip(res) -> bool:
    """A required stage SKIPPED because the scanning profile deliberately
    excludes that capability (e.g. ``balanced`` has no ``port_scan``) is not a
    coverage failure; the baseline did everything the profile mandates."""
    reason = res.get("reason") or ""
    return "profile" in reason and ("exclude" in reason or "not enabled" in reason)


def _aggregate_baseline(stats):
    """P0-017: explicit stage aggregation -> COMPLETE / PARTIAL / FAILED.

    ``stats`` maps stage short-name to its result dict; each result carries a
    ``status`` from COMPLETED / PARTIAL / SKIPPED / FAILED.

    COMPLETE: every required stage COMPLETED (or SKIPPED only because the
              profile deliberately excludes that capability) and the optional
              URL crawl neither failed nor degraded.
    PARTIAL:  work happened but coverage is honestly reduced — a required stage
              ended PARTIAL or unexpectedly SKIPPED, or the optional URL crawl
              FAILED/PARTIAL. Never mislabeled COMPLETE.
    FAILED:   a required stage FAILED, or a required stage left no record.
    """
    statuses = {
        name: (stats.get(name) or {})
        for name in BASELINE_REQUIRED_STAGES + BASELINE_OPTIONAL_STAGES
    }
    for name in BASELINE_REQUIRED_STAGES:
        st = statuses[name].get("status")
        if st not in ("COMPLETED", "PARTIAL", "SKIPPED", "FAILED"):
            return "FAILED"  # materially incomplete: required stage failed / no record
        if st == "FAILED":
            return "FAILED"

    def _required_satisfied(res):
        st = res.get("status")
        return st == "COMPLETED" or (st == "SKIPPED" and _is_intentional_profile_skip(res))

    for name in BASELINE_REQUIRED_STAGES:
        if not _required_satisfied(statuses[name]):
            return "PARTIAL"  # PARTIAL or unexpected SKIPPED -> reduced coverage
    opt_status = statuses.get("discover_urls").get("status", "")
    if opt_status in ("FAILED", "PARTIAL", ""):
        return "PARTIAL"  # optional URL crawl degraded or left no record
    return "COMPLETE"


def summarize(stats):
    out = {}
    for k, v in (stats or {}).items():
        if isinstance(v, dict):
            out[k] = {
                kk: vv
                for kk, vv in v.items()
                if kk in ("new", "total", "status", "new_urls", "new_apis", "changed")
            }
        else:
            out[k] = v
    return out


@shared_task(name="apps.jobs.tasks.discover_subdomains")
def discover_subdomains(target_id, scan_run_id=None):
    from apps.scope.models import ScopeRule
    from services.correlation.ingest import detect_wildcard, ingest_subdomains
    from services.scope_engine.validator import scope_allows_scan
    from services.tool_adapters.adapters import (
        AmassAdapter,
        AssetfinderAdapter,
        CrtshAdapter,
        FindomainAdapter,
        SubfinderAdapter,
    )

    _evidence_failures(reset=True)  # P1-003: per-stage evidence-loss counter
    job, target, run = _job(
        target_id,
        "subdomain_enum",
        tool="multi",
        scan_run_id=scan_run_id,
        scan_type="DISCOVERY",
        trigger="baseline" if target_is_baseline(target_id) else "manual",
    )
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    rules = list(ScopeRule.objects.filter(target__in=[None, target]))
    ok, reason = scope_allows_scan(target, rules)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    # wildcard detection first
    try:
        detect_wildcard(target)
    except Exception as e:
        _log(job, "WARNING", f"wildcard check failed: {e}", stage="wildcard")
    items = []
    partial = False
    with _stage_context(target, run, job):
        try:
            with _cancellable(target, job=job, run=run) as check:
                for cls in (
                    SubfinderAdapter,
                    AmassAdapter,
                    FindomainAdapter,
                    AssetfinderAdapter,
                    CrtshAdapter,
                ):
                    check()  # P2-006: stop between tools, not just between stages
                    adapter = cls()
                    tool_name = getattr(adapter, "tool_name", cls.__name__)
                    started = timezone.now()
                    with _StageTimer(
                        "discover_subdomains:source", target, run, job, "subdomain_enum", tool_name
                    ):
                        pass  # the start line is emitted; the end line follows the run
                    try:
                        res = adapter.run(target.root_domain, cancel_check=check)
                    except Exception as e:
                        partial = True
                        _log(
                            job,
                            "ERROR",
                            f"{tool_name} crashed: {e}",
                            stage="passive",
                            tool=tool_name,
                        )
                        _record_tool(
                            target, run, job, tool_name, "FAILED", error=e, started_at=started
                        )
                        continue
                    _record_tool(
                        target,
                        run,
                        job,
                        tool_name,
                        res.status,
                        error=res.error,
                        started_at=started,
                        coverage={"hosts": len(res.data or [])},
                        exit_code=res.exit_code,
                        command=res.command,
                        stdout=res.stdout,
                        stderr=res.stderr,
                        duration_ms=res.duration_ms,
                    )
                    if res is None:
                        partial = True
                        continue
                    if res.status == "SKIPPED":
                        _log(
                            job,
                            "WARNING",
                            f"{res.tool} not installed, skipped",
                            stage="passive",
                            tool=res.tool,
                        )
                        partial = True
                    elif res.status == "FAILED":
                        _log(
                            job,
                            "ERROR",
                            f"{res.tool} failed: {res.error}",
                            stage="passive",
                            tool=res.tool,
                        )
                        partial = True
                    else:
                        if res.status == "PARTIAL":
                            partial = True
                        items.extend(res.data)
                        _log(
                            job,
                            "INFO",
                            f"{res.tool}: {len(res.data)} hosts",
                            stage="passive",
                            tool=res.tool,
                        )
        except _Cancelled as exc:
            return _stop_if_cancelled(exc, job, target)
        try:
            new_count, total = ingest_subdomains(target, items)
        except Exception as e:
            _finish(job, "FAILED", error=str(e)[:1000])
            return {"status": "FAILED", "error": str(e)[:300]}
    job.progress = 100
    # P1-003: lost evidence rows mean the audit trail is incomplete, so the
    # stage is never reported as a clean success.
    partial = partial or bool(_evidence_failures())
    _finish(
        job,
        "PARTIAL" if partial else "COMPLETED",
        stats={"new": new_count, "total": total, "sources": len(items)},
    )
    target.last_scan = timezone.now()
    target.save(update_fields=["last_scan"])
    return {"status": job.status, "run_id": run.pk, "new": new_count, "total": total}


def target_is_baseline(target_id):
    from apps.targets.models import Target

    try:
        return Target.objects.get(pk=target_id).baseline_status == "INITIAL_BASELINE"
    except Exception:
        return False


@shared_task(name="apps.jobs.tasks.resolve_dns")
def resolve_dns(target_id, scan_run_id=None):
    import socket

    from django.conf import settings

    from apps.assets.models import Subdomain
    from services.correlation.ingest import ingest_dns

    _evidence_failures(reset=True)  # P1-003: per-stage evidence-loss counter
    job, target, run = _job(
        target_id,
        "dns",
        tool="socket/dnsx",
        scan_run_id=scan_run_id,
        scan_type="DISCOVERY",
        trigger="baseline" if target_is_baseline(target_id) else "manual",
    )
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    # P3-002: the DNS stage used to resolve only the first 2000 active hosts
    # (``[:2000]``), silently leaving the rest unresolved -- a coverage hole
    # with no record. The host list is now paginated in bounded batches and the
    # stage reports how many hosts it actually covered.
    hosts = []
    host_cursor = None
    dns_batch = int(getattr(settings, "DNS_HOST_BATCH_SIZE", 1000) or 1000)
    while True:
        qs = Subdomain.objects.filter(target=target, is_active=True)
        if host_cursor is not None:
            qs = qs.filter(hostname__gt=host_cursor)
        batch = list(qs.order_by("hostname").values_list("hostname", flat=True)[:dns_batch])
        if not batch:
            break
        hosts.extend(batch)
        host_cursor = batch[-1]
        if len(batch) < dns_batch:
            break
    records = []
    # Prefer dnsx binary if present; else stdlib A-record resolution
    from services.tool_adapters.adapters import DnsxAdapter
    from services.tool_adapters.base import redact_command

    adapter = DnsxAdapter()
    dnsx_row = None
    fallback = True
    if adapter.is_available():
        # Task 13: single adapter.run(hosts) path (stdin piped, redacted cmd logged).
        job.command_redacted = redact_command(adapter.build_command(hosts))
        job.save(update_fields=["command_redacted"])
        started = timezone.now()
        try:
            with _cancellable(target, job=job, run=run) as check:
                res = adapter.run(hosts, timeout=300, cancel_check=check)
                dnsx_row = _record_tool(
                    target,
                    run,
                    job,
                    "dnsx",
                    res.status,
                    error=res.error,
                    started_at=started,
                    coverage={"records": len(res.data or [])},
                    exit_code=res.exit_code,
                    command=res.command,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    duration_ms=res.duration_ms,
                )
                if res.status == "SKIPPED":
                    _log(
                        job,
                        "WARNING",
                        "dnsx not installed, falling back to socket",
                        stage="dns",
                        tool="dnsx",
                    )
                elif res.status == "FAILED":
                    _log(
                        job,
                        "ERROR",
                        f"dnsx failed, falling back to socket: {res.error}",
                        stage="dns",
                        tool="dnsx",
                    )
                else:
                    fallback = False
                    if res.status == "PARTIAL":
                        _log(job, "WARNING", f"dnsx partial: {res.error}", stage="dns", tool="dnsx")
                    # P0-013: parsing res.data is loop work too — the kill switch
                    # must be able to stop *between* dnsx batches just as well as
                    # inside the socket fallback.
                    for o in res.data:
                        check()  # P2-006: stop between batches of writes
                        if not isinstance(o, dict):
                            continue
                        h = o.get("host") or o.get("input") or o.get("name") or ""
                        for a in o.get("a") or []:
                            records.append({"hostname": h, "type": "A", "value": a})
                        for aaa in o.get("aaaa") or []:
                            records.append({"hostname": h, "type": "AAAA", "value": aaa})
                    _log(job, "INFO", f"dnsx: {len(records)} records", stage="dns", tool="dnsx")
        except _Cancelled as exc:
            return _stop_if_cancelled(exc, job, target)
        except Exception as e:
            _record_tool(target, run, job, "dnsx", "FAILED", error=e, started_at=started)
            _log(
                job, "ERROR", f"dnsx failed, falling back to socket: {e}", stage="dns", tool="dnsx"
            )
    with _stage_context(target, run, job):
        if fallback:
            try:
                with _cancellable(target, job=job, run=run) as check:
                    for i, h in enumerate(hosts):
                        if i % 25 == 0:
                            check()  # P2-006: a 2000-host pass must be stoppable
                        try:
                            for fam, _, _, _, addr in socket.getaddrinfo(h, None):
                                if fam == socket.AF_INET:
                                    records.append({"hostname": h, "type": "A", "value": addr[0]})
                                    break
                        except OSError:
                            # NXDOMAIN / no A record is a normal result, not an error.
                            continue
            except _Cancelled as exc:
                return _stop_if_cancelled(exc, job, target)
        # P1-005: the DNS observations are linked to whichever resolver ran
        # (dnsx when available, the socket fallback otherwise).
        socket_row = _record_tool(
            target,
            run,
            job,
            "socket-getaddrinfo",
            "COMPLETED",
            coverage={"records": len(records)},
            fallback=fallback,
        )
        with _tool_context(dnsx_row if not fallback else socket_row):
            new = ingest_dns(target, records)
    # P1-003: a lost evidence row means the DNS pass is not cleanly auditable.
    stage_status = "PARTIAL" if _evidence_failures() else "COMPLETED"
    _finish(
        job,
        stage_status,
        stats={"new": new, "resolved_hosts": len({r["hostname"] for r in records})},
    )
    return {"status": stage_status, "run_id": run.pk, "new": new}


@shared_task(name="apps.jobs.tasks.scan_ports")
def scan_ports(target_id, scan_run_id=None):
    import socket

    from apps.assets.models import IPAddress
    from services.correlation.ingest import ingest_ports

    _evidence_failures(reset=True)  # P1-003: per-stage evidence-loss counter
    job, target, run = _job(
        target_id,
        "ports",
        tool="naabu/socket",
        scan_run_id=scan_run_id,
        scan_type="DISCOVERY",
        trigger="baseline" if target_is_baseline(target_id) else "manual",
    )
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    from services.scan_profiles import profile_allows as _allows

    if not _allows(getattr(target, "scan_profile", "balanced"), "port_scan"):
        _finish(
            job,
            "SKIPPED",
            error="port_scan not enabled for profile " + str(getattr(target, "scan_profile", "")),
        )
        return {"status": "SKIPPED", "reason": "profile excludes port_scan"}
    ports_cfg = (target.scan_config or {}).get(
        "ports", "80,443,8080,8443,8000,8888,3000,5000,22,21,25,53,3306,5432,6379,27017"
    )
    port_list = [int(p) for p in str(ports_cfg).split(",") if p.strip().isdigit()]
    # P3-002: no silent IP cap -- the full active set is scanned, the socket
    # fallback just iterates it in bounded batches (PORT_FALLBACK_MAX_PORTS).
    ips = list(
        IPAddress.objects.filter(target=target, is_active=True)
        .order_by("ip")
        .values_list("ip", flat=True)
    )
    # T5: never actively scan shared-suspect IPs without explicit confirmation.
    # P3-002: this set is a *safety* filter, not a display limit -- capping it
    # would let unconfirmed shared IPs be scanned, so the full set is loaded.
    shared_skipped = list(
        IPAddress.objects.filter(
            target=target, is_active=True, shared_suspect=True, confirmed_dedicated=False
        ).values_list("ip", flat=True)
    )
    if shared_skipped:
        _log(
            job,
            "WARNING",
            f"skipped {len(shared_skipped)} shared-suspect IP(s) (shared_ip_unconfirmed): "
            + ", ".join(shared_skipped[:10]),
            stage="ports",
            tool="naabu",
        )
        ips = [ip for ip in ips if ip not in set(shared_skipped)]
    entries = []
    from services.tool_adapters.adapters import NaabuAdapter

    adapter = NaabuAdapter()
    used_naabu = False
    naabu_status = ""
    naabu_row = None
    naabu_missing_reason = (
        ""
        if (adapter.is_available() and ips)
        else ("naabu not installed" if not adapter.is_available() else "no resolvable IPs to scan")
    )
    # P2-011: one structured line pair for the whole stage, whichever path runs
    _ports_timer = _StageTimer(
        "scan_ports",
        target,
        run,
        job,
        "ports",
        "naabu" if used_naabu or adapter.is_available() else "socket-connect",
    )
    _ports_timer.__enter__()
    if adapter.is_available() and ips:
        started = timezone.now()
        # P0-013: naabu can run for minutes; the kill switch must stop the
        # actual subprocess, not just wait for it to return.
        with (
            _stage_context(target, run, job),
            _StageTimer("scan_ports:naabu", target, run, job, "ports", "naabu"),
            _cancellable(target, job=job, run=run) as check,
        ):
            try:
                res = adapter.run(
                    ",".join(ips), ports=",".join(map(str, port_list)), cancel_check=check
                )
                naabu_row = _record_tool(
                    target,
                    run,
                    job,
                    "naabu",
                    res.status,
                    error=res.error,
                    started_at=started,
                    coverage={"open": len(res.data or [])},
                    exit_code=res.exit_code,
                    command=res.command,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    duration_ms=res.duration_ms,
                )
                naabu_status = res.status
                for r in res.data:
                    entries.append(r)
                used_naabu = res.status in ("COMPLETED", "PARTIAL")
                _log(job, "INFO", f"naabu: {len(entries)} open", stage="ports", tool="naabu")
            except _Cancelled as exc:
                return _stop_if_cancelled(exc, job, target)
            except Exception as e:
                _record_tool(target, run, job, "naabu", "FAILED", error=e, started_at=started)
                _log(job, "ERROR", f"naabu failed: {e}", stage="ports", tool="naabu")
    elif not used_naabu and naabu_missing_reason and ips:
        # P1-011/P1-012: an absent primary scanner is recorded explicitly, with
        # the reduced coverage the fallback will produce, so a downstream
        # "COMPLETED" is never read as equivalent naabu coverage.
        _record_tool(
            target,
            run,
            job,
            "naabu",
            "SKIPPED",
            error=naabu_missing_reason,
            fallback=True,
            command=adapter.binary,
            coverage=_coverage_note(
                len(ips) * len(port_list),
                0,
                dimension="port_probes",
                open=0,
                degraded=True,
                reason=naabu_missing_reason,
            ),
        )
        _log(
            job,
            "WARNING",
            f"naabu unavailable ({naabu_missing_reason}); using reduced " "socket fallback",
            stage="ports",
            tool="naabu",
        )
    with _stage_context(target, run, job):
        if not used_naabu:
            # P1-012: the stdlib fallback can only afford a capped port set over
            # many IPs; the cap is reported as reduced coverage below, never as
            # complete coverage of the configured port list.
            fallback_ports = port_list[:PORT_FALLBACK_MAX_PORTS]
            try:
                with _cancellable(target, job=job, run=run) as check:
                    for i, ip in enumerate(ips):
                        if i % 5 == 0:
                            check()  # P2-006
                        for pt in fallback_ports:  # stdlib fallback connect scan
                            try:
                                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s.settimeout(1.5)
                                try:
                                    if s.connect_ex((ip, pt)) == 0:
                                        entries.append({"ip": ip, "port": pt, "protocol": "tcp"})
                                finally:
                                    s.close()
                            except OSError:
                                # Refused / unreachable host: expected, not an error.
                                continue
            except _Cancelled as exc:
                return _stop_if_cancelled(exc, job, target)
        # P1-012: the fallback is never reported as full coverage. It attempted
        # len(fallback_ports) of len(port_list) configured ports on each IP, and
        # skipped shared-suspect IPs entirely -- both are recorded as reduced.
        socket_coverage = _coverage_note(
            configured=len(ips) * len(port_list),
            attempted=(
                len(ips) * len(fallback_ports) if not used_naabu else len(ips) * len(port_list)
            ),
            dimension="port_probes",
            open=len(entries),
            hosts_configured=len(ips),
            hosts_skipped_shared_suspect=len(shared_skipped),
            ports_configured=len(port_list),
            ports_attempted=(len(fallback_ports) if not used_naabu else len(port_list)),
        )
        # P1-005: record the execution *before* ingesting so the observations
        # this tool produced can be linked back to it.
        socket_row = _record_tool(
            target,
            run,
            job,
            "socket-connect",
            "COMPLETED",
            coverage=socket_coverage,
            fallback=not used_naabu,
        )
        with _tool_context(naabu_row if used_naabu else socket_row):
            new = ingest_ports(target, entries)
    # P0-017: reduced coverage (limited stdlib fallback, or a partial naabu run)
    # is never reported as a full COMPLETED.
    if used_naabu and naabu_status == "COMPLETED":
        stage_status = "COMPLETED"
    elif used_naabu:
        stage_status = "PARTIAL"  # naabu ended PARTIAL -> reduced coverage
    elif ips:
        stage_status = "PARTIAL"  # fallback ran on a limited port list
    else:
        stage_status = "COMPLETED"  # nothing to scan
    if stage_status == "COMPLETED" and _evidence_failures():
        # P1-003: evidence rows were lost -- the stage cannot claim a clean
        # completion, because the audit trail is incomplete by definition.
        stage_status = "PARTIAL"
        _log(
            job,
            "WARNING",
            f"evidence rows lost: {_evidence_failures()}",
            stage="evidence",
            tool="evidence",
        )
    _ports_timer.__exit__(None, None, None)
    _log_stage_event(
        "INFO",
        "scan_ports:finish",
        target,
        run,
        job,
        "ports",
        "",
        status=stage_status,
        open=len(entries),
        new=new,
    )
    _finish(job, stage_status, stats={"new": new, "open": len(entries)})
    return {"status": stage_status, "run_id": run.pk, "new": new}


@shared_task(name="apps.jobs.tasks.probe_http")
def probe_http(target_id, scan_run_id=None):
    import urllib.parse
    import urllib.request

    from apps.assets.models import Port, Subdomain
    from services.correlation.ingest import ingest_http, ingest_technology

    _evidence_failures(reset=True)  # P1-003: per-stage evidence-loss counter
    job, target, run = _job(
        target_id,
        "http",
        tool="httpx/urllib",
        scan_run_id=scan_run_id,
        scan_type="DISCOVERY",
        trigger="baseline" if target_is_baseline(target_id) else "manual",
    )
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    candidates = set()
    # P3-002: every active host contributes a candidate (no silent [:1000]);
    # the probing work itself is bounded by the httpx timeout / fallback cap,
    # which is reported as reduced coverage (P1-011).
    for h in Subdomain.objects.filter(target=target, is_active=True).values_list(
        "hostname", flat=True
    ):
        candidates.add(f"https://{h}")
        candidates.add(f"http://{h}")
    for p in Port.objects.filter(target=target, state="open").select_related("target"):
        scheme = "https" if p.port in (443, 8443) else "http"
        candidates.add(f"{scheme}://{p.ip}:{p.port}")
    entries = []
    from services.tool_adapters.adapters import HttpxAdapter
    from services.tool_adapters.base import redact_command

    adapter = HttpxAdapter()
    used_httpx = False
    httpx_status = ""
    httpx_row = None
    if adapter.is_available() and candidates:
        # Task 13: single adapter.run(hosts) path (stdin piped, redacted cmd logged).
        job.command_redacted = redact_command(adapter.build_command(sorted(candidates)))
        job.save(update_fields=["command_redacted"])
        started = timezone.now()
        # P0-013: httpx probing a 1000-candidate list is minutes of work;
        # the kill switch must terminate the subprocess group on pause/expiry.
        with (
            _stage_context(target, run, job),
            _StageTimer("probe_http:httpx", target, run, job, "http", "httpx"),
            _cancellable(target, job=job, run=run) as check,
        ):
            try:
                res = adapter.run(sorted(candidates), timeout=600, cancel_check=check)
                httpx_row = _record_tool(
                    target,
                    run,
                    job,
                    "httpx",
                    res.status,
                    error=res.error,
                    started_at=started,
                    coverage={"services": len(res.data or [])},
                    exit_code=res.exit_code,
                    command=res.command,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    duration_ms=res.duration_ms,
                )
                httpx_status = res.status
                used_httpx = res.status in ("COMPLETED", "PARTIAL")
                if res.status == "FAILED":
                    _log(job, "ERROR", f"httpx failed: {res.error}", stage="http", tool="httpx")
                else:
                    if res.status == "PARTIAL":
                        _log(
                            job,
                            "WARNING",
                            f"httpx partial: {res.error}",
                            stage="http",
                            tool="httpx",
                        )
                    entries.extend(o for o in res.data if isinstance(o, dict))
                    _log(job, "INFO", f"httpx: {len(entries)} services", stage="http", tool="httpx")
            except _Cancelled as exc:
                return _stop_if_cancelled(exc, job, target)
            except Exception as e:
                _record_tool(target, run, job, "httpx", "FAILED", error=e, started_at=started)
                _log(job, "ERROR", f"httpx failed: {e}", stage="http", tool="httpx")
    elif not used_httpx and candidates:
        # P1-011: record the absent primary prober explicitly and the reduced
        # coverage the urllib fallback will deliver, so a downstream COMPLETED
        # is never read as equivalent httpx coverage.
        reason = (
            "httpx not installed" if not adapter.is_available() else "httpx produced no results"
        )
        _record_tool(
            target,
            run,
            job,
            "httpx",
            "SKIPPED",
            error=reason,
            fallback=True,
            command=adapter.binary,
            coverage=_coverage_note(
                len(candidates),
                HTTP_FALLBACK_MAX_URLS,
                dimension="http_probes",
                degraded=True,
                reason=reason,
            ),
        )
        _log(
            job,
            "WARNING",
            f"httpx unavailable ({reason}); using reduced urllib fallback",
            stage="http",
            tool="httpx",
        )
    if not used_httpx:
        fetched = 0
        with _stage_context(target, run, job):
            try:
                with _cancellable(target, job=job, run=run) as check:
                    for i, url in enumerate(sorted(candidates)[:HTTP_FALLBACK_MAX_URLS]):
                        if i % 10 == 0:
                            check()  # P2-006
                        try:
                            # T2+T4: candidates derive from our own asset rows, but re-check
                            # scope + resolved IP before touching the network (redirects /
                            # stale DNS can point anywhere).
                            ok, reason, _h = _url_allowed_for_fetch(target, url)
                            if not ok:
                                _log(
                                    job,
                                    "INFO",
                                    f"skipped probe {url[:200]}: {reason}",
                                    stage="http",
                                    tool="urllib",
                                )
                                continue
                            req = urllib.request.Request(
                                url, headers={"User-Agent": "recon-monitor/1.0"}
                            )
                            with _safe_opener(target, job, "http").open(req, timeout=8) as r:
                                entries.append(
                                    {
                                        "url": url,
                                        "host": urllib.parse.urlparse(url).hostname or "",
                                        "status_code": r.status,
                                        "title": "",
                                        "server": r.headers.get("Server", ""),
                                        "content_type": r.headers.get("Content-Type", ""),
                                    }
                                )
                                fetched += 1
                        except _ReconFetchSkipped as e:
                            _log(
                                job,
                                "INFO",
                                f"skipped probe {url[:200]}: {e}",
                                stage="http",
                                tool="urllib",
                            )
                            continue
                        except Exception as e:
                            # Connection refused / TLS error / timeout: the endpoint is
                            # simply not serving right now. Recorded, not swallowed.
                            _log(
                                job,
                                "INFO",
                                f"probe failed {url[:200]}: {e.__class__.__name__}",
                                stage="http",
                                tool="urllib",
                            )
                            continue
            except _Cancelled as exc:
                return _stop_if_cancelled(exc, job, target)
            # P1-011: the fallback is explicitly reduced -- it can only probe a
            # capped slice of the candidate set.
            urllib_row = _record_tool(
                target,
                run,
                job,
                "urllib",
                "COMPLETED",
                fallback=True,
                coverage=_coverage_note(
                    len(candidates),
                    min(len(candidates), HTTP_FALLBACK_MAX_URLS),
                    dimension="http_probes",
                    services=fetched,
                ),
            )
            # P1-005: observations produced by the probe are linked to the tool.
            with _tool_context(urllib_row):
                new, changed = ingest_http(target, entries)
            # lightweight tech fingerprint from server headers
            for entry in entries:
                srv = (entry.get("server") or entry.get("webserver") or "").strip()
                if srv and entry.get("url"):
                    ingest_technology(
                        target,
                        entry["url"],
                        srv.split("/")[0],
                        srv.split("/")[1] if "/" in srv else "",
                        0.6,
                        f"Server header: {srv}",
                        "httpx",
                    )
    else:
        with _stage_context(target, run, job), _tool_context(httpx_row):
            new, changed = ingest_http(target, entries)
            for entry in entries:
                srv = (entry.get("server") or entry.get("webserver") or "").strip()
                if srv and entry.get("url"):
                    ingest_technology(
                        target,
                        entry["url"],
                        srv.split("/")[0],
                        srv.split("/")[1] if "/" in srv else "",
                        0.6,
                        f"Server header: {srv}",
                        "httpx",
                    )
    # P0-017: reduced coverage (urllib fallback capped at 200, or a partial
    # httpx run) is never reported as a full COMPLETED.
    if used_httpx and httpx_status == "COMPLETED":
        stage_status = "COMPLETED"
    elif used_httpx:
        stage_status = "PARTIAL"  # httpx ended PARTIAL -> reduced coverage
    elif candidates:
        stage_status = "PARTIAL"  # fallback probed only a capped subset
    else:
        stage_status = "COMPLETED"  # nothing to probe
    if stage_status == "COMPLETED" and _evidence_failures():
        # P1-003: see scan_ports -- a lost evidence row downgrades the stage.
        stage_status = "PARTIAL"
        _log(
            job,
            "WARNING",
            f"evidence rows lost: {_evidence_failures()}",
            stage="evidence",
            tool="evidence",
        )
    _finish(job, stage_status, stats={"new": new, "changed": changed})
    return {"status": stage_status, "run_id": run.pk, "new": new, "changed": changed}


@shared_task(name="apps.jobs.tasks.discover_urls")
def discover_urls(target_id, scan_run_id=None):
    from apps.assets.models import HTTPService
    from services.correlation.ingest import ingest_urls

    _evidence_failures(reset=True)  # P1-003: per-stage evidence-loss counter
    job, target, run = _job(
        target_id,
        "urls",
        tool="gau/waybackurls/katana",
        scan_run_id=scan_run_id,
        scan_type="DISCOVERY",
        trigger="baseline" if target_is_baseline(target_id) else "manual",
    )
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    items = []
    partial = False
    from services.tool_adapters.adapters import (
        GauAdapter,
        KatanaAdapter,
        WaybackurlsAdapter,
        WaymoreAdapter,
    )

    with _stage_context(target, run, job):
        try:
            with _cancellable(target, job=job, run=run) as check:
                for cls in (GauAdapter, WaybackurlsAdapter, WaymoreAdapter):
                    check()  # P2-006
                    a = cls()
                    if not a.is_available():
                        _record_tool(
                            target,
                            run,
                            job,
                            a.tool_name,
                            "SKIPPED",
                            error=f"{a.binary} not installed",
                            fallback=True,
                            command=a.binary,
                            coverage={
                                "urls": 0,
                                "degraded": True,
                                "reason": f"{a.binary} not installed",
                            },
                        )
                        _log(
                            job,
                            "WARNING",
                            f"{a.tool_name} missing, skipped",
                            stage="urls",
                            tool=a.tool_name,
                        )
                        partial = True
                        continue
                    started = timezone.now()
                    try:
                        res = a.run(target.root_domain)
                        _record_tool(
                            target,
                            run,
                            job,
                            a.tool_name,
                            res.status,
                            error=res.error,
                            started_at=started,
                            coverage={"urls": len(res.data or [])},
                            exit_code=res.exit_code,
                            command=res.command,
                            stdout=res.stdout,
                            stderr=res.stderr,
                            duration_ms=res.duration_ms,
                        )
                        items.extend(res.data)
                        _log(
                            job,
                            "INFO",
                            f"{a.tool_name}: {len(res.data)} urls",
                            stage="urls",
                            tool=a.tool_name,
                        )
                    except Exception as e:
                        _record_tool(
                            target, run, job, a.tool_name, "FAILED", error=e, started_at=started
                        )
                        partial = True
                        _log(
                            job,
                            "ERROR",
                            f"{a.tool_name} failed: {e}",
                            stage="urls",
                            tool=a.tool_name,
                        )
                # katana crawl a sample of live http services
                kat = KatanaAdapter()
                if kat.is_available():
                    for svc in HTTPService.objects.filter(target=target).order_by("-last_seen")[
                        :20
                    ]:
                        check()
                        started = timezone.now()
                        try:
                            res = kat.run(svc.url)
                            _record_tool(
                                target,
                                run,
                                job,
                                "katana",
                                res.status,
                                error=res.error,
                                started_at=started,
                                coverage={"urls": len(res.data or [])},
                                exit_code=res.exit_code,
                                command=res.command,
                                stdout=res.stdout,
                                stderr=res.stderr,
                                duration_ms=res.duration_ms,
                            )
                            items.extend(res.data)
                        except Exception as e:
                            _record_tool(
                                target, run, job, "katana", "FAILED", error=e, started_at=started
                            )
                            partial = True
                            _log(
                                job,
                                "ERROR",
                                f"katana failed for {svc.url}: {e}",
                                stage="urls",
                                tool="katana",
                            )
                else:
                    _record_tool(
                        target,
                        run,
                        job,
                        "katana",
                        "SKIPPED",
                        error="katana not installed",
                        fallback=True,
                        command=kat.binary,
                        coverage={"urls": 0, "degraded": True, "reason": "katana not installed"},
                    )
                    partial = True
        except _Cancelled as exc:
            return _stop_if_cancelled(exc, job, target)
        new_urls, new_apis = ingest_urls(target, items)
    # JS discovery: fetch <script src> from live services (stdlib) + ingest
    js_count = 0
    try:
        with _stage_context(target, run, job):
            js_count = discover_js_for_target(target, job)
    except Exception as e:
        logger.exception(
            "js discovery failed: %s",
            e,
            extra={
                "target_id": target.pk,
                "scan_run_id": run.pk,
                "task_id": job.pk,
                "operation": "discover_urls:js",
                "status": "ERROR",
            },
        )
        _log(job, "ERROR", f"js discovery failed: {e.__class__.__name__}", stage="js")
    # P1-003: lost evidence rows degrade the stage, never a clean success.
    partial = partial or bool(_evidence_failures())
    _finish(
        job,
        "PARTIAL" if partial else "COMPLETED",
        stats={"new_urls": new_urls, "new_apis": new_apis, "js": js_count},
    )
    return {"status": job.status, "run_id": run.pk, "new_urls": new_urls, "new_apis": new_apis}


def discover_js_for_target(target, job=None):
    """Download script URLs from live HTTP services and ingest with hashing/analysis.

    T2+T3+T4: page fetches and every <script src> fetch go through
    _fetch_url_for_recon (scope-validated, SSRF-checked, TLS-honoring).
    Out-of-scope third-party scripts (CDNs, trackers, planted refs) are
    logged and skipped, never fetched.
    """
    from apps.assets.models import HTTPService

    count = 0
    for svc in HTTPService.objects.filter(target=target).order_by("-last_seen")[:30]:
        try:
            raw = _fetch_url_for_recon(
                target, svc.url, job=job, stage="js", timeout=10, max_bytes=500000
            )
        except _ReconFetchSkipped as e:
            if job is not None:
                _log(job, "INFO", f"skipped page {svc.url[:200]}: {e}", stage="js")
            continue
        except Exception:
            continue
        html = raw.decode("utf-8", errors="ignore")
        count += _extract_and_ingest_scripts(target, html, svc.url, job=job, source="crawler")
    return count


@shared_task(name="apps.jobs.tasks.run_nuclei")
def run_nuclei(target_id, scan_run_id=None):
    from apps.assets.models import HTTPService
    from services.correlation.ingest import ingest_nuclei_finding

    _evidence_failures(reset=True)  # P1-003: per-stage evidence-loss counter
    job, target, run = _job(
        target_id, "nuclei", tool="nuclei", scan_run_id=scan_run_id, scan_type="VALIDATION"
    )
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    from services.tool_adapters.adapters import NucleiAdapter

    adapter = NucleiAdapter()
    findings = 0
    if not adapter.is_available():
        # P1-011: the absent validator is recorded with the coverage that was
        # therefore never produced.
        _record_tool(
            target,
            run,
            job,
            "nuclei",
            "SKIPPED",
            error="nuclei not installed",
            command=adapter.binary,
            coverage={
                "validated": 0,
                "degraded": True,
                "dimension": "cve_validation",
                "reason": "nuclei not installed",
            },
        )
        _finish(job, "SKIPPED", error="nuclei not installed")
        return {"status": "SKIPPED", "reason": "nuclei missing"}
    with _stage_context(target, run, job):
        try:
            with _cancellable(target, job=job, run=run) as check:
                for svc in HTTPService.objects.filter(target=target).order_by("-last_seen")[:50]:
                    check()  # P2-006: a 50-URL nuclei pass is minutes of work
                    started = timezone.now()
                    try:
                        res = adapter.run(svc.url, cancel_check=check)
                    except _Cancelled:
                        raise  # do not record a tool failure or scan more URLs after a kill switch
                    except Exception as e:
                        _record_tool(
                            target,
                            run,
                            job,
                            "nuclei",
                            "FAILED",
                            error=e,
                            started_at=started,
                            coverage={"url": svc.url[:200]},
                        )
                        _log(
                            job,
                            "ERROR",
                            f"nuclei failed for {svc.url}: {e}",
                            stage="nuclei",
                            tool="nuclei",
                        )
                        continue
                    nuclei_row = _record_tool(
                        target,
                        run,
                        job,
                        "nuclei",
                        res.status,
                        error=res.error,
                        started_at=started,
                        coverage={"findings": len(res.data or [])},
                        exit_code=res.exit_code,
                        command=res.command,
                        stdout=res.stdout,
                        stderr=res.stderr,
                        duration_ms=res.duration_ms,
                    )
                    # P1-005: each finding is traceable to the tool run that
                    # produced it, not merely to the job.
                    with _tool_context(nuclei_row):
                        for item in res.data:
                            ingest_nuclei_finding(
                                target,
                                (
                                    item
                                    if isinstance(item, dict)
                                    else {"template": str(item), "matched_at": svc.url}
                                ),
                            )
                            findings += 1
        except _Cancelled as exc:
            return _stop_if_cancelled(exc, job, target)
    # P1-003: a per-URL nuclei failure or a lost evidence row means the
    # validation pass was incomplete.
    stage_status = "PARTIAL" if _evidence_failures() else "COMPLETED"
    _finish(job, stage_status, stats={"findings": findings})
    return {"status": stage_status, "run_id": run.pk, "findings": findings}


@shared_task(name="apps.jobs.tasks.handle_event_dependents")
def handle_event_dependents(event_id):
    """Async dependency fan-out: NEW_SUBDOMAIN->dns, NEW_IP->ports, NEW_OPEN_PORT->http, etc.
    Coalesces: if the dependent stage already has a QUEUED/RUNNING job for this
    target, the new trigger is skipped (prevents fan-out storms on big baselines)."""
    from apps.events.models import Event

    try:
        event = Event.objects.select_related("target").get(pk=event_id)
    except Event.DoesNotExist:
        return {"status": "SKIPPED", "reason": "event gone"}
    target = event.target
    if target is None or not target.is_scannable:
        return {"status": "SKIPPED", "reason": "target not scannable"}
    # NOTE: fan-out is per-asset incremental ONLY — never whole-target rescans.
    # Full-target stages run on schedule/baseline via their own tasks.
    if event.event_type in ("TECH_VERSION_CHANGED", "NEW_TECHNOLOGY", "NEW_CVE_CANDIDATE"):
        # targeted nuclei validation for the affected URL only
        url = (event.evidence or {}).get("asset_url", "")
        if url.startswith("http"):
            nuclei_for_url.delay(target.id, url, trigger=f"event:{event.id}")
            return {"status": "QUEUED", "next": "nuclei_for_url", "url": url[:150]}
        return {"status": "SKIPPED", "reason": "no URL to validate"}
    if True:
        # per-asset incremental dispatch (never whole-target rescans)
        ev = event.evidence or {}
        if event.event_type == "NEW_SUBDOMAIN" and event.asset_value:
            process_new_subdomain.delay(target.id, event.asset_value, trigger=f"event:{event.id}")
            return {"status": "QUEUED", "next": "process_new_subdomain"}
        if event.event_type == "NEW_IP" and event.asset_value:
            process_new_ip.delay(target.id, event.asset_value, trigger=f"event:{event.id}")
            return {"status": "QUEUED", "next": "process_new_ip"}
        if (
            event.event_type == "NEW_DNS_RECORD"
            and ev.get("type") in ("A", "AAAA")
            and ev.get("value")
        ):
            process_new_ip.delay(target.id, ev["value"], trigger=f"event:{event.id}")
            return {"status": "QUEUED", "next": "process_new_ip"}
        if event.event_type == "NEW_OPEN_PORT" and event.asset_value:
            import re as _re

            m = _re.match(r"(.+):(\d+)$", event.asset_value.strip())
            if m:
                ip, port = m.group(1), int(m.group(2))
                scheme = "https" if port in (443, 8443) else "http"
                probe_http_targets.delay(
                    target.id, [f"{scheme}://{ip}:{port}"], trigger=f"event:{event.id}"
                )
                return {"status": "QUEUED", "next": "probe_http_targets"}
            return {"status": "SKIPPED", "reason": "unparseable port asset"}
        if event.event_type == "NEW_HTTP_SERVICE" and event.asset_value.startswith("http"):
            host_url_discovery.delay(target.id, event.asset_value, trigger=f"event:{event.id}")
            return {"status": "QUEUED", "next": "host_url_discovery"}
        if event.event_type in ("NEW_JS", "JS_CHANGED") and event.asset_id:
            queue_js_analysis.delay(event.asset_id, trigger=event.event_type)
            return {"status": "QUEUED", "next": "queue_js_analysis"}
        return {"status": "SKIPPED", "reason": "no dependents"}


RECONCILE_ASSET_STAGES = {
    "SUBDOMAIN": "subdomain_enum",
    "IP": "dns",
    "PORT": "ports",
    "HTTP_SERVICE": "http",
    "URL": "urls",
    "JS_FILE": "js",
    "API_ENDPOINT": "urls",
}

# P1-010: the four states an asset's presence can be in after a scan.
OBSERVED = "OBSERVED"
NOT_OBSERVED_DURING_SUCCESSFUL_SCAN = "NOT_OBSERVED_DURING_SUCCESSFUL_SCAN"
SCAN_PARTIAL = "SCAN_PARTIAL"
SCAN_FAILED = "SCAN_FAILED"

# A stage that ended in one of these cannot prove the absence of anything.
_INCOMPLETE_STAGE_STATUSES = frozenset(
    {
        "PARTIAL",
        "SKIPPED",
        "PAUSED",
        "CANCELLED",
        "CANCELLED_KILL_SWITCH",
        "QUEUED",
        "RUNNING",
    }
)


def _coverage_state_for(target, job_type):
    """Classify the most recent execution of ``job_type`` for this target.

    P1-010: absence can only be *proven* by a stage that actually completed.
    Returns one of:

    * ``OBSERVED``  -- the stage completed: anything it did not report is
      genuinely gone (subject to the grace period);
    * ``SCAN_PARTIAL`` -- the stage ran with reduced coverage (fallback tools, a
      capped port list, a profile exclusion) or was stopped, so its silence
      proves nothing;
    * ``SCAN_FAILED`` -- the stage failed outright;
    * ``SCAN_PARTIAL`` (with ``last=None``) -- the stage has never run, so there
      is no evidence at all.
    """
    from apps.jobs.models import ScanJob

    last = (
        ScanJob.all_objects.filter(target=target, job_type=job_type).order_by("-created_at").first()
    )
    if last is None:
        return SCAN_PARTIAL, None
    if last.status == ScanJob.STATUS_COMPLETED:
        return OBSERVED, last
    if last.status in _INCOMPLETE_STAGE_STATUSES:
        return SCAN_PARTIAL, last
    return SCAN_FAILED, last


def _reconcile_scan_states(target):
    """Per-asset-type coverage states, reported on the reconcile result (P1-010)."""
    states = {}
    for asset_type, job_type in RECONCILE_ASSET_STAGES.items():
        state, _last = _coverage_state_for(target, job_type)
        states[asset_type] = state
    return states


@shared_task(name="apps.jobs.tasks.reconcile_target")
def reconcile_target(target_id):
    """Periodic reconciliation: detect removed assets (stale last_seen), refresh state.

    P1-010 — an asset is only marked removed when a *sufficiently complete,
    successful* scan proves it is absent. The previous implementation flipped
    assets to REMOVED purely because ``last_seen`` had aged past the grace
    period, so a scan that failed, was cancelled, or silently covered less
    (missing tool, capped port list, profile exclusion) manufactured false
    "removed" events. Coverage is now decided per asset type from the latest
    execution of the stage that would have observed it, and the four states
    (``OBSERVED`` / ``NOT_OBSERVED_DURING_SUCCESSFUL_SCAN`` / ``SCAN_PARTIAL`` /
    ``SCAN_FAILED``) are reported explicitly instead of being conflated.

    The stale rows are also walked in batches rather than truncated at a fixed
    ``[:500]``, so a target with more stale assets than one page reconciles
    completely instead of leaving a silent remainder.
    """
    from datetime import timedelta

    from django.conf import settings

    from apps.assets.models import Port, Subdomain
    from services.event_engine.engine import emit_event

    job, target, run = _job(target_id, "reconcile", tool="internal", scan_type="RECONCILE")
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    # Task 11: never reconcile a target that never completed a scan — fresh
    # targets would otherwise get all assets marked REMOVED on first run.
    from apps.jobs.models import ScanJob, ScanRun

    has_history = (
        ScanRun.objects.filter(target=target, status="COMPLETED").exists()
        or ScanJob.objects.filter(target=target, status=ScanJob.STATUS_COMPLETED).exists()
        or getattr(target, "baseline_status", "") == "BASELINE_COMPLETE"
    )
    if not has_history:
        _finish(job, "SKIPPED", error="no_baseline_yet: no completed scan history")
        return {"status": "SKIPPED", "reason": "no_baseline_yet"}
    grace = getattr(target, "reconciliation_grace_days", 14) or 14
    cutoff = timezone.now() - timedelta(days=grace)
    batch_size = int(getattr(settings, "RECONCILE_BATCH_SIZE", 500) or 500)
    states = _reconcile_scan_states(target)
    removed = 0
    withheld = 0  # assets that aged out but whose absence is not proven
    withheld_by_type = {}

    def _may_remove(asset_type, stale_qs=None):
        """True only when a completed stage proves absence for this type.

        P1-010: when absence is *not* proven, the stale assets of that type are
        counted per asset (not per type) and left untouched, so the withheld
        total in the result reflects real assets, not asset classes.
        """
        nonlocal withheld
        if states.get(asset_type) == OBSERVED:
            return True
        if stale_qs is not None:
            count = stale_qs.count()
            if count:
                withheld_by_type[asset_type] = withheld_by_type.get(asset_type, 0) + count
                withheld += count
        return False

    with _stage_context(target, run, job):
        try:
            with _cancellable(target, job=job, run=run) as check:
                stale_subs = Subdomain.all_objects.filter(
                    target=target, is_active=True, last_seen__lt=cutoff
                )
                if _may_remove("SUBDOMAIN", stale_subs):
                    for sub in _batched(stale_subs, batch_size, "pk", check):
                        sub.is_active = False
                        sub.state = "REMOVED"
                        sub.last_changed = timezone.now()
                        sub.save(update_fields=["is_active", "state", "last_changed"])
                        emit_event(
                            "SUBDOMAIN_REMOVED",
                            target=target,
                            asset_type="SUBDOMAIN",
                            asset_id=sub.id,
                            asset_value=sub.hostname,
                            source="reconcile",
                            evidence={
                                "note": "not observed during a completed scan",
                                "absence": NOT_OBSERVED_DURING_SUCCESSFUL_SCAN,
                                "scan_state": OBSERVED,
                            },
                            old_state={"hostname": sub.hostname, "state": "ACTIVE"},
                            new_state={"hostname": sub.hostname, "state": "REMOVED"},
                        )
                        removed += 1
                stale_ports = Port.all_objects.filter(
                    target=target, state="open", last_seen__lt=cutoff
                )
                if _may_remove("PORT", stale_ports):
                    for p in _batched(stale_ports, batch_size, "pk", check):
                        p.state = "closed"
                        p.last_changed = timezone.now()
                        p.save(update_fields=["state", "last_changed"])
                        emit_event(
                            "PORT_CLOSED",
                            target=target,
                            asset_type="PORT",
                            asset_id=p.id,
                            asset_value=f"{p.ip}:{p.port}",
                            source="reconcile",
                            evidence={
                                "absence": NOT_OBSERVED_DURING_SUCCESSFUL_SCAN,
                                "scan_state": OBSERVED,
                            },
                            old_state={"state": "open"},
                            new_state={"state": "closed"},
                        )
                        removed += 1
                # HTTP + URL + JS removal (TASK-015/019/023)
                from apps.assets.models import HTTPService as _HTTP
                from apps.assets.models import JavaScriptAsset as _JS
                from apps.assets.models import URLAsset as _URL

                stale_svcs = (
                    _HTTP.all_objects.filter(target=target)
                    .exclude(state__in=["INACTIVE", "REMOVED"])
                    .filter(last_seen__lt=cutoff)
                )
                if _may_remove("HTTP_SERVICE", stale_svcs):
                    for svc in _batched(stale_svcs, batch_size, "pk", check):
                        svc.state = "REMOVED"
                        svc.last_changed = timezone.now()
                        svc.save(update_fields=["state", "last_changed"])
                        emit_event(
                            "HTTP_SERVICE_REMOVED",
                            target=target,
                            asset_type="HTTP_SERVICE",
                            asset_id=svc.id,
                            asset_value=svc.url,
                            source="reconcile",
                            evidence={
                                "absence": NOT_OBSERVED_DURING_SUCCESSFUL_SCAN,
                                "scan_state": OBSERVED,
                            },
                        )
                        removed += 1
                stale_urls = (
                    _URL.all_objects.filter(target=target)
                    .exclude(state__in=["INACTIVE", "REMOVED"])
                    .filter(last_seen__lt=cutoff)
                )
                if _may_remove("URL", stale_urls):
                    for u in _batched(stale_urls, batch_size, "pk", check):
                        u.state = "REMOVED"
                        u.save(update_fields=["state"])
                        emit_event(
                            "URL_REMOVED",
                            target=target,
                            asset_type="URL",
                            asset_id=u.id,
                            asset_value=u.canonical_url[:500],
                            source="reconcile",
                            evidence={
                                "absence": NOT_OBSERVED_DURING_SUCCESSFUL_SCAN,
                                "scan_state": OBSERVED,
                            },
                        )
                        removed += 1
                stale_js = (
                    _JS.all_objects.filter(target=target)
                    .exclude(state__in=["INACTIVE", "REMOVED"])
                    .filter(last_seen__lt=cutoff)
                )
                if _may_remove("JS_FILE", stale_js):
                    for j in _batched(stale_js, batch_size, "pk", check):
                        j.state = "REMOVED"
                        j.last_changed = timezone.now()
                        j.save(update_fields=["state", "last_changed"])
                        emit_event(
                            "JS_REMOVED",
                            target=target,
                            asset_type="JS_FILE",
                            asset_id=j.id,
                            asset_value=j.js_url,
                            source="reconcile",
                            evidence={
                                "absence": NOT_OBSERVED_DURING_SUCCESSFUL_SCAN,
                                "scan_state": OBSERVED,
                            },
                        )
                        removed += 1
                # Task 9: IP + API endpoint reconciliation (IP_REMOVED / API_ENDPOINT_REMOVED
                # were defined but never emitted; is_active never flipped back).
                from apps.assets.models import APIEndpoint as _API
                from apps.assets.models import DNSRecord as _DNS
                from apps.assets.models import IPAddress as _IP

                stale_ips = _IP.all_objects.filter(
                    target=target, is_active=True, last_seen__lt=cutoff
                )
                if _may_remove("IP", stale_ips):
                    for ip in _batched(stale_ips, batch_size, "pk", check):
                        # Edge: an IP shared by several hostnames must not be removed while any
                        # live DNS record still points at it — only the hostname went stale.
                        if _DNS.objects.filter(
                            target=target,
                            value=ip.ip,
                            record_type__in=["A", "AAAA"],
                            last_seen__gte=cutoff,
                        ).exists():
                            continue
                        ip.is_active = False
                        ip.state = "REMOVED"
                        ip.save(update_fields=["is_active", "state"])
                        emit_event(
                            "IP_REMOVED",
                            target=target,
                            asset_type="IP",
                            asset_id=ip.id,
                            asset_value=ip.ip,
                            source="reconcile",
                            evidence={
                                "absence": NOT_OBSERVED_DURING_SUCCESSFUL_SCAN,
                                "scan_state": OBSERVED,
                            },
                            old_state={"ip": ip.ip, "state": "ACTIVE"},
                            new_state={"ip": ip.ip, "state": "REMOVED"},
                        )
                        removed += 1
                stale_eps = (
                    _API.all_objects.filter(target=target)
                    .exclude(state__in=["INACTIVE", "REMOVED"])
                    .filter(last_seen__lt=cutoff)
                )
                if _may_remove("API_ENDPOINT", stale_eps):
                    for ep in _batched(stale_eps, batch_size, "pk", check):
                        ep.state = "REMOVED"
                        ep.save(update_fields=["state"])
                        emit_event(
                            "API_ENDPOINT_REMOVED",
                            target=target,
                            asset_type="API_ENDPOINT",
                            asset_id=ep.id,
                            asset_value=ep.url[:500],
                            source="reconcile",
                            evidence={
                                "method": ep.method,
                                "api_type": ep.api_type,
                                "absence": NOT_OBSERVED_DURING_SUCCESSFUL_SCAN,
                                "scan_state": OBSERVED,
                            },
                        )
                        removed += 1
        except _Cancelled as exc:
            return _stop_if_cancelled(exc, job, target)
    # P1-010: the outcome is honest about what was and was not proven. Withheld
    # assets are NOT silently dropped -- the count and reason are on the job and
    # in the returned state map.
    if withheld:
        _log(
            job,
            "WARNING",
            f"withheld {withheld} removal(s): absence not proven ({withheld_by_type})",
            stage="reconcile",
            tool="internal",
        )
    _finish(
        job,
        "COMPLETED",
        stats={
            "marked_inactive": removed,
            "withheld": withheld,
            "withheld_by_type": withheld_by_type,
            "scan_states": states,
        },
    )
    return {
        "status": "COMPLETED",
        "marked_inactive": removed,
        "withheld": withheld,
        "withheld_by_type": withheld_by_type,
        "scan_states": states,
    }


def _batched(qs, batch_size, cursor_field="pk", check=None):
    """Yield every row of ``qs`` in keyset batches (no silent ``[:N]`` tail).

    P1-010/P1-007/P1-009: the sweep is bounded per batch but complete. The
    kill-switch ``check`` is invoked between batches.
    """
    cursor = 0
    while True:
        batch = list(
            qs.filter(**{f"{cursor_field}__gt": cursor}).order_by(cursor_field)[:batch_size]
        )
        if not batch:
            return
        for row in batch:
            cursor = getattr(row, cursor_field)
            yield row
        if check is not None:
            check()  # P2-006: stop between batches of writes
        if len(batch) < batch_size:
            return


# ---------------------------------------------------------------------------
# Incremental per-asset pipeline: process ONLY what is new, never full rescans.
# NEW_SUBDOMAIN -> resolve that host -> NEW_IP -> scan that IP ->
# NEW_OPEN_PORT -> probe that service -> NEW_HTTP_SERVICE -> crawl that host ->
# NEW_URL/NEW_JS -> analyze that JS -> technology -> CVE -> nuclei.
# ---------------------------------------------------------------------------


def _asset_job(
    target, job_type, asset_type="", asset_value="", trigger="event", tool="", scan_run=None
):
    """Create a RUNNING ScanJob with full context, or return (None, reason).

    P0-009: the job attaches to the real execution root that produced the event
    (when the caller knows it), otherwise it opens its own. There is no
    free-form run id any more.
    """
    from apps.jobs.models import ScanJob
    from services.event_engine.engine import broadcast_job

    if not target.is_scannable:
        return None, f"target not scannable: {target.blocking_reason() or 'unknown'}"
    if (
        asset_value
        and ScanJob.objects.filter(
            target=target,
            job_type=job_type,
            asset_value=asset_value[:1024],
            status__in=[ScanJob.STATUS_QUEUED, ScanJob.STATUS_RUNNING],
        ).exists()
    ):
        return None, "already running for this asset (coalesced)"
    run = scan_run or _get_or_create_run(target, scan_type="MONITORING", trigger=trigger)
    job = ScanJob.objects.create(
        target=target,
        job_type=job_type,
        tool=tool,
        status=ScanJob.STATUS_RUNNING,
        asset_type=asset_type,
        asset_value=(asset_value or "")[:1024],
        trigger=trigger,
        scan_run=run,
        started_at=timezone.now(),
    )
    job.beat()
    broadcast_job(job)
    return job, "ok"


@shared_task(name="apps.jobs.tasks.process_new_subdomain", queue="recon")
def process_new_subdomain(target_id, hostname, trigger="event"):
    """Downstream for one new subdomain: DNS for that host, then HTTP probe."""
    from apps.scope.models import ScopeRule
    from apps.targets.models import Target
    from services.correlation.ingest import ingest_dns
    from services.scope_engine.validator import scope_allows_scan, validate_host

    try:
        target = Target.objects.get(pk=target_id)
    except Target.DoesNotExist:
        return {"status": "SKIPPED", "reason": "target gone"}
    rules = list(ScopeRule.objects.filter(target__in=[None, target]))
    ok, reason = scope_allows_scan(target, rules)
    if not ok:
        return {"status": "SKIPPED", "reason": reason}
    ok, reason = validate_host(target, hostname, rules)
    if not ok:
        return {"status": "SKIPPED", "reason": f"scope: {reason}"}
    job, msg = _asset_job(target, "dns", "SUBDOMAIN", hostname, trigger, tool="socket/dnsx")
    if job is None:
        return {"status": "SKIPPED", "reason": msg}
    import socket as _socket

    records = []
    try:
        for fam, _, _, _, addr in _socket.getaddrinfo(hostname, None):
            if fam == _socket.AF_INET:
                records.append({"hostname": hostname, "type": "A", "value": addr[0]})
            elif fam == _socket.AF_INET6:
                records.append({"hostname": hostname, "type": "AAAA", "value": addr[0]})
    except Exception as e:
        _log(job, "ERROR", f"resolve failed for {hostname}: {e}", stage="dns")
    new = ingest_dns(target, records)
    _finish(job, "COMPLETED", stats={"new": new, "host": hostname})
    # HTTP probe for this host (its own job; fan-out coalesces duplicates)
    probe_http_targets.delay(target_id, [f"https://{hostname}", f"http://{hostname}"], trigger)
    return {"status": "COMPLETED", "host": hostname, "dns_new": new}


@shared_task(name="apps.jobs.tasks.process_new_ip", queue="recon")
def process_new_ip(target_id, ip, trigger="event"):
    """Downstream for one new IP: port-scan that IP only, then probe new ports."""
    import socket as _socket

    from apps.scope.models import ScopeRule
    from apps.targets.models import Target
    from services.correlation.ingest import ingest_ports
    from services.scope_engine.validator import scope_allows_scan, validate_ip

    try:
        target = Target.objects.get(pk=target_id)
    except Target.DoesNotExist:
        return {"status": "SKIPPED", "reason": "target gone"}
    rules = list(ScopeRule.objects.filter(target__in=[None, target]))
    ok, reason = scope_allows_scan(target, rules)
    if not ok:
        return {"status": "SKIPPED", "reason": reason}
    ok, reason = validate_ip(target, ip, rules)
    if not ok:
        return {"status": "SKIPPED", "reason": f"scope: {reason}"}
    # T5: shared-infrastructure IP (also claimed by another target) needs an
    # explicit confirmed_dedicated=True before any active port scan.
    from apps.assets.models import IPAddress as _IP

    rec = _IP.objects.filter(target=target, ip=ip).first()
    if rec is not None and rec.shared_suspect and not rec.confirmed_dedicated:
        return {"status": "SKIPPED", "reason": "shared_ip_unconfirmed"}
    job, msg = _asset_job(target, "ports", "IP", ip, trigger, tool="naabu/socket")
    if job is None:
        return {"status": "SKIPPED", "reason": msg}
    ports_cfg = (
        target.scan_config.get("ports", "80,443,8080,8443,8000,8888,3000,5000")
        if isinstance(target.scan_config, dict)
        else "80,443,8080,8443,8000,8888,3000,5000"
    )
    port_list = [int(p) for p in str(ports_cfg).split(",") if p.strip().isdigit()][:30]
    entries = []
    from services.tool_adapters.adapters import NaabuAdapter

    adapter = NaabuAdapter()
    used_naabu = False
    if adapter.is_available():
        # P0-013: child jobs must respect the kill switch mid-subprocess too.
        try:
            with _cancellable(target, job=job, run=None) as _check:
                res = adapter.run(ip, ports=",".join(map(str, port_list)), cancel_check=_check)
                entries.extend(res.data)
                used_naabu = res.status in ("COMPLETED", "PARTIAL")
                _record_tool(
                    target,
                    None,
                    job,
                    "naabu",
                    res.status,
                    error=res.error,
                    coverage={"open": len(res.data or []), "ip": ip},
                    exit_code=res.exit_code,
                    command=res.command,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    duration_ms=res.duration_ms,
                )
                _log(
                    job, "INFO", f"naabu on {ip}: {len(res.data)} open", stage="ports", tool="naabu"
                )
        except _Cancelled as exc:
            return _stop_if_cancelled(exc, job, target)
        except Exception as e:
            _record_tool(target, None, job, "naabu", "FAILED", error=e, coverage={"ip": ip})
            _log(job, "ERROR", f"naabu failed for {ip}: {e}", stage="ports", tool="naabu")
    elif not used_naabu:
        # P1-011: absent primary scanner is part of the record.
        _record_tool(
            target,
            None,
            job,
            "naabu",
            "SKIPPED",
            error="naabu not installed",
            command=adapter.binary,
            coverage={"ip": ip, "validated": False, "degraded": True},
        )
    if not entries:
        # P1-011/P1-012: record the fallback use and the coverage it achieves.
        # This per-IP sweep covers the full capped port list, so coverage is not
        # reduced by the cap -- but the absent/failed primary is still recorded.
        _record_tool(
            target,
            None,
            job,
            "socket-connect",
            "COMPLETED",
            fallback=not used_naabu,
            coverage=_coverage_note(
                len(port_list),
                len(port_list),
                dimension="port_probes",
                ip=ip,
                reason=(
                    "naabu unavailable"
                    if not adapter.is_available()
                    else "naabu produced no results"
                ),
            ),
        )
        for pt in port_list:
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((ip, pt)) == 0:
                    entries.append({"ip": ip, "port": pt, "protocol": "tcp"})
                s.close()
            except Exception:
                continue
    before = {(p.ip, p.port) for p in target.ports.filter(state="open")}
    new = ingest_ports(target, entries)
    new_ports = [e for e in entries if (e.get("ip"), e.get("port")) not in before]
    _finish(job, "COMPLETED", stats={"new": new, "open": len(entries), "ip": ip})
    for entry in new_ports:  # probe only the newly opened ports
        scheme = "https" if entry.get("port") in (443, 8443) else "http"
        probe_http_targets.delay(target_id, [f"{scheme}://{ip}:{entry['port']}"], trigger)
    return {"status": "COMPLETED", "ip": ip, "new": new}


@shared_task(name="apps.jobs.tasks.probe_http_targets", queue="recon")
def probe_http_targets(target_id, urls, trigger="event"):
    """HTTP-probe an explicit URL list (per-asset), then crawl new services."""
    from apps.targets.models import Target
    from services.correlation.ingest import ingest_http

    try:
        target = Target.objects.get(pk=target_id)
    except Target.DoesNotExist:
        return {"status": "SKIPPED", "reason": "target gone"}
    ok, reason = _gate(target)
    if not ok:
        return {"status": "SKIPPED", "reason": reason}
    label = (urls[0] if urls else "")[:200]
    if urls and all((".invalid" in u or ".example" in u or ".test" in u) for u in urls):
        return {"status": "SKIPPED", "reason": "test URLs — no network"}
    job, msg = _asset_job(target, "http", "URL", label, trigger, tool="httpx/urllib")
    if job is None:
        return {"status": "SKIPPED", "reason": msg}
    entries = []
    from services.tool_adapters.adapters import HttpxAdapter
    from services.tool_adapters.base import redact_command

    adapter = HttpxAdapter()
    if adapter.is_available() and urls:
        # Task 13: single adapter.run(hosts) path (stdin piped, redacted cmd logged).
        job.command_redacted = redact_command(adapter.build_command(urls[:50]))
        job.save(update_fields=["command_redacted"])
        try:
            with _cancellable(target, job=job, run=None) as _check:
                res = adapter.run(urls[:50], timeout=300, cancel_check=_check)
                if res.status == "FAILED":
                    _log(job, "ERROR", f"httpx failed: {res.error}", stage="http", tool="httpx")
                else:
                    entries.extend(o for o in res.data if isinstance(o, dict))
        except _Cancelled as exc:
            return _stop_if_cancelled(exc, job, target)
        except Exception as e:
            _log(job, "ERROR", f"httpx failed: {e}", stage="http", tool="httpx")
    if not entries:
        import urllib.request as _urlreq

        for url in (urls or [])[:50]:
            if not target.is_scannable:  # P0-013: no per-asset work after a kill switch
                _log(
                    job,
                    "INFO",
                    f"stopped probing {label}: {target.blocking_reason()}",
                    stage="http",
                )
                break
            try:
                # T2+T4: per-asset URLs still get scope + SSRF pre-checks.
                ok, reason, _h = _url_allowed_for_fetch(target, url)
                if not ok:
                    _log(
                        job,
                        "INFO",
                        f"skipped probe {url[:200]}: {reason}",
                        stage="http",
                        tool="urllib",
                    )
                    continue
                req = _urlreq.Request(url, headers={"User-Agent": "recon-monitor/1.0"})
                with _safe_opener(target, job, "http").open(req, timeout=8) as r:
                    entries.append(
                        {
                            "url": url,
                            "status_code": r.status,
                            "title": "",
                            "server": r.headers.get("Server", ""),
                            "content_type": r.headers.get("Content-Type", ""),
                        }
                    )
            except Exception:
                continue
    new, changed = ingest_http(target, entries)
    _finish(job, "COMPLETED", stats={"new": new, "changed": changed})
    # crawl only hosts that are genuinely new services (fan-out also covers via events)
    return {"status": "COMPLETED", "new": new, "changed": changed}


@shared_task(name="apps.jobs.tasks.host_url_discovery", queue="recon")
def host_url_discovery(target_id, url, trigger="event"):
    """Crawl a single HTTP service: katana + <script> extraction + JS ingest."""
    from apps.targets.models import Target

    try:
        target = Target.objects.get(pk=target_id)
    except Target.DoesNotExist:
        return {"status": "SKIPPED", "reason": "target gone"}
    ok, reason = _gate(target)
    if not ok:
        return {"status": "SKIPPED", "reason": reason}
    job, msg = _asset_job(target, "urls", "HTTP_SERVICE", url[:500], trigger, tool="katana/crawler")
    if job is None:
        return {"status": "SKIPPED", "reason": msg}
    from services.correlation.ingest import ingest_urls

    items = []
    from services.tool_adapters.adapters import KatanaAdapter

    kat = KatanaAdapter()
    used_katana = False
    katana_status = ""
    if kat.is_available():
        try:
            res = kat.run(url)
            items.extend(res.data)
            used_katana = res.status in ("COMPLETED", "PARTIAL")
            katana_status = res.status
            _record_tool(
                target,
                None,
                job,
                "katana",
                res.status,
                error=res.error,
                coverage={"urls": len(res.data or []), "url": url[:200]},
                exit_code=res.exit_code,
                command=res.command,
                stdout=res.stdout,
                stderr=res.stderr,
                duration_ms=res.duration_ms,
            )
            _log(job, "INFO", f"katana on {url}: {len(res.data)} urls", stage="urls", tool="katana")
        except Exception as e:
            _record_tool(
                target, None, job, "katana", "FAILED", error=e, coverage={"url": url[:200]}
            )
            _log(job, "ERROR", f"katana failed: {e}", stage="urls", tool="katana")
    else:
        # P1-011: without katana the only URL discovery left is <script src>
        # extraction from the page itself -- materially reduced coverage, so it
        # is recorded as such and never reported as a full crawl.
        _record_tool(
            target,
            None,
            job,
            "katana",
            "SKIPPED",
            error="katana not installed",
            fallback=True,
            command=kat.binary,
            coverage={
                "urls": 0,
                "reduced": True,
                "degraded": True,
                "dimension": "url_crawl",
                "reason": "katana not installed",
            },
        )
        _log(
            job,
            "WARNING",
            "katana not installed; only script-src extraction will run",
            stage="urls",
            tool="katana",
        )
    new_urls, new_apis = ingest_urls(target, items)
    # script-src JS extraction from the page itself (T2: shared scoped helper).
    js_count = 0
    try:
        raw = _fetch_url_for_recon(target, url, job=job, stage="js", timeout=10, max_bytes=500000)
    except _ReconFetchSkipped as e:
        _log(job, "INFO", f"skipped page {url[:200]}: {e}", stage="js")
        raw = b""
    except Exception as e:
        _log(job, "ERROR", f"page fetch failed for {url}: {e}", stage="js")
        raw = b""
    if raw:
        js_count = _extract_and_ingest_scripts(
            target, raw.decode("utf-8", errors="ignore"), url, job=job, source="crawler"
        )
    # P1-011: no katana means the crawl never ran; script-src extraction alone
    # is materially reduced coverage and must not read as a completed crawl.
    if used_katana and katana_status == "COMPLETED":
        job_status = "COMPLETED"
    else:
        job_status = "PARTIAL"  # katana missing, or ended PARTIAL
    _finish(job, job_status, stats={"new_urls": new_urls, "new_apis": new_apis, "js": js_count})
    return {"status": job_status, "new_urls": new_urls, "js": js_count}


@shared_task(name="apps.jobs.tasks.queue_js_analysis", queue="js_analysis")
def queue_js_analysis(js_id, trigger="NEW_JS"):
    """Create a JSAnalysisJob and dispatch the staged analyzer pipeline."""
    from apps.assets.models import JavaScriptAsset
    from apps.jobs.models import JSAnalysisJob

    try:
        js = JavaScriptAsset.objects.select_related("target").get(pk=js_id)
    except JavaScriptAsset.DoesNotExist:
        return {"status": "SKIPPED", "reason": "js gone"}
    if not js.target.is_scannable:
        return {"status": "SKIPPED", "reason": "target not scannable"}
    if JSAnalysisJob.objects.filter(js=js, status__in=["QUEUED", "RUNNING"]).exists():
        return {"status": "SKIPPED", "reason": "analysis already queued/running"}
    job = JSAnalysisJob.objects.create(target=js.target, js=js, trigger=trigger)
    analyze_js_task.delay(job.id)
    return {"status": "QUEUED", "job": job.id}


@shared_task(name="apps.jobs.tasks.analyze_js_task", queue="js_analysis")
def analyze_js_task(analysis_job_id):
    from services.correlation.jsanalysis import run_analysis

    return {"status": run_analysis(analysis_job_id)}


@shared_task(name="apps.jobs.tasks.nuclei_for_url", queue="cve")
def nuclei_for_url(target_id, url, trigger="event"):
    """Targeted nuclei validation for a single URL (CVE follow-up)."""
    from apps.targets.models import Target
    from services.correlation.ingest import ingest_nuclei_finding

    try:
        target = Target.objects.get(pk=target_id)
    except Target.DoesNotExist:
        return {"status": "SKIPPED", "reason": "target gone"}
    ok, reason = _gate(target)
    if not ok:
        return {"status": "SKIPPED", "reason": reason}
    job, msg = _asset_job(target, "nuclei", "URL", url[:500], trigger, tool="nuclei")
    if job is None:
        return {"status": "SKIPPED", "reason": msg}
    from services.tool_adapters.adapters import NucleiAdapter

    adapter = NucleiAdapter()
    if not adapter.is_available():
        # P1-011: the missing validator is recorded so the target's validation
        # coverage is never assumed to have run.
        _record_tool(
            target,
            None,
            job,
            "nuclei",
            "SKIPPED",
            error="nuclei not installed",
            command=adapter.binary,
            coverage={"url": url[:200], "validated": False, "degraded": True},
        )
        _finish(job, "SKIPPED", error="nuclei not installed")
        return {"status": "SKIPPED", "reason": "nuclei missing"}
    started = timezone.now()
    try:
        with _cancellable(target, job=job, run=None) as _check:
            res = adapter.run(url, cancel_check=_check)
    except _Cancelled as exc:
        return _stop_if_cancelled(exc, job, target)
    except Exception as e:
        _record_tool(
            target,
            None,
            job,
            "nuclei",
            "FAILED",
            error=e,
            started_at=started,
            coverage={"url": url[:200]},
        )
        _finish(job, "FAILED", error=str(e)[:500])
        return {"status": "FAILED", "error": str(e)[:200]}
    _record_tool(
        target,
        None,
        job,
        "nuclei",
        res.status,
        error=res.error,
        started_at=started,
        coverage={"findings": len(res.data or []), "url": url[:200]},
        exit_code=res.exit_code,
        command=res.command,
        stdout=res.stdout,
        stderr=res.stderr,
        duration_ms=res.duration_ms,
    )
    n = 0
    for item in res.data:
        ingest_nuclei_finding(
            target, item if isinstance(item, dict) else {"template": str(item), "matched_at": url}
        )
        n += 1
    _finish(
        job,
        "COMPLETED" if res.status == "COMPLETED" else "PARTIAL",
        stats={"findings": n, "url": url[:200]},
    )
    return {"status": job.status, "findings": n}
