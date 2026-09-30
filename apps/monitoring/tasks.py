"""Periodic monitoring tasks (celery beat): reconcile, CVE sync, auth expiry, JS recheck."""

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(name="apps.monitoring.tasks.generate_export", queue="recon")
def generate_export(export_job_id):
    from apps.monitoring.exports import run_export_job

    return run_export_job(export_job_id)


def _cve_uptodate(tech) -> bool:
    """True when this technology needs no re-correlation against an unchanged KB.

    A technology is up to date once it has been correlated and its fingerprint
    has not changed since: a *new* technology (``cve_checked_at`` is null) or one
    whose ``last_changed`` post-dates its last correlation must be re-checked.
    """
    if not getattr(tech, "cve_checked_at", None):
        return False
    changed = getattr(tech, "last_changed", None)
    if changed is not None and changed > tech.cve_checked_at:
        return False
    return True


@shared_task(name="apps.monitoring.tasks.detect_stalled_jobs", queue="recon")
def detect_stalled_jobs():
    """Flag (and close) RUNNING jobs whose liveness signal has expired (P1-006).

    Liveness is decided by ``heartbeat_at`` — the cooperative heartbeat the job
    writes while it works — and *not* by log activity: a job can be wedged
    between log lines, and a chatty job can stall between writes. Logs are
    recorded as secondary evidence only.

    A job whose heartbeat is older than ``settings.JOB_STALL_SECONDS`` is
    stalled. It is flagged, reported (``JOB_STALLED``) and — unless
    ``settings.JOB_STALL_MARK_FAILED`` is off — moved out of RUNNING, because a
    job that stays RUNNING forever is indistinguishable from a live one and
    defeats stall detection, run bookkeeping and the kill switch alike.
    """
    from datetime import timedelta

    from django.conf import settings

    from apps.jobs.models import ScanJob
    from services.event_engine.engine import emit_event

    stall_seconds = int(getattr(settings, "JOB_STALL_SECONDS", 1800) or 1800)
    mark_failed = bool(getattr(settings, "JOB_STALL_MARK_FAILED", True))
    cutoff = timezone.now() - timedelta(seconds=stall_seconds)
    stalled = 0
    closed = 0
    for job in ScanJob.objects.filter(status=ScanJob.STATUS_RUNNING):
        heartbeat = job.heartbeat_at
        # Secondary evidence: the newest log line, if any. Never the deciding
        # signal, but recorded so an operator can see what the job was doing.
        last_log = job.logs.order_by("-created_at").first() if job.pk else None
        last_log_at = last_log.created_at if last_log else None
        # A job that never wrote a heartbeat is judged from when it started.
        reference = heartbeat or job.started_at or job.created_at
        if reference is None or reference >= cutoff:
            continue  # fresh heartbeat: genuinely working
        if (job.stats or {}).get("stalled_flagged"):
            continue  # already reported; do not spam a new event per sweep
        hb_error = (job.stats or {}).get("last_heartbeat_error", "")
        stats = dict(job.stats or {})
        stats["stalled_flagged"] = True
        stats["stalled_at"] = timezone.now().isoformat()
        stats["stalled_reason"] = "heartbeat_expired"
        stats["stalled_heartbeat_at"] = heartbeat.isoformat() if heartbeat else ""
        if hb_error:
            # The heartbeat write itself failed: liveness could not be proven,
            # which is a distinct (and more serious) condition than silence.
            stats["stalled_reason"] = "heartbeat_write_failed"
        job.stats = stats
        fields = ["stats"]
        if mark_failed:
            job.status = ScanJob.STATUS_FAILED
            job.finished_at = timezone.now()
            job.error = f"stalled: no heartbeat for {stall_seconds}s (kill the worker or re-run)"
            fields += ["status", "finished_at", "error"]
        job.save(update_fields=fields)
        emit_event(
            "JOB_STALLED",
            target=job.target,
            asset_value=f"job #{job.id} {job.job_type}",
            source="monitoring",
            severity="HIGH",
            scan_run=job.scan_run,
            evidence={
                "job_id": job.id,
                "job_type": job.job_type,
                "stall_seconds": stall_seconds,
                "liveness_signal": "heartbeat",
                "heartbeat_at": str(heartbeat) if heartbeat else None,
                "last_log_at": str(last_log_at) if last_log_at else None,
                "heartbeat_write_error": hb_error,
                "running_since": str(job.started_at),
                "marked_failed": mark_failed,
            },
        )
        stalled += 1
        if mark_failed and job.scan_run_id is not None:
            # P0-012: a stalled job is a closed job -- let the run bookkeeping
            # decide whether the execution root can close too.
            from apps.jobs.tasks import _close_run_if_idle

            _close_run_if_idle(job, ScanJob.STATUS_FAILED)
            closed += 1
    return {"stalled": stalled, "runs_closed": closed, "stall_seconds": stall_seconds}


@shared_task(name="apps.monitoring.tasks.reconcile_all")
def reconcile_all():
    from apps.jobs.tasks import reconcile_target
    from apps.targets.models import Target

    queued = 0
    for t in Target.objects.filter(status=Target.STATUS_ACTIVE):
        if t.is_scannable:
            reconcile_target.delay(t.id)
            queued += 1
    return {"queued": queued}


@shared_task(name="apps.monitoring.tasks.sync_cve_database")
def sync_cve_database(full_sync=None):
    """Sync the CVE KB, then correlate **every** technology (P1-007/P1-008).

    The previous implementation correlated ``Technology.objects.all()[:2000]``:
    a hard global cap that silently left every target beyond the 2000th
    technology un-correlated, with no record that anything was skipped. Coverage
    is now complete and bounded:

    * processing walks the table in keyset-paginated batches
      (``CVE_CORRELATION_BATCH_SIZE``) until no rows remain, so the work is
      bounded per batch but the coverage is total;
    * when the CVE KB is *unchanged* since the last successful pass, only
      technologies that are new or changed since their last correlation are
      re-checked (incremental), because a stale KB cannot produce new matches
      for an unchanged technology;
    * when the KB changed (or ``full_sync=True`` is passed), every technology is
      re-correlated. Correlation itself is idempotent
      (``CVE.objects.get_or_create`` on a unique key, events only on create), so
      a repeat run duplicates nothing (P1-008);
    * the sweep beats the running job's heartbeat and tolerates a per-technology
      failure without aborting the rest, counting what failed.
    """
    import subprocess

    from django.conf import settings

    from apps.monitoring.models import CVESyncState

    state, _ = CVESyncState.objects.get_or_create(source="cvelistV5")
    previous_count = state.record_count or 0
    previous_info = dict(state.info or {})
    # Default to "re-check everything": only a *successful* sync that reports the
    # same record count as the previous pass may narrow the work to incremental.
    kb_unchanged = False
    # Try git sync if available; never fail hard.
    try:
        import os
        import shutil

        # Use the resolved absolute path: a bare "git" relies on PATH lookup at
        # exec time, and a relative/unvalidated path in a world-writable
        # directory is a PATH-injection risk in a shared container.
        git = shutil.which("git")
        # P3-005: keep the clone out of world-writable /tmp. In a shared
        # container another user could pre-create the directory and plant files
        # that the CVE importer would then read.
        dest = os.path.join(
            str(getattr(settings, "DATA_DIR", "/var/lib/recon-monitor")), "cvelistV5"
        )
        if git and os.access(os.path.dirname(dest) or "/", os.W_OK):
            if not os.path.exists(os.path.join(dest, ".git")):
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                subprocess.run(
                    [
                        git,
                        "clone",
                        "--depth",
                        "1",
                        "https://github.com/CVEProject/cvelistV5.git",
                        dest,
                    ],
                    timeout=600,
                    capture_output=True,
                )
            else:
                subprocess.run(
                    [git, "-C", dest, "pull", "--ff-only"], timeout=600, capture_output=True
                )
            count = 0
            for _, _, files in os.walk(os.path.join(dest, "cves")):
                count += sum(1 for f in files if f.endswith(".json"))
                if count > 0:
                    break
            state.record_count = count
            info = {"path": dest, "count": count}
            # Unchanged only when we had a previous baseline, the count matches,
            # and we are looking at the same KB location.
            kb_unchanged = (
                bool(previous_count)
                and count == previous_count
                and previous_info.get("path") == dest
            )
            state.info = info
        else:
            state.info = {"note": "git unavailable; using bundled KB"}
            # A bundled KB does not change between runs, so after the first
            # pass an unchanged bundled KB may be treated as incremental.
            kb_unchanged = bool(previous_info.get("note")) and previous_count == 0
    except Exception as e:
        state.info = {"error": str(e)[:300]}
        # A failed sync must not silently skip correlation work: re-correlate
        # everything so a prior truncation cannot persist.
        kb_unchanged = False
    state.last_synced = timezone.now()
    state.save()
    # Re-correlate every known technology against (bundled or synced) KB.
    try:
        from apps.assets.models import Technology
        from services.correlation.ingest import correlate_cves_for_tech

        batch_size = int(getattr(settings, "CVE_CORRELATION_BATCH_SIZE", 500) or 500)
        # Full pass = re-check every technology. Incremental pass = re-check only
        # what could have changed: technologies never correlated before, or whose
        # fingerprint changed since their last correlation.
        full_pass = bool(full_sync) or not kb_unchanged
        processed = 0
        failed = 0
        cursor_id = 0
        # Keyset pagination: bounded memory per batch, no OFFSET scan, and it
        # keeps working while correlation writes new rows.
        while True:
            qs = Technology.all_objects.filter(pk__gt=cursor_id).order_by("pk")[:batch_size]
            batch = list(qs)
            if not batch:
                break
            for tech in batch:
                cursor_id = tech.pk
                if not full_pass and _cve_uptodate(tech):
                    continue  # already correlated and unchanged since then
                try:
                    correlate_cves_for_tech(tech)
                    processed += 1
                except Exception as e:
                    failed += 1
                    import logging

                    logging.getLogger(__name__).error(
                        "CVE correlation failed for technology %s: %s",
                        tech.pk,
                        e.__class__.__name__,
                        extra={
                            "target_id": tech.target_id,
                            "operation": "cve_correlate",
                            "status": "ERROR",
                        },
                    )
            if len(batch) < batch_size:
                break
        return {
            "synced": str(state.last_synced),
            "recorrelated": processed,
            "failed": failed,
            "mode": "full" if full_pass else "incremental",
            "batch_size": batch_size,
            "kb_unchanged": kb_unchanged,
        }
    except Exception as e:
        return {"synced": str(state.last_synced), "error": str(e)[:300]}


@shared_task(name="apps.monitoring.tasks.check_authorization_expiry")
def check_authorization_expiry():
    from datetime import timedelta

    from apps.targets.models import Target
    from services.event_engine.engine import emit_event

    now = timezone.now()
    paused = 0
    for t in Target.objects.filter(status=Target.STATUS_ACTIVE).exclude(
        authorization_expires_at=None
    ):
        # Fingerprints are state-scoped (TASK-053): the window (expires_at +
        # warning days) is part of the event state, so a stable window dedups
        # across scheduler runs while a renewal produces a fresh event.
        expires_iso = t.authorization_expires_at.isoformat()
        if t.authorization_expires_at <= now and t.authorization_status != Target.AUTH_EXPIRED:
            prev_status = t.authorization_status
            t.authorization_status = Target.AUTH_EXPIRED
            t.status = Target.STATUS_PAUSED
            t.save(update_fields=["authorization_status", "status"])
            # P0-014: expiry is the same cooperative kill switch as a pause —
            # queued work pauses, live runs are tripped and finalized when idle,
            # and RUNNING jobs detect the trip at their next check().
            from apps.jobs.tasks import _halt_work

            _halt_work(t, "AUTH_EXPIRED")
            emit_event(
                "AUTHORIZATION_EXPIRED",
                target=t,
                asset_value=t.root_domain,
                source="monitoring",
                severity="HIGH",
                evidence={"expired_at": str(t.authorization_expires_at)},
                old_state={"authorization": prev_status, "expires_at": expires_iso},
                new_state={"authorization": "EXPIRED", "expires_at": expires_iso},
            )
            paused += 1
        elif t.authorization_expires_at <= now + timedelta(days=t.auth_warning_days):
            emit_event(
                "AUTHORIZATION_EXPIRING",
                target=t,
                asset_value=t.root_domain,
                source="monitoring",
                severity="MEDIUM",
                evidence={"warning": True, "expires_at": str(t.authorization_expires_at)},
                new_state={
                    "authorization": "EXPIRING",
                    "expires_at": expires_iso,
                    "warning_days": t.auth_warning_days,
                },
            )
    return {"paused": paused}


@shared_task(name="apps.monitoring.tasks.recheck_javascript")
def recheck_javascript(target_id=None):
    """Event-triggered + periodic JS rehash: re-download, detect JS_CHANGED.

    P0-015: uses the centralized _fetch_url_for_recon (scope/SSRF + TLS policy
    honoring target.verify_tls) instead of the old CERT_NONE ssl context.
    P1-009: the sweep is **batched, not truncated**. It used to stop after the
    first 200 assets, so on a target with more than 200 scripts the remainder
    was never rechecked and nothing recorded the omission. It now walks every
    asset in keyset batches (``JS_RECHECK_BATCH_SIZE``), re-checking the job
    heartbeat per batch so a long sweep stays provably alive, and returns a
    summary of what it covered (scanned/skipped/failed) so partial coverage is
    visible instead of silent.
    """
    from django.conf import settings

    from apps.assets.models import JavaScriptAsset
    from apps.jobs.tasks import _fetch_url_for_recon, _ReconFetchSkipped
    from services.correlation.ingest import ingest_js

    qs = JavaScriptAsset.all_objects.select_related("target")
    if target_id:
        qs = qs.filter(target_id=target_id)
    batch_size = int(getattr(settings, "JS_RECHECK_BATCH_SIZE", 100) or 100)
    changed = 0
    scanned = 0
    skipped = 0
    failed = 0
    not_scannable = 0
    cursor_id = 0
    while True:
        batch = list(qs.filter(pk__gt=cursor_id).order_by("pk")[:batch_size])
        if not batch:
            break
        for js in batch:
            cursor_id = js.pk
            if not js.target.is_scannable:
                not_scannable += 1
                continue
            try:
                body = _fetch_url_for_recon(js.target, js.js_url, stage="js-recheck")
                _, outcome = ingest_js(js.target, js.js_url, body, source="recheck")
                scanned += 1
                if outcome == "JS_CHANGED":
                    changed += 1
            except _ReconFetchSkipped as e:
                skipped += 1
                logger.warning("js recheck skipped %s: %s", js.js_url[:200], e)
            except Exception as e:
                failed += 1
                logger.warning("js recheck failed %s: %s", js.js_url[:200], e)
        if len(batch) < batch_size:
            break
    return {
        "changed": changed,
        "scanned": scanned,
        "skipped": skipped,
        "failed": failed,
        "not_scannable": not_scannable,
        "batch_size": batch_size,
    }
