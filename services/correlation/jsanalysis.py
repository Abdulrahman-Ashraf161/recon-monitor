"""Staged JS analysis: DOWNLOAD->HASH->DEDUP->BEAUTIFY->JSLUICE->LINKFINDER->
SECRETFINDER->SEMGREP->RETIREJS->AGGREGATE. Per-stage logs, partial success."""

import logging
import os
import tempfile
import time

logger = logging.getLogger(__name__)

STAGE_ORDER = [
    "DOWNLOADING",
    "HASHING",
    "DEDUPLICATING",
    "BEAUTIFYING",
    "JSLUICE",
    "LINKFINDER",
    "SECRETFINDER",
    "SEMGREP",
    "RETIREJS",
    "AGGREGATING",
]


def _log(job, stage, message, level="INFO", tool=""):
    from apps.jobs.models import JSAnalysisLog

    JSAnalysisLog.objects.create(
        job=job, level=level, stage=stage, tool=tool, message=message[:1500]
    )


def _stage(job, stage, progress):
    job.current_stage = stage
    job.progress = progress
    job.save(update_fields=["current_stage", "progress"])
    try:
        from services.event_engine.engine import broadcast_job_like

        broadcast_job_like(job)
    except Exception as exc:
        # FINAL-001: the live progress update is best-effort (the row is
        # already persisted above), but a persistent failure is worth seeing.
        logger.debug(
            "js analysis progress broadcast failed for job %s: %s",
            getattr(job, "pk", None),
            exc.__class__.__name__,
        )


def _heartbeat_checker(job, interval=30.0):
    """A ``cancel_check`` that only refreshes the job heartbeat (P1-006).

    JS analyzers are not a kill-switch checkpoint (the target's scannability is
    re-checked by the orchestrator), but they do need to prove liveness while a
    single tool runs for minutes. Returning ``None`` keeps the adapter's
    fast path when heartbeating is unnecessary.
    """
    import time as _time

    last = [0.0]

    def _check():
        now = _time.monotonic()
        if now - last[0] < interval:
            return
        last[0] = now
        try:
            job.beat()
        except Exception:
            pass

    return _check


def _record_tool(
    target,
    job,
    tool_name,
    status,
    error="",
    coverage=None,
    fallback=False,
    command="",
    exit_code=None,
    stdout="",
    stderr="",
    duration_ms=None,
):
    """Persist a JS-analyzer invocation (P1-011/P1-002).

    A missing analyzer must be visible in the audit trail, not just in a log
    line: a run where every optional analyzer is absent must never be able to
    claim equivalent coverage. The row carries the same evidence set as every
    other tool execution (redacted command, exit code, stdout/stderr refs).
    """
    from django.utils import timezone as _tz

    from apps.jobs.models import ToolExecution
    from apps.jobs.tasks import _store_tool_output

    now = _tz.now()
    try:
        return ToolExecution.objects.create(
            target=target,
            scan_run=getattr(job, "scan_run", None),
            job=None,
            tool_name=tool_name,
            status=status,
            started_at=now,
            finished_at=now,
            error=str(error)[:2000] if error else "",
            fallback_used=fallback,
            coverage=coverage or {},
            command=(command or "")[:4000],
            exit_code=exit_code,
            stdout_reference=_store_tool_output(tool_name, "out", stdout),
            stderr_reference=_store_tool_output(tool_name, "err", stderr),
            duration=(round(duration_ms / 1000.0, 3) if duration_ms is not None else None),
        )
    except Exception as exc:  # P1-003: never silent -- surface as a failure signal
        from apps.jobs.tasks import _note_evidence_failure

        _note_evidence_failure(
            target, tool_name, status, exc, run=getattr(job, "scan_run", None), job=None
        )
        return None


def _run_tool(adapter_cls, *args, stage, job, timeout=180, **kwargs):
    """Run one analyzer; never raises. Returns (ok, data)."""
    from services.tool_adapters.adapters import ADAPTERS  # noqa

    inst = adapter_cls()
    if not inst.is_available():
        _log(
            job,
            stage,
            f"{inst.tool_name} not installed, skipped",
            level="WARNING",
            tool=inst.tool_name,
        )
        job.stages[stage] = "SKIPPED"
        # P1-011: absent analyzer = no coverage for this dimension, recorded
        # explicitly so the run can be reported as degraded rather than complete.
        _record_tool(
            job.target,
            job,
            inst.tool_name,
            "SKIPPED",
            error=f"{inst.binary} not installed",
            command=inst.binary,
            coverage={
                "analyzed": False,
                "degraded": True,
                "stage": stage,
                "reason": "not installed",
            },
        )
        return True, []
    start = time.time()
    _log(job, stage, f"{inst.tool_name} start", tool=inst.tool_name)
    job.beat()
    try:
        res = inst.run(
            *args,
            timeout=timeout,
            **kwargs,
            # P1-006: a long analyzer (semgrep on a bundle can run
            # minutes) must keep refreshing liveness so the stall
            # detector can tell "working" from "wedged".
            cancel_check=_heartbeat_checker(job),
        )
    except Exception as e:
        _log(job, stage, f"{inst.tool_name} crashed: {e}", level="ERROR", tool=inst.tool_name)
        job.stages[stage] = "FAILED"
        _record_tool(
            job.target,
            job,
            inst.tool_name,
            "FAILED",
            error=e,
            command=inst.binary,
            coverage={"analyzed": False, "stage": stage},
        )
        return False, []
    dur = int((time.time() - start) * 1000)
    if res.status == "FAILED":
        _log(
            job,
            stage,
            f"{inst.tool_name} failed: {res.error[:300]} ({dur}ms)",
            level="ERROR",
            tool=inst.tool_name,
        )
        job.stages[stage] = "FAILED"
        _record_tool(
            job.target,
            job,
            inst.tool_name,
            "FAILED",
            error=res.error,
            command=res.command or inst.binary,
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            duration_ms=dur,
            coverage={"analyzed": False, "stage": stage},
        )
        return False, []
    _log(
        job,
        stage,
        f"{inst.tool_name} complete: {len(res.data)} items ({dur}ms)",
        tool=inst.tool_name,
    )
    job.stages[stage] = "COMPLETED" if res.status == "COMPLETED" else "PARTIAL"
    _record_tool(
        job.target,
        job,
        inst.tool_name,
        res.status,
        error=res.error,
        command=res.command or inst.binary,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
        duration_ms=dur,
        coverage={
            "analyzed": True,
            "items": len(res.data or []),
            "stage": stage,
            "duration_ms": dur,
        },
    )
    return True, res.data


def run_analysis(analysis_job_id):
    """Execute all stages. Returns final status string."""
    from django.utils import timezone

    from apps.jobs.models import JSAnalysisJob
    from services.event_engine.engine import emit_event

    try:
        job = JSAnalysisJob.objects.select_related("js", "target").get(pk=analysis_job_id)
    except JSAnalysisJob.DoesNotExist:
        return "SKIPPED"
    js, target = job.js, job.target
    if not target.is_scannable:
        job.status = "FAILED"
        job.error = "target not scannable"
        job.save(update_fields=["status", "error"])
        return "FAILED"
    job.status = "RUNNING"
    job.started_at = timezone.now()
    job.stages = {}
    job.save()
    emit_event(
        "JS_ANALYSIS_STARTED",
        target=target,
        asset_type="JS_FILE",
        asset_id=js.id,
        asset_value=js.js_url,
        source="js-worker",
        evidence={"job": job.id},
    )
    failures = 0
    body = b""
    # DOWNLOAD
    _stage(job, "DOWNLOADING", 5)
    try:
        # P0-016: centralized scope/SSRF + TLS fetch (honors target.verify_tls)
        # instead of the old CERT_NONE ssl context.
        from apps.jobs.tasks import _fetch_url_for_recon, _ReconFetchSkipped

        try:
            body = _fetch_url_for_recon(
                target, js.js_url, stage="js-analysis", timeout=30, max_bytes=5000000
            )
        except _ReconFetchSkipped as e:
            _log(job, "DOWNLOADING", f"download skipped by policy: {e}", level="WARNING")
            job.stages["DOWNLOADING"] = "FAILED"
            return _finish(job, "FAILED", f"download blocked: {e}")
        _log(job, "DOWNLOADING", f"download complete: {len(body)} bytes")
        job.stages["DOWNLOADING"] = "COMPLETED"
    except Exception as e:
        _log(job, "DOWNLOADING", f"download failed: {e}", level="ERROR")
        job.stages["DOWNLOADING"] = "FAILED"
        return _finish(job, "FAILED", f"download failed: {e}")
    # HASH
    _stage(job, "HASHING", 12)
    from services.correlation.jsintel import sha256_bytes

    digest = sha256_bytes(body)
    _log(job, "HASHING", f"sha256: {digest[:16]}...")
    job.stages["HASHING"] = "COMPLETED"
    # DEDUP
    _stage(job, "DEDUPLICATING", 18)
    if js.sha256 == digest and job.trigger not in ("manual", "recheck"):
        _log(
            job,
            "DEDUPLICATING",
            "content unchanged since stored version; analyzers still run for fresh findings",
        )
    job.stages["DEDUPLICATING"] = "COMPLETED"
    # BEAUTIFY
    _stage(job, "BEAUTIFYING", 24)
    from services.correlation.jsintel import beautify

    text = body.decode("utf-8", errors="ignore")
    beautified = beautify(text)
    _log(job, "BEAUTIFYING", "beautify complete")
    job.stages["BEAUTIFYING"] = "COMPLETED"
    # write temp file for file-based analyzers
    tmpdir = tempfile.mkdtemp(prefix="jsanalysis_")
    js_path = os.path.join(tmpdir, "target.js")
    try:
        with open(js_path, "w") as f:
            f.write(beautified)
    except Exception as e:
        return _finish(job, "FAILED", f"temp write failed: {e}")
    from services.tool_adapters.adapters import (
        JsluiceAdapter,
        LinkfinderAdapter,
        RetirejsAdapter,
        SecretfinderAdapter,
        SemgrepAdapter,
    )

    results = {}
    for i, (stage, cls) in enumerate(
        [
            ("JSLUICE", JsluiceAdapter),
            ("LINKFINDER", LinkfinderAdapter),
            ("SECRETFINDER", SecretfinderAdapter),
            ("SEMGREP", SemgrepAdapter),
            ("RETIREJS", RetirejsAdapter),
        ]
    ):
        _stage(job, stage, 24 + int(66 * (i + 1) / 6))
        if stage == "SEMGREP":
            ok, data = _run_tool(cls, tmpdir, stage=stage, job=job, timeout=300)
        elif stage == "RETIREJS":
            ok, data = _run_tool(cls, tmpdir, stage=stage, job=job, timeout=180)
        else:
            ok, data = _run_tool(cls, js_path, stage=stage, job=job, timeout=180)
        job.save(update_fields=["stages"])
        if not ok:
            failures += 1
        results[stage] = data
    # AGGREGATE
    _stage(job, "AGGREGATING", 95)
    try:
        _aggregate(job, js, target, text, results)
        job.stages["AGGREGATING"] = "COMPLETED"
        _log(job, "AGGREGATING", "aggregation complete")
    except Exception as e:
        logger.exception("js aggregate failed")
        _log(job, "AGGREGATING", f"aggregation failed: {e}", level="ERROR")
        failures += 1
        job.stages["AGGREGATING"] = "FAILED"
    finally:
        try:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
    final = "PARTIAL" if failures else "COMPLETED"
    # P1-011: analyzers that were never installed produce no findings for their
    # dimension. A run with skipped analyzers is degraded coverage, never a
    # complete analysis -- the raw text still yields routes/secrets, but the
    # tool-backed dimensions were not covered.
    skipped = [
        s
        for s in ("JSLUICE", "LINKFINDER", "SECRETFINDER", "SEMGREP", "RETIREJS")
        if job.stages.get(s) == "SKIPPED"
    ]
    if skipped and final == "COMPLETED":
        final = "PARTIAL"
    if job.stages.get("DOWNLOADING") == "FAILED":
        final = "FAILED"
    # P1-011: name the skipped analyzers on the job so a degraded analysis is
    # self-describing rather than a bare PARTIAL.
    error = f"degraded coverage: {', '.join(skipped)} not installed" if skipped else ""
    return _finish(job, final, error)


def _aggregate(job, js, target, text, results):
    from urllib.parse import urljoin, urlparse

    from apps.assets.models import APIEndpoint, JavaScriptFinding
    from services.correlation.jsintel import (
        detect_js_libraries,
        extract_routes,
        extract_secret_candidates,
    )
    from services.event_engine.engine import emit_event
    from services.normalization.urls import canonicalize_url, classify_api

    routes = extract_routes(text)
    jsluice_urls = [
        r.get("url") for r in results.get("JSLUICE", []) if isinstance(r, dict) and r.get("url")
    ]
    linkfinder_eps = [
        r.get("endpoint")
        for r in results.get("LINKFINDER", [])
        if isinstance(r, dict) and r.get("endpoint")
    ]
    all_routes = list(dict.fromkeys(routes + [u for u in (jsluice_urls + linkfinder_eps) if u]))[
        :300
    ]
    # drop jsluice JSON blobs / non-path noise, keep real endpoints
    clean = []
    for r in all_routes:
        s = (r or "").strip()
        if not s or s.startswith("{") or len(s) > 500:
            continue
        if s.startswith(("http", "/")):
            clean.append(s)
    all_routes = clean[:300]
    # resolve relative endpoints against JS host
    base = f"https://{js.host}/"
    new_apis = 0
    for ep in all_routes:
        abs_url = ep if ep.startswith("http") else urljoin(base, ep)
        canon = canonicalize_url(abs_url)
        if not canon:
            continue
        is_api, api_type, auth_hints = classify_api(canon)
        if is_api:

            obj, created = APIEndpoint.objects.get_or_create(
                target=target,
                url=canon[:4000],
                method="GET",
                defaults={
                    "host": urlparse(canon).hostname or "",
                    "api_type": api_type,
                    "auth_indicators": auth_hints,
                    "source": "js-analysis",
                },
            )
            if created:
                new_apis += 1
                emit_event(
                    "NEW_API_ENDPOINT",
                    target=target,
                    asset_type="API_ENDPOINT",
                    asset_id=obj.id,
                    asset_value=canon[:500],
                    source="js-analysis",
                    evidence={"api_type": api_type, "via_js": js.js_url},
                )
    secrets = extract_secret_candidates(text)
    for s in secrets:
        JavaScriptFinding.objects.get_or_create(
            js=js,
            finding_type=s["type"],
            location="body",
            defaults={
                "evidence_preview": (s.get("match_preview") or "") + " (redacted)",
                "evidence_full": s.get("full", "")[:2000],
                "source_tool": "js-analysis",
                "confidence": "candidate",
                "status": "candidate",
            },
        )
    semgrep_count = len(results.get("SEMGREP", []))
    for r in results.get("SEMGREP", [])[:50]:
        if not isinstance(r, dict):
            continue
        JavaScriptFinding.objects.get_or_create(
            js=js,
            finding_type="sast:" + str(r.get("check_id", "finding"))[:100],
            location=str(r.get("path", ""))[:200],
            defaults={
                "evidence_preview": str(r.get("extra", {}).get("message", ""))[:300],
                "evidence_full": str(r)[:2000],
                "source_tool": "semgrep",
                "confidence": "candidate",
                "status": "candidate",
            },
        )
    retire_count = len(results.get("RETIREJS", []))
    js.routes = all_routes
    js.dependencies = detect_js_libraries(text)
    js.secret_candidates = len(secrets)
    js.save(update_fields=["routes", "dependencies", "secret_candidates", "last_seen"])
    job.stats = {
        "endpoints": len(all_routes),
        "new_apis": new_apis,
        "secrets": len(secrets),
        "semgrep": semgrep_count,
        "retirejs": retire_count,
        "jsluice": len(jsluice_urls),
        "linkfinder": len(linkfinder_eps),
    }
    job.save(update_fields=["stats", "stages"])
    emit_event(
        "JS_ANALYSIS_COMPLETED",
        target=target,
        asset_type="JS_FILE",
        asset_id=js.id,
        asset_value=js.js_url,
        source="js-worker",
        evidence={"job": job.id, "stats": job.stats, "status": job.status},
    )


def _finish(job, status, error):
    from django.utils import timezone

    job.status = status
    job.current_stage = "DONE" if status in ("COMPLETED", "PARTIAL") else status
    job.progress = 100 if status in ("COMPLETED", "PARTIAL") else job.progress
    job.error = (error or "")[:1000]
    job.finished_at = timezone.now()
    job.save()
    try:
        from services.event_engine.engine import broadcast_job_like

        broadcast_job_like(job)
    except Exception as exc:
        # FINAL-001: the live progress update is best-effort (the row is
        # already persisted above), but a persistent failure is worth seeing.
        logger.debug(
            "js analysis progress broadcast failed for job %s: %s",
            getattr(job, "pk", None),
            exc.__class__.__name__,
        )
    return status
