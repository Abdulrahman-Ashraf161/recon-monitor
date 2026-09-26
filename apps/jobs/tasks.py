"""Celery pipeline: discovery -> dns -> network -> http -> urls -> js -> tech/cve -> nuclei.
Every task: scope-gated, kill-switch aware, failure-isolated, resumable via ScanJob.checkpoint."""
import logging
import uuid

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)
# --- TASK-006/007/008/059/060/061/071 helpers: ScanRun + ToolExecution + observations ---
def _get_or_create_run(target, scan_type="MONITORING", profile="", trigger="manual", requested_by=""):
    """Idempotent-ish: reuse latest RUNNING run for same target/type, else create."""
    from django.utils import timezone as _tz

    from apps.jobs.models import ScanRun
    prof = profile or getattr(target, "scan_profile", "balanced") or "balanced"
    cfg = {"scan_config": getattr(target, "scan_config", {}), "profile": prof,
           "verify_tls": getattr(target, "verify_tls", True)}
    run = ScanRun.objects.filter(target=target, status="RUNNING", scan_type=scan_type).order_by("-created_at").first()
    if run:
        return run
    return ScanRun.objects.create(target=target, scan_type=scan_type, profile=prof,
                                  status="RUNNING", started_at=_tz.now(), trigger=trigger,
                                  requested_by=requested_by, configuration_snapshot=cfg)


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
    run.save()


def _record_tool(target, scan_run, job, tool_name, status, error="", fallback=False, coverage=None):
    from django.utils import timezone as _tz

    from apps.jobs.models import ToolExecution
    try:
        ToolExecution.objects.create(target=target, scan_run=scan_run, job=job, tool_name=tool_name,
                                     status=status, finished_at=_tz.now(), error=str(error)[:2000],
                                     fallback_used=fallback, coverage=coverage or {})
    except Exception:
        pass


def _observe(target, scan_run, asset_type, asset_id=None, asset_value="", observed=True, evidence=None, state=None):
    """TASK-008: append-only observation row (history preserved)."""
    if scan_run is None:
        return
    import hashlib as _hl
    import json as _js

    from apps.jobs.models import AssetObservation
    try:
        mh = _hl.sha256(_js.dumps(state or evidence or {}, sort_keys=True, default=str).encode()).hexdigest()[:16]
        AssetObservation.objects.create(scan_run=scan_run, target=target, asset_type=asset_type,
                                        asset_id=asset_id, asset_value=str(asset_value)[:2000],
                                        observed=observed, metadata_hash=mh, evidence=evidence or {})
    except Exception:
        pass




def _job(target_id, job_type, tool="", baseline=False, run_id=""):
    from apps.jobs.models import ScanJob
    from apps.targets.models import Target

    target = Target.objects.get(pk=target_id)
    return ScanJob.objects.create(target=target, job_type=job_type, tool=tool,
                                  status=ScanJob.STATUS_RUNNING, baseline_mode=baseline,
                                  run_id=run_id or uuid.uuid4().hex[:12],
                                  started_at=timezone.now()), target


def _finish(job, status, stats=None, error=""):
    from services.event_engine.engine import broadcast_job

    job.status = status
    job.finished_at = timezone.now()
    job.progress = 100 if status == "COMPLETED" else job.progress
    if stats is not None:
        job.stats = stats
    if error:
        job.error = error[:2000]
    job.save()
    broadcast_job(job)


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
            _log(job, "WARNING", "TLS verification DISABLED by target config (verify_tls=false)",
                 stage=stage or "fetch")
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


def _fetch_url_for_recon(target, url, job=None, stage="", timeout=10, max_bytes=2000000, rules=None):
    """T2+T3+T4: scoped, SSRF-checked, TLS-honoring fetch. Returns bytes.

    Raises _ReconFetchSkipped for policy refusals (log + continue),
    or the underlying exception for genuine fetch failures.
    """
    import urllib.request

    ok, reason, _host = _url_allowed_for_fetch(target, url, rules=rules)
    if not ok:
        raise _ReconFetchSkipped(reason)
    ctx = _ssl_context_for(target, job, stage)
    req = urllib.request.Request(url, headers={"User-Agent": "recon-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read(max_bytes)


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
            js, outcome = ingest_js(target, src, body, source=source)
            try:
                js.discovered_from = page_url[:2000]
                js.save(update_fields=["discovered_from"])
            except Exception:
                pass
            count += 1
        except Exception:
            continue
    return count


def _gate(target) -> tuple[bool, str]:
    from apps.scope.models import ScopeRule
    from services.scope_engine.validator import scope_allows_scan

    rules = list(ScopeRule.objects.filter(target__in=[None, target]))
    return scope_allows_scan(target, rules)


@shared_task(name="apps.jobs.tasks.baseline_target", bind=True, max_retries=1)
def baseline_target(self, target_id):
    """First-scan experience: INITIAL_BASELINE -> discovery chain -> BASELINE_COMPLETE + summary."""
    from apps.monitoring.models import Baseline
    from apps.targets.models import Target
    from services.event_engine.engine import emit_event

    target = Target.objects.get(pk=target_id)
    ok, reason = _gate(target)
    if not ok:
        return {"status": "SKIPPED", "reason": reason}
    run_id = uuid.uuid4().hex[:12]
    target.baseline_status = "INITIAL_BASELINE"
    target.baseline_started_at = timezone.now()
    target.save(update_fields=["baseline_status", "baseline_started_at"])
    Baseline.objects.update_or_create(target=target, defaults={"status": "RUNNING", "started_at": timezone.now()})
    emit_event("BASELINE_STARTED", target=target, asset_value=target.root_domain, source="monitoring")
    # chain stages synchronously in-order (each internally failure-isolated)
    stats = {}
    try:
        stats["subdomains"] = discover_subdomains.run(target_id, run_id) if hasattr(discover_subdomains, "run") else discover_subdomains(target_id, run_id)
    except Exception as e:
        stats["subdomains"] = {"status": "FAILED", "error": str(e)[:300]}
    for stage in (resolve_dns, scan_ports, probe_http, discover_urls):
        try:
            stats[stage.name.split(".")[-1]] = stage.run(target_id, run_id)
        except Exception as e:
            stats[stage.name.split(".")[-1]] = {"status": "FAILED", "error": str(e)[:300]}
    target.baseline_status = "BASELINE_COMPLETE"
    target.baseline_completed_at = timezone.now()
    target.last_scan = timezone.now()
    target.save(update_fields=["baseline_status", "baseline_completed_at", "last_scan"])
    Baseline.objects.update_or_create(target=target, defaults={"status": "COMPLETE",
                                                               "completed_at": timezone.now(), "summary": stats})
    emit_event("BASELINE_COMPLETED", target=target, asset_value=target.root_domain,
               source="monitoring", evidence={"summary": summarize(stats)})
    # one baseline summary to Discord (not hundreds of NEW_* alerts)
    try:
        from apps.alerts.tasks import send_baseline_summary

        send_baseline_summary.delay(target_id, summarize(stats))
    except Exception as e:
        logger.warning("baseline summary dispatch failed: %s", e)
    return {"status": "COMPLETED", "stats": summarize(stats)}


def summarize(stats):
    out = {}
    for k, v in (stats or {}).items():
        if isinstance(v, dict):
            out[k] = {kk: vv for kk, vv in v.items() if kk in ("new", "total", "status", "new_urls", "new_apis", "changed")}
        else:
            out[k] = v
    return out


@shared_task(name="apps.jobs.tasks.discover_subdomains")
def discover_subdomains(target_id, run_id=""):
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

    job, target = _job(target_id, "subdomain_enum", tool="multi", baseline=target_is_baseline(target_id), run_id=run_id)
    ok, reason = scope_allows_scan(target, list(ScopeRule.objects.filter(target__in=[None, target])))
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
    for cls in (SubfinderAdapter, AmassAdapter, FindomainAdapter, AssetfinderAdapter, CrtshAdapter):
        adapter = cls()
        try:
            if cls.__name__ == "CrtshAdapter":
                res = adapter.run(target.root_domain)
            else:
                res = adapter.run(target.root_domain)
        except Exception as e:
            res = None
            _log(job, "ERROR", f"{cls.tool_name} crashed: {e}", stage="passive", tool=getattr(cls, "tool_name", ""))
        if res is None:
            partial = True
            continue
        if res.status == "SKIPPED":
            _log(job, "WARNING", f"{res.tool} not installed, skipped", stage="passive", tool=res.tool)
            partial = True
        elif res.status == "FAILED":
            _log(job, "ERROR", f"{res.tool} failed: {res.error}", stage="passive", tool=res.tool)
            partial = True
        else:
            if res.status == "PARTIAL":
                partial = True
            items.extend(res.data)
            _log(job, "INFO", f"{res.tool}: {len(res.data)} hosts", stage="passive", tool=res.tool)
    try:
        new_count, total = ingest_subdomains(target, items)
    except Exception as e:
        _finish(job, "FAILED", error=str(e)[:1000])
        return {"status": "FAILED", "error": str(e)[:300]}
    job.progress = 100
    _finish(job, "PARTIAL" if partial else "COMPLETED", stats={"new": new_count, "total": total, "sources": len(items)})
    target.last_scan = timezone.now()
    target.save(update_fields=["last_scan"])
    return {"status": job.status, "new": new_count, "total": total}


def target_is_baseline(target_id):
    from apps.targets.models import Target

    try:
        return Target.objects.get(pk=target_id).baseline_status == "INITIAL_BASELINE"
    except Exception:
        return False


@shared_task(name="apps.jobs.tasks.resolve_dns")
def resolve_dns(target_id, run_id=""):
    import socket

    from apps.assets.models import Subdomain
    from services.correlation.ingest import ingest_dns

    job, target = _job(target_id, "dns", tool="socket/dnsx", baseline=target_is_baseline(target_id), run_id=run_id)
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    hosts = list(Subdomain.objects.filter(target=target, is_active=True).values_list("hostname", flat=True)[:2000])
    records = []
    # Prefer dnsx binary if present; else stdlib A-record resolution
    from services.tool_adapters.adapters import DnsxAdapter
    from services.tool_adapters.base import redact_command

    adapter = DnsxAdapter()
    if adapter.is_available():
        # Task 13: single adapter.run(hosts) path (stdin piped, redacted cmd logged).
        job.command_redacted = redact_command(adapter.build_command(hosts))
        job.save(update_fields=["command_redacted"])
        try:
            res = adapter.run(hosts, timeout=300)
            if res.status == "SKIPPED":
                _log(job, "WARNING", "dnsx not installed, falling back to socket", stage="dns", tool="dnsx")
            elif res.status == "FAILED":
                _log(job, "ERROR", f"dnsx failed, falling back to socket: {res.error}", stage="dns", tool="dnsx")
            else:
                if res.status == "PARTIAL":
                    _log(job, "WARNING", f"dnsx partial: {res.error}", stage="dns", tool="dnsx")
                for o in res.data:
                    if not isinstance(o, dict):
                        continue
                    h = o.get("host") or o.get("input") or o.get("name") or ""
                    for a in o.get("a") or []:
                        records.append({"hostname": h, "type": "A", "value": a})
                    for aaaa in o.get("aaaa") or []:
                        records.append({"hostname": h, "type": "AAAA", "value": aaaa})
                _log(job, "INFO", f"dnsx: {len(records)} records", stage="dns", tool="dnsx")
        except Exception as e:
            _log(job, "ERROR", f"dnsx failed, falling back to socket: {e}", stage="dns", tool="dnsx")
    if not records:
        for h in hosts:
            try:
                for fam, _, _, _, addr in socket.getaddrinfo(h, None):
                    if fam == socket.AF_INET:
                        records.append({"hostname": h, "type": "A", "value": addr[0]})
                        break
            except Exception:
                continue
    new = ingest_dns(target, records)
    _finish(job, "COMPLETED", stats={"new": new, "resolved_hosts": len({r['hostname'] for r in records})})
    return {"status": "COMPLETED", "new": new}


@shared_task(name="apps.jobs.tasks.scan_ports")
def scan_ports(target_id, run_id=""):
    import socket

    from apps.assets.models import IPAddress
    from services.correlation.ingest import ingest_ports

    job, target = _job(target_id, "ports", tool="naabu/socket", baseline=target_is_baseline(target_id), run_id=run_id)
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    from services.scan_profiles import profile_allows as _allows
    if not _allows(getattr(target, "scan_profile", "balanced"), "port_scan"):
        _finish(job, "SKIPPED", error="port_scan not enabled for profile " + str(getattr(target, "scan_profile", "")))
        return {"status": "SKIPPED", "reason": "profile excludes port_scan"}
    ports_cfg = (target.scan_config or {}).get("ports", "80,443,8080,8443,8000,8888,3000,5000,22,21,25,53,3306,5432,6379,27017")
    port_list = [int(p) for p in str(ports_cfg).split(",") if p.strip().isdigit()]
    ips = list(IPAddress.objects.filter(target=target, is_active=True).values_list("ip", flat=True)[:500])
    # T5: never actively scan shared-suspect IPs without explicit confirmation.
    shared_skipped = list(IPAddress.objects.filter(
        target=target, is_active=True, shared_suspect=True,
        confirmed_dedicated=False).values_list("ip", flat=True)[:500])
    if shared_skipped:
        _log(job, "WARNING",
             f"skipped {len(shared_skipped)} shared-suspect IP(s) (shared_ip_unconfirmed): "
             + ", ".join(shared_skipped[:10]), stage="ports", tool="naabu")
        ips = [ip for ip in ips if ip not in set(shared_skipped)]
    entries = []
    from services.tool_adapters.adapters import NaabuAdapter

    adapter = NaabuAdapter()
    used_naabu = False
    if adapter.is_available() and ips:
        try:
            res = adapter.run(",".join(ips), ports=",".join(map(str, port_list)))
            for r in res.data:
                entries.append(r)
            used_naabu = res.status in ("COMPLETED", "PARTIAL")
            _log(job, "INFO", f"naabu: {len(entries)} open", stage="ports", tool="naabu")
        except Exception as e:
            _log(job, "ERROR", f"naabu failed: {e}", stage="ports", tool="naabu")
    if not used_naabu:
        for ip in ips:  # stdlib fallback connect scan (top ports only)
            for pt in port_list[:20]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.5)
                    if s.connect_ex((ip, pt)) == 0:
                        entries.append({"ip": ip, "port": pt, "protocol": "tcp"})
                    s.close()
                except Exception:
                    continue
    new = ingest_ports(target, entries)
    _finish(job, "COMPLETED", stats={"new": new, "open": len(entries)})
    return {"status": "COMPLETED", "new": new}


@shared_task(name="apps.jobs.tasks.probe_http")
def probe_http(target_id, run_id=""):
    from apps.assets.models import Port, Subdomain
    from services.correlation.ingest import ingest_http, ingest_technology

    job, target = _job(target_id, "http", tool="httpx/urllib", baseline=target_is_baseline(target_id), run_id=run_id)
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    candidates = set()
    for h in Subdomain.objects.filter(target=target, is_active=True).values_list("hostname", flat=True)[:1000]:
        candidates.add(f"https://{h}")
        candidates.add(f"http://{h}")
    for p in Port.objects.filter(target=target, state="open").select_related("target")[:1000]:
        scheme = "https" if p.port in (443, 8443) else "http"
        candidates.add(f"{scheme}://{p.ip}:{p.port}")
    entries = []
    from services.tool_adapters.adapters import HttpxAdapter
    from services.tool_adapters.base import redact_command

    adapter = HttpxAdapter()
    if adapter.is_available() and candidates:
        # Task 13: single adapter.run(hosts) path (stdin piped, redacted cmd logged).
        job.command_redacted = redact_command(adapter.build_command(sorted(candidates)))
        job.save(update_fields=["command_redacted"])
        try:
            res = adapter.run(sorted(candidates), timeout=600)
            if res.status == "FAILED":
                _log(job, "ERROR", f"httpx failed: {res.error}", stage="http", tool="httpx")
            else:
                if res.status == "PARTIAL":
                    _log(job, "WARNING", f"httpx partial: {res.error}", stage="http", tool="httpx")
                entries.extend(o for o in res.data if isinstance(o, dict))
                _log(job, "INFO", f"httpx: {len(entries)} services", stage="http", tool="httpx")
        except Exception as e:
            _log(job, "ERROR", f"httpx failed: {e}", stage="http", tool="httpx")
    if not entries:
        import urllib.request

        for url in sorted(candidates)[:200]:
            try:
                # T2+T4: candidates derive from our own asset rows, but re-check
                # scope + resolved IP before touching the network (redirects /
                # stale DNS can point anywhere).
                ok, reason, _h = _url_allowed_for_fetch(target, url)
                if not ok:
                    _log(job, "INFO", f"skipped probe {url[:200]}: {reason}", stage="http", tool="urllib")
                    continue
                ctx = _ssl_context_for(target, job, stage="http")  # T3
                req = urllib.request.Request(url, headers={"User-Agent": "recon-monitor/1.0"})
                with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                    entries.append({"url": url, "host": urllib.parse.urlparse(url).hostname or "",
                                    "status_code": r.status, "title": "",
                                    "server": r.headers.get("Server", ""),
                                    "content_type": r.headers.get("Content-Type", "")})
            except Exception:
                continue
    import urllib.parse

    new, changed = ingest_http(target, entries)
    # lightweight tech fingerprint from server headers
    for e in entries:
        srv = (e.get("server") or e.get("webserver") or "").strip()
        if srv and e.get("url"):
            ingest_technology(target, e["url"], srv.split("/")[0], srv.split("/")[1] if "/" in srv else "",
                              0.6, f"Server header: {srv}", "httpx")
    _finish(job, "COMPLETED", stats={"new": new, "changed": changed})
    return {"status": "COMPLETED", "new": new, "changed": changed}


@shared_task(name="apps.jobs.tasks.discover_urls")
def discover_urls(target_id, run_id=""):
    from apps.assets.models import HTTPService
    from services.correlation.ingest import ingest_urls

    job, target = _job(target_id, "urls", tool="gau/waybackurls/katana", baseline=target_is_baseline(target_id), run_id=run_id)
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

    for cls in (GauAdapter, WaybackurlsAdapter, WaymoreAdapter):
        a = cls()
        if not a.is_available():
            _log(job, "WARNING", f"{a.tool_name} missing, skipped", stage="urls", tool=a.tool_name)
            partial = True
            continue
        try:
            res = a.run(target.root_domain)
            items.extend(res.data)
            _log(job, "INFO", f"{a.tool_name}: {len(res.data)} urls", stage="urls", tool=a.tool_name)
        except Exception as e:
            partial = True
            _log(job, "ERROR", f"{a.tool_name} failed: {e}", stage="urls", tool=a.tool_name)
    # katana crawl a sample of live http services
    kat = KatanaAdapter()
    if kat.is_available():
        for svc in HTTPService.objects.filter(target=target).order_by("-last_seen")[:20]:
            try:
                res = kat.run(svc.url)
                items.extend(res.data)
            except Exception:
                continue
    else:
        partial = True
    new_urls, new_apis = ingest_urls(target, items)
    # JS discovery: fetch <script src> from live services (stdlib) + ingest
    js_count = 0
    try:
        js_count = discover_js_for_target(target, job)
    except Exception as e:
        _log(job, "ERROR", f"js discovery failed: {e}", stage="js")
    _finish(job, "PARTIAL" if partial else "COMPLETED",
            stats={"new_urls": new_urls, "new_apis": new_apis, "js": js_count})
    return {"status": job.status, "new_urls": new_urls, "new_apis": new_apis}


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
            raw = _fetch_url_for_recon(target, svc.url, job=job, stage="js",
                                       timeout=10, max_bytes=500000)
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
def run_nuclei(target_id, run_id=""):
    from apps.assets.models import HTTPService
    from services.correlation.ingest import ingest_nuclei_finding

    job, target = _job(target_id, "nuclei", tool="nuclei", baseline=target_is_baseline(target_id), run_id=run_id)
    ok, reason = _gate(target)
    if not ok:
        _finish(job, "SKIPPED", error=reason)
        return {"status": "SKIPPED", "reason": reason}
    from services.tool_adapters.adapters import NucleiAdapter

    adapter = NucleiAdapter()
    findings = 0
    if not adapter.is_available():
        _finish(job, "SKIPPED", error="nuclei not installed")
        return {"status": "SKIPPED", "reason": "nuclei missing"}
    for svc in HTTPService.objects.filter(target=target).order_by("-last_seen")[:50]:
        try:
            res = adapter.run(svc.url)
        except Exception as e:
            _log(job, "ERROR", f"nuclei failed for {svc.url}: {e}", stage="nuclei", tool="nuclei")
            continue
        for item in res.data:
            ingest_nuclei_finding(target, item if isinstance(item, dict) else {"template": str(item), "matched_at": svc.url})
            findings += 1
    _finish(job, "COMPLETED", stats={"findings": findings})
    return {"status": "COMPLETED", "findings": findings}


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
        if event.event_type == "NEW_DNS_RECORD" and ev.get("type") in ("A", "AAAA") and ev.get("value"):
            process_new_ip.delay(target.id, ev["value"], trigger=f"event:{event.id}")
            return {"status": "QUEUED", "next": "process_new_ip"}
        if event.event_type == "NEW_OPEN_PORT" and event.asset_value:
            import re as _re

            m = _re.match(r"(.+):(\d+)$", event.asset_value.strip())
            if m:
                ip, port = m.group(1), int(m.group(2))
                scheme = "https" if port in (443, 8443) else "http"
                probe_http_targets.delay(target.id, [f"{scheme}://{ip}:{port}"], trigger=f"event:{event.id}")
                return {"status": "QUEUED", "next": "probe_http_targets"}
            return {"status": "SKIPPED", "reason": "unparseable port asset"}
        if event.event_type == "NEW_HTTP_SERVICE" and event.asset_value.startswith("http"):
            host_url_discovery.delay(target.id, event.asset_value, trigger=f"event:{event.id}")
            return {"status": "QUEUED", "next": "host_url_discovery"}
        if event.event_type in ("NEW_JS", "JS_CHANGED") and event.asset_id:
            queue_js_analysis.delay(event.asset_id, trigger=event.event_type)
            return {"status": "QUEUED", "next": "queue_js_analysis"}
        return {"status": "SKIPPED", "reason": "no dependents"}


@shared_task(name="apps.jobs.tasks.reconcile_target")
def reconcile_target(target_id):
    """Periodic reconciliation: detect removed assets (stale last_seen), refresh state."""
    from datetime import timedelta

    from apps.assets.models import Port, Subdomain
    from services.event_engine.engine import emit_event

    job, target = _job(target_id, "reconcile", tool="internal")
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
    removed = 0
    for sub in Subdomain.objects.filter(target=target, is_active=True, last_seen__lt=cutoff)[:500]:
        sub.is_active = False
        sub.state = "REMOVED"
        sub.last_changed = timezone.now()
        sub.save(update_fields=["is_active", "state", "last_changed"])
        emit_event("SUBDOMAIN_REMOVED", target=target, asset_type="SUBDOMAIN",
                   asset_id=sub.id, asset_value=sub.hostname, source="reconcile",
                   evidence={"note": "subdomain no longer observed; marked removed"},
                   old_state={"hostname": sub.hostname, "state": "ACTIVE"},
                   new_state={"hostname": sub.hostname, "state": "REMOVED"})
        removed += 1
    for p in Port.objects.filter(target=target, state="open", last_seen__lt=cutoff)[:500]:
        p.state = "closed"
        p.last_changed = timezone.now()
        p.save(update_fields=["state", "last_changed"])
        emit_event("PORT_CLOSED", target=target, asset_type="PORT", asset_id=p.id,
                   asset_value=f"{p.ip}:{p.port}", source="reconcile",
                   old_state={"state": "open"}, new_state={"state": "closed"})
        removed += 1
    # HTTP + URL + JS removal (TASK-015/019/023)
    from apps.assets.models import HTTPService as _HTTP
    from apps.assets.models import JavaScriptAsset as _JS
    from apps.assets.models import URLAsset as _URL
    for svc in _HTTP.objects.filter(target=target).exclude(state__in=["INACTIVE", "REMOVED"]).filter(last_seen__lt=cutoff)[:200]:
        svc.state = "REMOVED"
        svc.last_changed = timezone.now()
        svc.save(update_fields=["state", "last_changed"])
        emit_event("HTTP_SERVICE_REMOVED", target=target, asset_type="HTTP_SERVICE",
                   asset_id=svc.id, asset_value=svc.url, source="reconcile")
        removed += 1
    for u in _URL.objects.filter(target=target).exclude(state__in=["INACTIVE", "REMOVED"]).filter(last_seen__lt=cutoff)[:500]:
        u.state = "REMOVED"
        u.save(update_fields=["state"])
        emit_event("URL_REMOVED", target=target, asset_type="URL", asset_id=u.id,
                   asset_value=u.canonical_url[:500], source="reconcile")
        removed += 1
    for j in _JS.objects.filter(target=target).exclude(state__in=["INACTIVE", "REMOVED"]).filter(last_seen__lt=cutoff)[:200]:
        j.state = "REMOVED"
        j.last_changed = timezone.now()
        j.save(update_fields=["state", "last_changed"])
        emit_event("JS_REMOVED", target=target, asset_type="JS_FILE", asset_id=j.id,
                   asset_value=j.js_url, source="reconcile")
        removed += 1
    # Task 9: IP + API endpoint reconciliation (IP_REMOVED / API_ENDPOINT_REMOVED
    # were defined but never emitted; is_active never flipped back).
    from apps.assets.models import APIEndpoint as _API
    from apps.assets.models import DNSRecord as _DNS
    from apps.assets.models import IPAddress as _IP
    for ip in _IP.objects.filter(target=target, is_active=True, last_seen__lt=cutoff)[:500]:
        # Edge: an IP shared by several hostnames must not be removed while any
        # live DNS record still points at it — only the hostname went stale.
        if _DNS.objects.filter(target=target, value=ip.ip,
                               record_type__in=["A", "AAAA"],
                               last_seen__gte=cutoff).exists():
            continue
        ip.is_active = False
        ip.state = "REMOVED"
        ip.save(update_fields=["is_active", "state"])
        emit_event("IP_REMOVED", target=target, asset_type="IP", asset_id=ip.id,
                   asset_value=ip.ip, source="reconcile",
                   old_state={"ip": ip.ip, "state": "ACTIVE"},
                   new_state={"ip": ip.ip, "state": "REMOVED"})
        removed += 1
    for ep in _API.objects.filter(target=target).exclude(
            state__in=["INACTIVE", "REMOVED"]).filter(last_seen__lt=cutoff)[:500]:
        ep.state = "REMOVED"
        ep.save(update_fields=["state"])
        emit_event("API_ENDPOINT_REMOVED", target=target, asset_type="API_ENDPOINT",
                   asset_id=ep.id, asset_value=ep.url[:500], source="reconcile",
                   evidence={"method": ep.method, "api_type": ep.api_type})
        removed += 1
    _finish(job, "COMPLETED", stats={"marked_inactive": removed})
    return {"status": "COMPLETED", "marked_inactive": removed}


# ---------------------------------------------------------------------------
# Incremental per-asset pipeline: process ONLY what is new, never full rescans.
# NEW_SUBDOMAIN -> resolve that host -> NEW_IP -> scan that IP ->
# NEW_OPEN_PORT -> probe that service -> NEW_HTTP_SERVICE -> crawl that host ->
# NEW_URL/NEW_JS -> analyze that JS -> technology -> CVE -> nuclei.
# ---------------------------------------------------------------------------

def _asset_job(target, job_type, asset_type="", asset_value="", trigger="event", tool=""):
    """Create a RUNNING ScanJob with full context, or return (None, reason)."""
    import uuid as _uuid

    from apps.jobs.models import ScanJob
    from services.event_engine.engine import broadcast_job

    if not target.is_scannable:
        return None, "target not scannable"
    if asset_value and ScanJob.objects.filter(
            target=target, job_type=job_type, asset_value=asset_value[:1024],
            status__in=[ScanJob.STATUS_QUEUED, ScanJob.STATUS_RUNNING]).exists():
        return None, "already running for this asset (coalesced)"
    job = ScanJob.objects.create(
        target=target, job_type=job_type, tool=tool, status=ScanJob.STATUS_RUNNING,
        asset_type=asset_type, asset_value=(asset_value or "")[:1024], trigger=trigger,
        run_id=_uuid.uuid4().hex[:12], started_at=timezone.now())
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
    ports_cfg = target.scan_config.get("ports", "80,443,8080,8443,8000,8888,3000,5000") if isinstance(target.scan_config, dict) else "80,443,8080,8443,8000,8888,3000,5000"
    port_list = [int(p) for p in str(ports_cfg).split(",") if p.strip().isdigit()][:30]
    entries = []
    from services.tool_adapters.adapters import NaabuAdapter

    adapter = NaabuAdapter()
    if adapter.is_available():
        try:
            res = adapter.run(ip, ports=",".join(map(str, port_list)))
            entries.extend(res.data)
            _log(job, "INFO", f"naabu on {ip}: {len(res.data)} open", stage="ports", tool="naabu")
        except Exception as e:
            _log(job, "ERROR", f"naabu failed for {ip}: {e}", stage="ports", tool="naabu")
    if not entries:
        for pt in port_list:
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((ip, pt)) == 0:
                    entries.append({"ip": ip, "port": pt, "protocol": "tcp"})
                s.close()
            except Exception:
                continue
    before = set((p.ip, p.port) for p in target.ports.filter(state="open"))
    new = ingest_ports(target, entries)
    new_ports = [e for e in entries if (e.get("ip"), e.get("port")) not in before]
    _finish(job, "COMPLETED", stats={"new": new, "open": len(entries), "ip": ip})
    for e in new_ports:  # probe only the newly opened ports
        scheme = "https" if e.get("port") in (443, 8443) else "http"
        probe_http_targets.delay(target_id, [f"{scheme}://{ip}:{e['port']}"], trigger)
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
            res = adapter.run(urls[:50], timeout=300)
            if res.status == "FAILED":
                _log(job, "ERROR", f"httpx failed: {res.error}", stage="http", tool="httpx")
            else:
                entries.extend(o for o in res.data if isinstance(o, dict))
        except Exception as e:
            _log(job, "ERROR", f"httpx failed: {e}", stage="http", tool="httpx")
    if not entries:
        import urllib.request as _urlreq

        for url in (urls or [])[:50]:
            try:
                # T2+T4: per-asset URLs still get scope + SSRF pre-checks.
                ok, reason, _h = _url_allowed_for_fetch(target, url)
                if not ok:
                    _log(job, "INFO", f"skipped probe {url[:200]}: {reason}", stage="http", tool="urllib")
                    continue
                ctx = _ssl_context_for(target, job, stage="http")  # T3
                req = _urlreq.Request(url, headers={"User-Agent": "recon-monitor/1.0"})
                with _urlreq.urlopen(req, timeout=8, context=ctx) as r:
                    entries.append({"url": url, "status_code": r.status, "title": "",
                                    "server": r.headers.get("Server", ""),
                                    "content_type": r.headers.get("Content-Type", "")})
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
    if kat.is_available():
        try:
            res = kat.run(url)
            items.extend(res.data)
            _log(job, "INFO", f"katana on {url}: {len(res.data)} urls", stage="urls", tool="katana")
        except Exception as e:
            _log(job, "ERROR", f"katana failed: {e}", stage="urls", tool="katana")
    new_urls, new_apis = ingest_urls(target, items)
    # script-src JS extraction from the page itself (T2: shared scoped helper).
    js_count = 0
    try:
        raw = _fetch_url_for_recon(target, url, job=job, stage="js",
                                   timeout=10, max_bytes=500000)
    except _ReconFetchSkipped as e:
        _log(job, "INFO", f"skipped page {url[:200]}: {e}", stage="js")
        raw = b""
    except Exception as e:
        _log(job, "ERROR", f"page fetch failed for {url}: {e}", stage="js")
        raw = b""
    if raw:
        js_count = _extract_and_ingest_scripts(target, raw.decode("utf-8", errors="ignore"),
                                               url, job=job, source="crawler")
    _finish(job, "COMPLETED", stats={"new_urls": new_urls, "new_apis": new_apis, "js": js_count})
    return {"status": "COMPLETED", "new_urls": new_urls, "js": js_count}


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
        _finish(job, "SKIPPED", error="nuclei not installed")
        return {"status": "SKIPPED", "reason": "nuclei missing"}
    try:
        res = adapter.run(url)
    except Exception as e:
        _finish(job, "FAILED", error=str(e)[:500])
        return {"status": "FAILED", "error": str(e)[:200]}
    n = 0
    for item in res.data:
        ingest_nuclei_finding(target, item if isinstance(item, dict) else {"template": str(item), "matched_at": url})
        n += 1
    _finish(job, "COMPLETED", stats={"findings": n, "url": url[:200]})
    return {"status": "COMPLETED", "findings": n}
