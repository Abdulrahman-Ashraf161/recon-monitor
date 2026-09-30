"""State comparison + persistence: every ingest compares against stored state,
emits events only on meaningful change, updates first_seen/last_seen/last_changed."""

import logging

from django.utils import timezone

from services.event_engine.engine import emit_event
from services.normalization.hosts import dedup_hostnames
from services.normalization.urls import canonicalize_url, classify_api
from services.scope_engine.validator import validate_host, validate_ip

logger = logging.getLogger(__name__)


def _touch(obj, changed=False):
    obj.last_seen = timezone.now()
    if changed:
        obj.last_changed = timezone.now()
    obj.save(update_fields=["last_seen"] + (["last_changed"] if changed else []))


def _asset(target, asset_type, value, metadata=None):
    from apps.assets.models import Asset

    a, created = Asset.objects.get_or_create(
        target=target,
        asset_type=asset_type,
        value=value[:2048],
        defaults={"metadata": metadata or {}},
    )
    if not created:
        a.last_seen = timezone.now()
        a.is_active = True
        a.save(update_fields=["last_seen", "is_active"])
    return a, created


def _note(asset_type, value, asset_id=None, evidence=None, observed=True):
    """Record provenance for one asset inside the active scan context (P1-005).

    A no-op when no execution context is installed (management commands,
    migrations, ad-hoc ingest from the dashboard), so ingest behaviour is
    unchanged outside a scan.
    """
    from apps.core.execution_context import record_observation

    if not value:
        return None
    return record_observation(
        asset_type, value, asset_id=asset_id, observed=observed, evidence=evidence
    )


def ingest_subdomains(target, items, source_label="pipeline"):
    """items: iterable of {'hostname':..., 'source':...}. Returns (new_count, total)."""
    from apps.assets.models import Subdomain

    rules = list(target.scope_rules.all())
    pairs = [(i.get("hostname", ""), i.get("source", source_label)) for i in items]
    merged = dedup_hostnames(pairs)
    new_count = 0
    persisted = []
    for hostname, sources in merged.items():
        ok, reason = validate_host(target, hostname, rules)
        if not ok:
            logger.info("scope-rejected subdomain %s: %s", hostname, reason)
            continue
        persisted.append((hostname, sources))
        # wildcard guard: if wildcard detected and hostname only resolves to wildcard IPs, flag suspect
        suspect = False
        if target.wildcard_detected and target.wildcard_ips:
            suspect = True  # confirmed later by DNS stage; stored as suspect until verified
        sub, created = Subdomain.objects.get_or_create(
            target=target,
            hostname=hostname,
            defaults={"sources": sources, "wildcard_suspect": suspect, "state": "DISCOVERED"},
        )
        if created:
            new_count += 1
            sub.state = "DISCOVERED"
            sub.is_active = True
            sub.save(update_fields=["state", "is_active"])
            _asset(target, "SUBDOMAIN", hostname, {"sources": sources})
            emit_event(
                "NEW_SUBDOMAIN",
                target=target,
                asset_type="SUBDOMAIN",
                asset_id=sub.id,
                asset_value=hostname,
                source="+".join(sources[:3]),
                evidence={"sources": sources, "wildcard_suspect": suspect},
                new_state={"hostname": hostname, "sources": sources},
            )
        elif not sub.is_active or sub.state in ("INACTIVE", "REMOVED", "SUSPECTED_INACTIVE"):
            sub.is_active = True
            sub.state = "REACTIVATED"
            sub.last_seen = timezone.now()
            sub.last_changed = timezone.now()
            sub.save(update_fields=["is_active", "state", "last_seen", "last_changed"])
            _asset(target, "SUBDOMAIN", hostname, {"sources": sources})
            emit_event(
                "SUBDOMAIN_REACTIVATED",
                target=target,
                asset_type="SUBDOMAIN",
                asset_id=sub.id,
                asset_value=hostname,
                source="+".join(sources[:3]),
                evidence={"sources": sources},
                severity="LOW",
            )
        else:
            merged_sources = sorted(set(sub.sources or []) | set(sources))
            if set(merged_sources) != set(sub.sources or []):
                sub.sources = merged_sources
                sub.save(update_fields=["sources", "last_seen"])
            else:
                _touch(sub)
    # P1-005: every accepted hostname is an observation of this execution.
    for hostname, sources in persisted:
        _note("SUBDOMAIN", hostname, evidence={"sources": sources})
    return new_count, len(merged)


def detect_wildcard(target, resolver=None):
    """Generate random labels, resolve; if they consistently resolve -> wildcard.

    T4: a wildcard verdict gates subdomain acceptance, so a probe that could
    not run must never be recorded as "no wildcard". The detection is left
    untouched and the failure is reported instead of being swallowed.
    """
    import secrets

    labels = [f"rand-{secrets.token_hex(4)}-{i}" for i in range(3)]
    ips = set()
    try:
        import dns.resolver
    except ImportError as e:
        logger.error(
            "wildcard detection unavailable: %s",
            e,
            extra={"target_id": target.pk, "operation": "detect_wildcard", "status": "SKIPPED"},
        )
        return target.wildcard_detected, sorted(target.wildcard_ips or [])

    res = resolver or dns.resolver.Resolver()
    res.timeout = 5
    resolved_any = False
    for label in labels:
        try:
            ans = res.resolve(f"{label}.{target.root_domain}", "A")
            for r in ans:
                ips.add(str(r))
            resolved_any = True
        except dns.resolver.NXDOMAIN:
            continue
        except Exception as e:
            logger.warning(
                "wildcard probe failed for %s.%s: %s",
                label,
                target.root_domain,
                e.__class__.__name__,
                extra={"target_id": target.pk, "operation": "detect_wildcard", "status": "ERROR"},
            )
            continue

    if not resolved_any:
        # Inconclusive: do not assert absence of wildcard DNS.
        logger.error(
            "wildcard detection inconclusive for %s; verdict left at %s",
            target.root_domain,
            target.wildcard_detected,
            extra={"target_id": target.pk, "operation": "detect_wildcard", "status": "ERROR"},
        )
        return target.wildcard_detected, sorted(target.wildcard_ips or [])

    target.wildcard_detected = len(ips) > 0
    target.wildcard_ips = sorted(ips)
    target.save(update_fields=["wildcard_detected", "wildcard_ips"])
    return target.wildcard_detected, sorted(ips)


def ingest_dns(target, records):
    """records: [{'hostname','type','value'}]."""
    from apps.assets.models import DNSRecord, IPAddress, Subdomain

    rules = list(target.scope_rules.all())
    new = 0
    persisted = []
    for r in records:
        host, rtype, val = r.get("hostname", ""), r.get("type", "A"), r.get("value", "")
        if not host or not val:
            continue
        if rtype in ("A", "AAAA"):
            ok, _ = validate_ip(target, val, rules)
            if not ok:
                continue
        persisted.append((host, rtype, val))
        rec, created = DNSRecord.objects.get_or_create(
            target=target, hostname=host, record_type=rtype, value=val
        )
        if created:
            new += 1
            emit_event(
                "NEW_DNS_RECORD",
                target=target,
                asset_type="SUBDOMAIN",
                asset_value=host,
                source="dnsx",
                evidence={"type": rtype, "value": val},
            )
        else:
            _touch(rec) if hasattr(rec, "last_seen") else None
        if rtype in ("A", "AAAA"):
            # T5 edge: normalize IPv6/IPv4-mapped forms so ::ffff:1.2.3.4 can't
            # dodge the same-IP check against 1.2.3.4.
            try:
                import ipaddress as _ip

                val = str(_ip.ip_address(val.strip()))
            except ValueError:
                continue
            # T5: same IP already tied to a different target => shared infra suspect.
            # First target to claim an IP scans normally (no retro-flagging here).
            shared = IPAddress.objects.filter(ip=val).exclude(target=target).exists()
            ip, ip_created = IPAddress.objects.get_or_create(
                target=target, ip=val, defaults={"shared_suspect": shared}
            )
            if ip_created:
                hosts = ip.source_hostnames or []
                if host not in hosts:
                    hosts.append(host)
                ip.source_hostnames = hosts
                ip.state = "DISCOVERED"
                ip.save(update_fields=["source_hostnames", "last_seen", "state"])
                _asset(target, "IP", val, {})
                emit_event(
                    "NEW_IP",
                    target=target,
                    asset_type="IP",
                    asset_id=ip.id,
                    asset_value=val,
                    source="dnsx",
                    evidence={"hostname": host},
                    new_state={"ip": val, "hostname": host},
                )
            else:
                if shared and not ip.shared_suspect:
                    ip.shared_suspect = True
                    ip.save(update_fields=["shared_suspect"])
                hosts = ip.source_hostnames or []
                updated = False
                if host not in hosts:
                    hosts.append(host)
                    ip.source_hostnames = hosts
                    updated = True
                if not ip.is_active or getattr(ip, "state", "") in ("INACTIVE", "REMOVED"):
                    ip.is_active = True
                    ip.state = "REACTIVATED"
                    updated = True
                    emit_event(
                        "IP_REACTIVATED",
                        target=target,
                        asset_type="IP",
                        asset_id=ip.id,
                        asset_value=val,
                        source="dnsx",
                        evidence={"hostname": host},
                    )
                ip.last_seen = timezone.now()
                ip.save(
                    update_fields=["source_hostnames", "last_seen"]
                    + (["state", "is_active"] if updated else [])
                )
            Subdomain.objects.filter(target=target, hostname=host).update(
                dns_status="resolved", last_seen=timezone.now()
            )
    for host, rtype, val in persisted:
        _note("DNS_RECORD", f"{host}/{rtype}/{val}", evidence={"hostname": host, "type": rtype})
    return new


def ingest_ports(target, entries):
    """entries: [{'ip','port','protocol','service'}]."""
    from apps.assets.models import Port

    new = 0
    persisted = []
    for e in entries:
        ip, port = e.get("ip"), e.get("port")
        if not ip or not port:
            continue
        proto = e.get("protocol", "tcp")
        persisted.append((ip, port, proto, e.get("service", "")))
        p, created = Port.objects.get_or_create(
            target=target,
            ip=ip,
            port=int(port),
            protocol=proto,
            defaults={
                "state": "open",
                "service": e.get("service", ""),
                "product": e.get("product", ""),
                "version": e.get("version", ""),
                "banner": e.get("banner", ""),
            },
        )
        if created:
            new += 1
            p.state = "DISCOVERED"
            p.save(update_fields=["state"])
            _asset(target, "PORT", f"{ip}:{port}/{proto}", {})
            emit_event(
                "NEW_OPEN_PORT",
                target=target,
                asset_type="PORT",
                asset_id=p.id,
                asset_value=f"{ip}:{port}",
                source="naabu",
                evidence={
                    "protocol": proto,
                    "service": e.get("service", ""),
                    "product": e.get("product", ""),
                    "version": e.get("version", ""),
                },
                severity="MEDIUM",
                new_state={"ip": ip, "port": port, "service": e.get("service", "")},
            )
        else:
            diffs = {}
            if e.get("service") and p.service != e["service"]:
                diffs["service"] = [p.service, e["service"]]
                p.service = e["service"]
            if e.get("product") and getattr(p, "product", "") != e["product"]:
                diffs["product"] = [getattr(p, "product", ""), e["product"]]
                p.product = e["product"]
            if e.get("version") and getattr(p, "version", "") != e["version"]:
                diffs["version"] = [getattr(p, "version", ""), e["version"]]
                p.version = e["version"]
            if e.get("banner") and getattr(p, "banner", "") != e["banner"]:
                diffs["banner"] = [getattr(p, "banner", "")[:200], e["banner"][:200]]
                p.banner = e["banner"]
            if getattr(p, "state", "") in ("INACTIVE", "REMOVED", "closed") or p.state == "closed":
                p.state = "REACTIVATED"
                diffs["reactivated"] = True
            if diffs:
                from django.utils import timezone as _tz

                p.last_changed = _tz.now()
                p.last_seen = _tz.now()
                p.save()
                etype = (
                    "PORT_SERVICE_CHANGED"
                    if ("service" in diffs or "product" in diffs)
                    else ("PORT_BANNER_CHANGED" if "banner" in diffs else "PORT_STATE_CHANGED")
                )
                emit_event(
                    etype,
                    target=target,
                    asset_type="PORT",
                    asset_id=p.id,
                    asset_value=f"{ip}:{port}",
                    source="naabu",
                    evidence={"changes": diffs, "protocol": proto},
                    old_state={},
                    new_state=diffs,
                )
            else:
                p.last_seen = timezone.now()
                p.save(update_fields=["last_seen"])
    for ip, port, proto, service in persisted:
        _note("PORT", f"{ip}:{port}", evidence={"protocol": proto, "service": service})
    # PORT_CLOSED detection happens in reconciliation (stale ports not re-observed)
    return new


def ingest_http(target, entries):
    """entries: httpx-style dicts."""
    from apps.assets.models import HTTPService

    new = changed = 0
    observed = []
    for e in entries:
        url = e.get("url") or e.get("input") or ""
        if not url:
            continue
        host = e.get("host") or e.get("input") or ""
        status = e.get("status_code") or e.get("status-code")
        title = e.get("title", "")
        server = ""
        techs = []
        if isinstance(e.get("tech"), list):
            techs = e["tech"]
        elif isinstance(e.get("technologies"), list):
            techs = e["technologies"]
        server = e.get("webserver") or e.get("server") or ""
        from services.http_fingerprint import http_fingerprint, normalize_http_state

        entry = dict(e)
        entry.update(
            {
                "url": url,
                "host": host,
                "status_code": status,
                "title": title,
                "server": server,
                "technologies": techs,
            }
        )
        fp = http_fingerprint(entry)
        norm = normalize_http_state(entry)
        svc, created = HTTPService.objects.get_or_create(
            target=target,
            url=url,
            defaults={
                "host": host,
                "port": e.get("port", 443),
                "scheme": e.get("scheme", "https"),
                "status_code": status,
                "title": title,
                "server": server,
                "content_type": e.get("content_type", ""),
                "content_length": e.get("content_length"),
                "ip": e.get("ip", e.get("host_ip", "")),
                "technologies": techs,
                "tls_info": e.get("tls", e.get("tls_info", {})),
                "redirect_chain": e.get("redirect_chain", []),
                "fingerprint": fp,
                "state": "DISCOVERED",
            },
        )
        if created:
            new += 1
            _asset(target, "HTTP_SERVICE", url, {"status": status})
            emit_event(
                "NEW_HTTP_SERVICE",
                target=target,
                asset_type="HTTP_SERVICE",
                asset_id=svc.id,
                asset_value=url,
                source="httpx",
                evidence={
                    "status": status,
                    "title": title,
                    "server": server,
                    "fingerprint": fp,
                    "ip": svc.ip,
                },
                new_state=norm,
            )
            for t in techs if isinstance(techs, list) else []:
                name = t if isinstance(t, str) else t.get("name", "")
                if name:
                    ingest_technology(target, url, name, "", 0.6, f"httpx: {url}", "httpx")
        else:
            if getattr(svc, "state", "") in ("INACTIVE", "REMOVED"):
                svc.state = "REACTIVATED"
                svc.fingerprint = fp
                svc.last_changed = timezone.now()
                svc.save()
                emit_event(
                    "HTTP_SERVICE_REACTIVATED",
                    target=target,
                    asset_type="HTTP_SERVICE",
                    asset_id=svc.id,
                    asset_value=url,
                    source="httpx",
                    evidence={"fingerprint": fp},
                )
                changed += 1
            elif svc.fingerprint != fp:
                old_state = {
                    "status_code": svc.status_code,
                    "title": svc.title,
                    "server": svc.server,
                    "ip": svc.ip,
                    "content_type": svc.content_type,
                    "technologies": svc.technologies,
                    "redirect_chain": svc.redirect_chain,
                    "fingerprint": svc.fingerprint,
                }
                svc.status_code = status
                svc.title = title
                svc.server = server
                svc.content_type = e.get("content_type", svc.content_type)
                if e.get("content_length") is not None:
                    svc.content_length = e.get("content_length")
                svc.ip = e.get("ip", e.get("host_ip", svc.ip))
                svc.technologies = techs
                svc.tls_info = e.get("tls", e.get("tls_info", svc.tls_info))
                svc.redirect_chain = e.get("redirect_chain", svc.redirect_chain)
                svc.fingerprint = fp
                svc.last_changed = timezone.now()
                svc.save()
                changed += 1
                emit_event(
                    "HTTP_SERVICE_CHANGED",
                    target=target,
                    asset_type="HTTP_SERVICE",
                    asset_id=svc.id,
                    asset_value=url,
                    source="httpx",
                    evidence={"fingerprint": fp, "ip": svc.ip},
                    old_state=old_state,
                    new_state=norm,
                )
            else:
                svc.last_seen = timezone.now()
                svc.save(update_fields=["last_seen"])
        observed.append((svc.id, url, status, server))
    for svc_id, url, status, server in observed:
        _note(
            "HTTP_SERVICE",
            url,
            asset_id=svc_id,
            evidence={"status": status, "server": server[:200]},
        )
    return new, changed


def ingest_urls(target, items):
    """Normalize, scope-validate (T1), and persist discovered URLs + API endpoints.

    T1: every host is checked with validate_host() before persistence — Wayback /
    Common Crawl / katana output routinely contains third-party hosts.
    T10: re-observed rows get last_seen bumped so reconciliation stays honest.
    T12: per-item try/except — one malformed URL never aborts the batch.
    """
    from urllib.parse import urlparse

    from apps.assets.models import APIEndpoint, URLAsset
    from services.scope_engine.validator import validate_host

    rules = list(target.scope_rules.all())
    new_urls = new_apis = 0
    observed = []
    for item in items:
        try:
            raw = item.get("url", "")
            canon = canonicalize_url(raw)
            if not canon:
                continue
            source = item.get("source", "")
            try:
                host = (urlparse(canon).hostname or "").lower().rstrip(".")
            except Exception:
                host = ""
            if host:
                ok, reason = validate_host(target, host, rules)
                if not ok:
                    logger.info("scope-rejected url %s: %s", canon[:200], reason)
                    continue
            u, created = URLAsset.objects.get_or_create(
                target=target,
                canonical_url=canon,
                defaults={"raw_url": raw, "host": host, "source": source},
            )
            if created:
                new_urls += 1
                emit_event(
                    "NEW_URL",
                    target=target,
                    asset_type="URL",
                    asset_id=u.id,
                    asset_value=canon[:500],
                    source=source,
                    evidence={"host": host},
                )
            else:
                # T10: re-observation keeps the row fresh for reconciliation.
                u.last_seen = timezone.now()
                u.save(update_fields=["last_seen"])
            is_api, api_type, auth_hints = classify_api(canon)
            observed.append((u.id, canon, source))
            if is_api:
                if not u.is_api:
                    u.is_api = True
                    u.save(update_fields=["is_api"])
                ep, ep_created = APIEndpoint.objects.get_or_create(
                    target=target,
                    url=canon[:4000],
                    method=item.get("method", "GET"),
                    defaults={
                        "host": host,
                        "api_type": api_type,
                        "auth_indicators": auth_hints,
                        "source": source,
                    },
                )
                if ep_created:
                    new_apis += 1
                    _asset(target, "API_ENDPOINT", canon[:1000], {"type": api_type})
                    emit_event(
                        "NEW_API_ENDPOINT",
                        target=target,
                        asset_type="API_ENDPOINT",
                        asset_id=ep.id,
                        asset_value=canon[:500],
                        source=source,
                        evidence={"api_type": api_type, "auth_indicators": auth_hints},
                    )
                else:
                    ep.last_seen = timezone.now()
                    ep.save(update_fields=["last_seen"])
        except Exception as e:
            logger.warning(
                "ingest_urls: skipping item: %s",
                e,
                exc_info=True,
                extra={"target_id": target.pk, "operation": "ingest_urls", "status": "ERROR"},
            )
            continue
    for url_id, canon, source in observed:
        _note("URL", canon, asset_id=url_id, evidence={"source": source})
    return new_urls, new_apis


def _current_scan_run():
    """The ScanRun of the active execution context, if any (P2-012)."""
    from apps.core.execution_context import current_context

    ctx = current_context()
    return getattr(ctx, "scan_run", None) if ctx is not None else None


def _js_dependency_keys(dependencies):
    """Hashable identity of detected libraries.

    The detector stores libraries as ``{"library": name, "version": v}`` dicts
    (richer than a bare string), so a set-difference over the raw list would
    raise "unhashable type: dict". The key is the library name plus version --
    the same identity the finding is reported under.
    """
    keys = set()
    for dep in dependencies or []:
        if isinstance(dep, dict):
            keys.add((str(dep.get("library") or ""), str(dep.get("version") or "")))
        else:
            keys.add((str(dep), ""))
    return keys


def _js_secret_keymap(text):
    """The secret candidates present in ``text`` as {type: [value-digest, ...]}.

    P2-003: the digest of each distinct matched value is the identity, so a
    bundle that *rotates* a credential (same type, new value) is a detectable
    add+remove rather than "no change". No secret material is returned.
    """
    import hashlib

    from services.correlation.jsintel import extract_secret_candidates

    out = {}
    for c in extract_secret_candidates(text):
        value = (c.get("full") or "")[:2000]
        digest = hashlib.sha256(value.encode()).hexdigest()[:12] if value else ""
        out.setdefault(c["type"], [])
        if digest not in out[c["type"]]:
            out[c["type"]].append(digest)
    return out


def _js_secret_keyset(keymap):
    """Flatten a key map into a comparable set of (type, digest) pairs."""
    return {(t, d) for t, digests in (keymap or {}).items() for d in (digests or [])}


def _emit_js_children(
    js, js_url, source, parent, old_routes, old_deps, old_secret_keys, target=None
):
    """Emit one child event per semantic add/remove (P2-003).

    A ``JS_CHANGED`` parent means the *content* moved; the actionable signal is
    what changed semantically. Additions and removals are both emitted, each
    correlated to the parent event (and its ``correlation_id``) and the
    execution's ``ScanRun``, so a child can always be traced back to the scan
    and change that caused it.
    """

    target = target or js.target
    new_routes = set(js.routes or [])
    new_deps = _js_dependency_keys(js.dependencies)
    run = _current_scan_run()
    corr = getattr(parent, "correlation_id", "") or ""
    counts = {
        "endpoints_added": 0,
        "endpoints_removed": 0,
        "libraries_added": 0,
        "libraries_removed": 0,
        "secrets_added": 0,
        "secrets_removed": 0,
    }
    try:
        for r in sorted(new_routes - old_routes):
            emit_event(
                "NEW_JS_ENDPOINT",
                target=target,
                asset_type="JS_FILE",
                asset_id=js.id,
                asset_value=f"{js_url} -> {r}",
                source=source,
                scan_run=run,
                evidence={"route": r, "js_url": js_url, "change": "added"},
                old_state={"route": r, "present": False},
                new_state={"route": r, "present": True},
                parent_event=parent,
                correlation_id=corr,
            )
            counts["endpoints_added"] += 1
        for r in sorted(old_routes - new_routes):
            emit_event(
                "JS_ENDPOINT_REMOVED",
                target=target,
                asset_type="JS_FILE",
                asset_id=js.id,
                asset_value=f"{js_url} -> {r}",
                source=source,
                scan_run=run,
                evidence={"route": r, "js_url": js_url, "change": "removed"},
                old_state={"route": r, "present": True},
                new_state={"route": r, "present": False},
                parent_event=parent,
                correlation_id=corr,
            )
            counts["endpoints_removed"] += 1
        for name, version in sorted(new_deps - old_deps):
            label = f"{name}@{version}" if version else name
            emit_event(
                "NEW_JS_LIBRARY",
                target=target,
                asset_type="JS_FILE",
                asset_id=js.id,
                asset_value=f"{js_url} -> {label}",
                source=source,
                scan_run=run,
                evidence={"library": name, "version": version, "js_url": js_url, "change": "added"},
                old_state={"library": name, "version": version, "present": False},
                new_state={"library": name, "version": version, "present": True},
                parent_event=parent,
                correlation_id=corr,
            )
            counts["libraries_added"] += 1
        for name, version in sorted(old_deps - new_deps):
            label = f"{name}@{version}" if version else name
            emit_event(
                "JS_LIBRARY_REMOVED",
                target=target,
                asset_type="JS_FILE",
                asset_id=js.id,
                asset_value=f"{js_url} -> {label}",
                source=source,
                scan_run=run,
                evidence={
                    "library": name,
                    "version": version,
                    "js_url": js_url,
                    "change": "removed",
                },
                old_state={"library": name, "version": version, "present": True},
                new_state={"library": name, "version": version, "present": False},
                parent_event=parent,
                correlation_id=corr,
            )
            counts["libraries_removed"] += 1
        new_secret_keys = _js_secret_keyset(getattr(js, "current_secret_keys", None) or {})
        # P2-013: the matched secret never reaches the event. asset_value and
        # evidence carry the type plus a redacted preview; the raw value is
        # only ever the in-memory set key above.
        for key in sorted(new_secret_keys - old_secret_keys):
            emit_event(
                "NEW_JS_SECRET_CANDIDATE",
                target=target,
                asset_type="JS_FILE",
                asset_id=js.id,
                asset_value=f"{js_url} [{key[0]}]",
                source=source,
                scan_run=run,
                severity="HIGH",
                evidence={
                    "secret_type": key[0],
                    "js_url": js_url,
                    "change": "added",
                    "rotated": bool(old_secret_keys)
                    and any(k[0] == key[0] for k in old_secret_keys),
                },
                old_state={"secret_type": key[0], "present": False},
                new_state={"secret_type": key[0], "present": True},
                parent_event=parent,
                correlation_id=corr,
            )
            counts["secrets_added"] += 1
        for key in sorted(old_secret_keys - new_secret_keys):
            emit_event(
                "JS_SECRET_CANDIDATE_REMOVED",
                target=target,
                asset_type="JS_FILE",
                asset_id=js.id,
                asset_value=f"{js_url} [{key[0]}]",
                source=source,
                scan_run=run,
                evidence={"secret_type": key[0], "js_url": js_url, "change": "removed"},
                old_state={"secret_type": key[0], "present": True},
                new_state={"secret_type": key[0], "present": False},
                parent_event=parent,
                correlation_id=corr,
            )
            counts["secrets_removed"] += 1
    except Exception as e:
        # A child event failure must be loud, and the counts are still reported
        # so a partial correlation is visible rather than assumed complete.
        logger.error(
            "js semantic child events failed for %s: %s",
            js_url[:200],
            e,
            extra={
                "target_id": target.pk,
                "js_id": js.id,
                "operation": "ingest_js:children",
                "status": "ERROR",
            },
        )
    if parent is not None and any(counts.values()):
        try:
            parent.evidence = {**(parent.evidence or {}), "semantic_delta": counts}
            parent.save(update_fields=["evidence"])
        except Exception as e:
            logger.error(
                "js parent delta summary not saved for %s: %s",
                js_url[:200],
                e,
                extra={
                    "target_id": target.pk,
                    "js_id": js.id,
                    "operation": "ingest_js:delta_summary",
                    "status": "ERROR",
                },
            )
    return counts


def ingest_js(target, js_url, content: bytes | str, source="httpx"):
    """Hash, store, detect JS_CHANGED, extract routes/secrets, emit events."""
    from apps.assets.models import JavaScriptAsset, JavaScriptVersion
    from services.correlation.jsintel import (
        beautify,
        detect_js_libraries,
        extract_routes,
        extract_secret_candidates,
        sha256_bytes,
    )

    raw = content if isinstance(content, bytes) else content.encode("utf-8", errors="ignore")
    digest = sha256_bytes(raw)
    text = raw.decode("utf-8", errors="ignore")
    host = js_url.split("/")[2] if "://" in js_url else ""
    js, created = JavaScriptAsset.objects.get_or_create(
        target=target, js_url=js_url, defaults={"host": host, "sha256": digest, "size": len(raw)}
    )
    if created:
        js.content = beautify(text)
        js.routes = extract_routes(text)
        js.dependencies = detect_js_libraries(text)
        js.secret_candidates = len(extract_secret_candidates(text))
        js.current_secret_keys = _js_secret_keymap(text)
        js.save()
        JavaScriptVersion.objects.create(
            js=js, sha256=digest, size=len(raw), content=beautify(text)
        )
        _asset(target, "JS_FILE", js_url, {"sha256": digest})
        _store_js_findings(js, text, source)
        emit_event(
            "NEW_JS",
            target=target,
            asset_type="JS_FILE",
            asset_id=js.id,
            asset_value=js_url,
            source=source,
            evidence={"sha256": digest, "size": len(raw)},
        )
        _note(
            "JS_FILE",
            js_url,
            asset_id=js.id,
            observed=True,
            evidence={"sha256": digest, "size": len(raw), "outcome": "NEW_JS", "source": source},
        )
        return js, "NEW_JS"
    if js.sha256 != digest:
        old = js.sha256
        old_routes, old_deps = set(js.routes or []), _js_dependency_keys(js.dependencies)
        # P2-003: secret candidates are a first-class semantic dimension. The
        # live key map of the *previous* content is captured before the new
        # content replaces it, so a removed (or rotated) secret is detectable
        # exactly like an added one.
        old_secret_keys = _js_secret_keyset(getattr(js, "current_secret_keys", None) or {})
        new_secret_keymap = _js_secret_keymap(text)
        js.sha256 = digest
        js.size = len(raw)
        js.content = beautify(text)
        js.routes = extract_routes(text)
        js.dependencies = detect_js_libraries(text)
        js.secret_candidates = sum(len(v) for v in new_secret_keymap.values())
        js.current_secret_keys = new_secret_keymap
        js.last_changed = timezone.now()
        js.save()
        JavaScriptVersion.objects.create(
            js=js, sha256=digest, size=len(raw), content=beautify(text)
        )
        # P2-003: events for new/removed candidates are emitted as correlated
        # children of JS_CHANGED below, not as orphans here.
        _store_js_findings(js, text, source, emit_events=False)
        ev, _ = emit_event(
            "JS_CHANGED",
            target=target,
            asset_type="JS_FILE",
            asset_id=js.id,
            asset_value=js_url,
            source=source,
            severity="MEDIUM",
            scan_run=_current_scan_run(),
            evidence={"old_sha256": old, "new_sha256": digest, "size": len(raw)},
            old_state={"sha256": old},
            new_state={"sha256": digest, "size": len(raw)},
        )
        # P2-003: every semantic delta -- added *and* removed routes,
        # libraries and secret candidates -- is a child event carrying the
        # correct parent event, target, correlation id and ScanRun.
        _emit_js_children(
            js, js_url, source, ev, old_routes, old_deps, old_secret_keys, target=target
        )
        _note(
            "JS_FILE",
            js_url,
            asset_id=js.id,
            observed=True,
            evidence={
                "sha256": digest,
                "old_sha256": old,
                "outcome": "JS_CHANGED",
                "source": source,
            },
        )
        return js, "JS_CHANGED"
    js.last_seen = timezone.now()
    js.save(update_fields=["last_seen"])
    _note(
        "JS_FILE",
        js_url,
        asset_id=js.id,
        observed=True,
        evidence={"sha256": digest, "outcome": "UNCHANGED", "source": source},
    )
    return js, "UNCHANGED"


def _store_js_findings(js, text, source, emit_events=True):
    """Persist a JS file's secret-candidate findings.

    P2-003: on a *change*, secret-candidate events are emitted by
    ``_emit_js_children`` so they carry the correct parent event and correlation
    id; ``emit_events=False`` avoids a duplicate, unparented event.
    """
    from apps.assets.models import JavaScriptFinding
    from services.correlation.jsintel import extract_secret_candidates

    for c in extract_secret_candidates(text):
        # P2-003: one row per distinct (type, value). Keying on the type alone
        # collapsed every occurrence of e.g. "aws_key" into a single row, so a
        # rotated credential looked identical to an unchanged one and neither
        # the add nor the removal was ever detectable. The value is carried in
        # ``evidence_full`` (internal) and only ever a short digest reaches
        # ``location``, so the stored row never duplicates the secret in a
        # queryable, scannable field.
        import hashlib

        value = (c.get("full") or "")[:2000]
        digest = hashlib.sha256(value.encode()).hexdigest()[:12] if value else ""
        _finding, created = JavaScriptFinding.objects.get_or_create(
            js=js,
            finding_type=c["type"],
            location=f"body@{digest}" if digest else "body",
            defaults={
                "target": js.target,
                "evidence_preview": (c["match_preview"] or "") + " (redacted)",
                "evidence_full": value,
                "source_tool": source,
                "confidence": "candidate",
                "status": "candidate",
            },
        )
        if created and emit_events:
            try:
                emit_event(
                    "NEW_JS_SECRET_CANDIDATE",
                    target=js.target,
                    asset_type="JS_FILE",
                    asset_id=js.id,
                    asset_value=f"{js.js_url} [{c['type']}]",
                    source=source,
                    severity="HIGH",
                    evidence={"secret_type": c["type"], "js_url": js.js_url},
                )
            except Exception as e:
                # The finding row is already persisted; losing the event must be
                # loud, not silent.
                logger.error(
                    "NEW_JS_SECRET_CANDIDATE not emitted for %s [%s]: %s",
                    js.js_url[:200],
                    c["type"],
                    e,
                    extra={
                        "target_id": js.target_id,
                        "js_id": js.id,
                        "operation": "emit_secret_candidate",
                        "status": "ERROR",
                    },
                )


def ingest_technology(
    target, asset_value, product, version="", confidence=0.6, evidence="", source=""
):
    from apps.assets.models import Technology
    from services.cve_engine.matcher import normalize_product

    product_n = normalize_product(product)
    tech, created = Technology.objects.get_or_create(
        target=target,
        asset_value=asset_value[:1000],
        product=product_n,
        defaults={
            "version": version or "",
            "confidence": confidence,
            "evidence": evidence or "",
            "source": source or "",
        },
    )
    if created:
        _asset(target, "TECHNOLOGY", f"{product_n} {version}@{asset_value[:200]}", {})
        emit_event(
            "NEW_TECHNOLOGY",
            target=target,
            asset_type="TECHNOLOGY",
            asset_id=tech.id,
            asset_value=f"{product_n} {version} on {asset_value[:200]}".strip(),
            source=source,
            evidence={"product": product_n, "version": version, "asset_url": asset_value[:1000]},
        )
        correlate_cves_for_tech(tech)
        _note(
            "TECHNOLOGY",
            f"{product_n} {version}".strip(),
            asset_id=tech.id,
            observed=True,
            evidence={"asset_url": asset_value[:1000], "confidence": confidence, "source": source},
        )
        return tech, "NEW"
    if version and tech.version != version:
        old = tech.version
        tech.version = version
        tech.confidence = confidence
        tech.last_changed = timezone.now()
        tech.save()
        emit_event(
            "TECH_VERSION_CHANGED",
            target=target,
            asset_type="TECHNOLOGY",
            asset_id=tech.id,
            asset_value=f"{product_n} {version} on {asset_value[:200]}".strip(),
            source=source,
            severity="MEDIUM",
            evidence={"product": product_n, "old_version": old, "new_version": version},
        )
        correlate_cves_for_tech(tech)
        _note(
            "TECHNOLOGY",
            f"{product_n} {version}".strip(),
            asset_id=tech.id,
            observed=True,
            evidence={"asset_url": asset_value[:1000], "old_version": old, "source": source},
        )
        return tech, "CHANGED"
    tech.last_seen = timezone.now()
    tech.save(update_fields=["last_seen"])
    _note(
        "TECHNOLOGY",
        f"{product_n} {tech.version}".strip(),
        asset_id=tech.id,
        observed=True,
        evidence={"asset_url": asset_value[:1000], "source": source},
    )
    return tech, "UNCHANGED"


def correlate_cves_for_tech(tech, kb=None):
    from django.utils import timezone as _tz

    from apps.assets.models import CVE
    from services.cve_engine.matcher import correlate

    for cand in correlate(tech, kb=kb):
        _cve, created = CVE.objects.get_or_create(
            target=tech.target,
            cve_id=cand["cve_id"],
            asset_value=tech.asset_value,
            product=tech.product,
            defaults={
                "vendor": getattr(tech, "vendor", ""),
                "detected_version": tech.version,
                "affected_range": cand.get("affected_range", ""),
                "status": "candidate",
                "evidence": cand.get("summary", ""),
                "sources": ["cvelistV5"],
            },
        )
        if created:
            _asset(
                tech.target,
                "CVE",
                f"{cand['cve_id']}@{tech.asset_value[:200]}",
                {"product": tech.product},
            )
            emit_event(
                "NEW_CVE_CANDIDATE",
                target=tech.target,
                asset_type="TECHNOLOGY",
                asset_id=tech.id,
                asset_value=f"{cand['cve_id']} on {tech.asset_value[:150]}",
                source="cve-engine",
                severity="HIGH",
                evidence={
                    "cve": cand["cve_id"],
                    "product": tech.product,
                    "version": tech.version,
                    "range": cand.get("affected_range", ""),
                    "asset_url": tech.asset_value[:1000],
                    "note": "Candidate — requires validation, not confirmed",
                },
            )
    # P1-007: record that this technology is up to date against the current KB
    # so a later sync can skip it while the KB is unchanged.
    try:
        type(tech)._base_manager.filter(pk=tech.pk).update(cve_checked_at=_tz.now())
    except Exception as exc:
        import logging

        logging.getLogger(__name__).warning(
            "cve_checked_at stamp failed for technology %s: %s", tech.pk, exc.__class__.__name__
        )
    return True


def ingest_nuclei_finding(target, item):
    """Normalize nuclei output into SecurityFinding."""
    from apps.assets.models import SecurityFinding

    info = item.get("info", {}) if isinstance(item, dict) else {}
    name = info.get("name", item.get("template", "nuclei-finding"))
    sev = (info.get("severity") or item.get("severity") or "MEDIUM").upper()
    if sev not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        sev = "MEDIUM"
    asset = item.get("matched_at") or item.get("host") or item.get("target") or ""
    template = item.get("templateID") or item.get("template") or ""
    f, created = SecurityFinding.objects.get_or_create(
        target=target,
        asset_value=str(asset)[:1000],
        finding_type=name[:128],
        template=template[:256],
        defaults={
            "title": name[:512],
            "severity": sev,
            "confidence": "medium",
            "evidence": {"raw": str(item)[:3000]},
            "source": "nuclei",
            "status": "NEW",
        },
    )
    if created:
        _asset(target, "FINDING", f"{name[:200]}@{str(asset)[:200]}", {"severity": sev})
        _note(
            "FINDING",
            f"{name}@{str(asset)[:200]}",
            asset_id=f.id,
            observed=True,
            evidence={"severity": sev, "template": template, "source": "nuclei"},
        )
        emit_event(
            "NEW_SECURITY_FINDING",
            target=target,
            asset_type="PORT",
            asset_id=f.id,
            asset_value=f"{name} on {str(asset)[:150]}",
            source="nuclei",
            severity="HIGH" if sev in ("HIGH", "CRITICAL") else "MEDIUM",
            evidence={"severity": sev, "template": template},
        )
    return f, created
