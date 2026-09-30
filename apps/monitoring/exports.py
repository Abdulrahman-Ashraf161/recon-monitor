"""Export generation: TXT/JSON/CSV per entity + full snapshot ZIP. No secrets included."""

import csv
import io
import json
import os
import re
import tempfile
import uuid
import zipfile
from datetime import datetime

from django.conf import settings
from django.utils import timezone

# P1-015: filesystem hardening. Export files are named after target-owned data,
# so every path component is derived from an opaque identifier and a strict
# charset -- never from a raw domain or any user-supplied string -- and writes go
# through a temp file + atomic rename so a concurrent export can never read a
# half-written artifact.
_SAFE_SEGMENT = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_segment(value, fallback="export"):
    """Reduce ``value`` to a safe single path segment (no separators, no '..')."""
    cleaned = _SAFE_SEGMENT.sub("-", str(value or "")).strip(".-")
    return cleaned[:64] or fallback


def export_root():
    """Root directory for exports (git-ignored ``data/exports``)."""
    configured = getattr(settings, "EXPORTS_DIR", None)
    if configured:
        return str(configured)
    return os.path.join(str(settings.BASE_DIR), "data", "exports")


def export_dir(target):
    """Per-target export directory, keyed by opaque id rather than the domain.

    P1-015: the taskbook prefers target IDs over raw domains for directory
    names. The id is unguessable-by-name, cannot contain separators, and cannot
    be crafted by an operator to traverse out of the export root.
    """
    d = os.path.join(export_root(), f"target-{int(target.pk):08d}")
    os.makedirs(d, mode=0o750, exist_ok=True)
    return d


def write_atomic(path, write_body, mode="w", **kwargs):
    """Write via a temp file in the same directory, then rename atomically."""
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".part")
    os.close(fd)
    try:
        with open(tmp, mode, **kwargs) as fh:
            write_body(fh)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def _filtered(qs, filters):
    f = filters or {}
    if f.get("active_only"):
        if hasattr(qs.model, "is_active"):
            qs = qs.filter(is_active=True)
        elif hasattr(qs.model, "state") and qs.model.__name__ == "Port":
            qs = qs.filter(state="open")
    if f.get("since"):
        try:
            since = datetime.fromisoformat(f["since"])
            qs = qs.filter(first_seen__gte=since)
        except ValueError:
            pass
    if f.get("source"):
        qs = qs.filter(source=f["source"]) if hasattr(qs.model, "source") else qs
    return qs


def collect(export_type, target, filters):
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

    if export_type == "subdomains":
        qs = _filtered(Subdomain.objects.filter(target=target).order_by("hostname"), filters)
        return ("subdomains", ["hostname"], [(s.hostname,) for s in qs.iterator()])
    if export_type == "ips":
        qs = _filtered(IPAddress.objects.filter(target=target).order_by("ip"), filters)
        return ("ips", ["ip"], [(i.ip,) for i in qs.iterator()])
    if export_type == "ports":
        qs = Port.objects.filter(target=target, state="open").order_by("ip", "port")
        return (
            "open_ports",
            ["host", "port", "protocol"],
            [(p.ip, p.port, p.protocol) for p in qs.iterator()],
        )
    if export_type == "http":
        qs = HTTPService.objects.filter(target=target).order_by("url")
        return ("http_urls", ["url"], [(h.url,) for h in qs.iterator()])
    if export_type == "urls":
        qs = URLAsset.objects.filter(target=target).order_by("canonical_url")
        return ("urls", ["url"], [(u.canonical_url,) for u in qs.iterator()])
    if export_type == "apis":
        qs = APIEndpoint.objects.filter(target=target).order_by("url")
        return ("api_endpoints", ["method", "url"], [(a.method, a.url) for a in qs.iterator()])
    if export_type == "javascript":
        qs = JavaScriptAsset.objects.filter(target=target).order_by("js_url")
        return ("javascript", ["url"], [(j.js_url,) for j in qs.iterator()])
    if export_type == "technologies":
        qs = Technology.objects.filter(target=target).order_by("product")
        return (
            "technologies",
            ["product", "version", "asset"],
            [(t.product, t.version, t.asset_value) for t in qs.iterator()],
        )
    if export_type == "cves":
        qs = CVE.objects.filter(target=target).order_by("cve_id")
        return ("cves", ["cve_id"], [(c.cve_id,) for c in qs.iterator()])
    if export_type == "findings":
        qs = SecurityFinding.objects.filter(target=target).order_by("-first_seen")
        return (
            "findings",
            ["severity", "title", "asset"],
            [(f.severity, f.title, f.asset_value) for f in qs.iterator()],
        )
    if export_type == "events":
        qs = Event.objects.filter(target=target).order_by("-created_at")
        return (
            "events",
            ["time", "type", "asset", "severity"],
            [
                (e.created_at.isoformat(), e.event_type, e.asset_value, e.severity)
                for e in qs.iterator()
            ],
        )
    raise ValueError(f"unknown export type {export_type}")


def render_txt(name, header, rows):
    lines = []
    for r in rows:
        lines.append(" | ".join(str(c) for c in r) if len(r) > 1 else str(r[0]))
    return "\n".join(lines) + ("\n" if lines else "")


def render_json(name, header, rows):
    # strict=False keeps a row with *more* values than headers from raising, but
    # a row with *fewer* would otherwise be silently zero-filled by zip(), which
    # would export a record with fabricated empty fields. Catch that instead.
    out = []
    for r in rows:
        if len(r) != len(header):
            raise ValueError(f"row has {len(r)} values but {len(header)} headers: {r!r}")
        out.append(dict(zip(header, r, strict=True)))
    return json.dumps(out, indent=2)


def render_csv(name, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def build_snapshot(target, filters):
    """Full target snapshot ZIP. Returns (path, size, total_rows).

    P1-015: the archive is built into a temp file and atomically renamed, and
    every internal name is derived from opaque ids -- two concurrent exports of
    the same target can therefore never read or overwrite each other's partial
    output, and no path component comes from user input.
    """
    stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
    run_id = uuid.uuid4().hex[:12]
    d = export_dir(target)
    filename = f"snapshot-{stamp}-{run_id}.zip"
    path = os.path.join(d, filename)
    inner = f"export-{int(target.pk):08d}-{stamp}"
    total = 0

    def _write(fh):
        nonlocal total
        with zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED) as z:
            for etype in [
                "subdomains",
                "ips",
                "ports",
                "http",
                "urls",
                "apis",
                "javascript",
                "technologies",
                "cves",
                "findings",
            ]:
                name, header, rows = collect(etype, target, filters)
                z.writestr(f"{inner}/{_safe_segment(name)}.txt", render_txt(name, header, rows))
                total += len(rows)
            name, header, rows = collect("events", target, filters)
            z.writestr(f"{inner}/events.json", render_json(name, header, rows))
            meta = {
                "target": target.root_domain,
                "exported_at": timezone.now().isoformat(),
                "baseline": target.baseline_status,
                "status": target.status,
                "job": run_id,
            }
            z.writestr(f"{inner}/metadata.json", json.dumps(meta, indent=2))

    write_atomic(path, _write, mode="wb")
    return path, os.path.getsize(path), total


def run_export_job(job_id):
    from apps.monitoring.models import ExportJob

    try:
        # P1-015: the worker has no request session, so it must not rely on a
        # request-scoped manager (that is ambient authorization, not a check).
        job = ExportJob.all_objects.select_related("target").get(pk=job_id)
    except ExportJob.DoesNotExist:
        return {"status": "SKIPPED"}
    job.status = ExportJob.STATUS_PROCESSING
    job.save(update_fields=["status"])
    try:
        # P1-015: an export is a disclosure of target data. If the target has
        # been deleted, the job is abandoned rather than producing a file nobody
        # can be authorized against any more.
        if job.target is None:
            job.status = ExportJob.STATUS_FAILED
            job.error = "target no longer exists"
            job.finished_at = timezone.now()
            job.save(update_fields=["status", "error", "finished_at"])
            return {"status": "FAILED", "error": "target gone"}
        d = export_dir(job.target)
        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        run_id = uuid.uuid4().hex[:12]
        if job.export_type == "snapshot":
            path, size, total = build_snapshot(job.target, job.filters)
            job.file_path, job.file_size, job.row_count = path, size, total
        else:
            name, header, rows = collect(job.export_type, job.target, job.filters)
            fmt = job.format if job.format in ("txt", "json", "csv") else "txt"
            body = {"txt": render_txt, "json": render_json, "csv": render_csv}[fmt](
                name, header, rows
            )
            # P1-015: a unique run id in the filename means two concurrent
            # exports of the same type/target never collide or overwrite.
            path = os.path.join(d, f"{_safe_segment(name)}-{stamp}-{run_id}.{fmt}")
            write_atomic(path, lambda fh: fh.write(body))
            job.file_path, job.file_size, job.row_count = path, os.path.getsize(path), len(rows)
        job.status = ExportJob.STATUS_COMPLETED
        job.finished_at = timezone.now()
        job.save()
        return {"status": "COMPLETED", "rows": job.row_count}
    except Exception as e:
        job.status = ExportJob.STATUS_FAILED
        job.error = str(e)[:1000]
        job.finished_at = timezone.now()
        job.save()
        return {"status": "FAILED", "error": str(e)[:300]}
