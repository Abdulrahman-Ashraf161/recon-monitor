"""P2-011/P2-012/P2-013 — Structured logging, correlation IDs, secret hygiene.

P2-011: every major stage logs the same structured fields, and never a secret.
P2-012: scan_run / correlation_id / parent_event / job / tool are used
        consistently enough to trace a scan end to end.
P2-013: synthetic secrets never reach logs, events, the DB or an export.
"""

import json
import logging
import tempfile
from unittest.mock import patch

from django.test import TestCase, override_settings

from apps.jobs import tasks
from apps.jobs.models import ScanJob, ScanRun, ToolExecution
from services.redaction import redact_text

from .fixtures import make_target

SECRET = "AKIAIOSFODNN7EXAMPLESECRET"  # aws-key shape
WEBHOOK = "https://discord.com/api/webhooks/123456/SuperSecretToken"
BEARER = "Bearer eyJhbGciOiJIUzI1NiJ9.super.secret.value"


class StructuredLoggingTests(TestCase):
    """P2-011: one shape, with the required fields."""

    class _Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record)

    def _capture(self, fn, *a, **kw):
        handler = self._Capture()
        log = logging.getLogger("apps.jobs.tasks")
        log.addHandler(handler)
        old = log.level
        log.setLevel(logging.DEBUG)
        try:
            fn(*a, **kw)
        finally:
            log.removeHandler(handler)
            log.setLevel(old)
        return handler.records

    def test_stage_event_carries_every_required_field(self):
        t = make_target(root_domain="log1.example.com")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        job = ScanJob.objects.create(target=t, job_type="ports", status="RUNNING", scan_run=run)
        records = self._capture(
            tasks._log_stage_event,
            "INFO",
            "test:op",
            t,
            run,
            job,
            "ports",
            "naabu",
            status="OK",
            duration_ms=1234,
            error="RuntimeError",
        )
        self.assertEqual(len(records), 1)
        rec = records[0]
        for field in (
            "target_id",
            "scan_run_id",
            "job_id",
            "stage",
            "tool",
            "status",
            "duration_ms",
            "error",
            "operation",
        ):
            self.assertTrue(hasattr(rec, field), f"missing structured field {field}")
        self.assertEqual(rec.target_id, t.pk)
        self.assertEqual(rec.scan_run_id, run.pk)
        self.assertEqual(rec.job_id, job.pk)
        self.assertEqual(rec.stage, "ports")
        self.assertEqual(rec.tool, "naabu")
        self.assertEqual(rec.status, "OK")
        self.assertEqual(rec.duration_ms, 1234)

    def test_stage_timer_emits_start_and_end(self):
        t = make_target(root_domain="log2.example.com")
        records = self._capture(self._run_timer, t)
        statuses = [r.status for r in records]
        self.assertIn("START", statuses)
        self.assertIn("OK", statuses)
        end = next(r for r in records if r.status == "OK")
        self.assertIsInstance(end.duration_ms, int)

    def _run_timer(self, t):
        with tasks._StageTimer("op", t, None, None, "stage", "tool"):
            pass

    def test_stage_timer_reports_error_with_class_only(self):
        t = make_target(root_domain="log3.example.com")

        def _boom():
            try:
                with tasks._StageTimer("op", t, None, None, "stage", "tool"):
                    raise ValueError(f"token={SECRET}")
            except ValueError:
                pass  # the stage context reports, it does not swallow

        records = self._capture(_boom)
        self.assertTrue(records)
        err = next(r for r in records if r.status == "ERROR")
        self.assertEqual(err.error, "ValueError")  # class only, never the message

    def test_major_stages_emit_structured_lines(self):
        t = make_target(
            root_domain="log4.example.com", scan_profile="active", scan_config={"ports": "80"}
        )
        from apps.assets.models import IPAddress
        from services.tool_adapters.adapters import NaabuAdapter

        IPAddress.objects.create(target=t, ip="203.0.113.1")
        with patch.object(NaabuAdapter, "is_available", return_value=False):
            records = self._capture(tasks.scan_ports, t.id)
        ops = {getattr(r, "operation", "") for r in records}
        # the whole stage is logged (the fallback path still emits a pair)
        self.assertIn("scan_ports", ops)
        self.assertIn("scan_ports:finish", ops)
        for rec in records:
            self.assertTrue(hasattr(rec, "target_id"))

    def test_manual_scan_logs_start_and_finish(self):
        t = make_target(root_domain="log5.example.com")
        with (
            patch.object(tasks.discover_subdomains, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.resolve_dns, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.scan_ports, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.probe_http, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.discover_urls, "run", return_value={"status": "COMPLETED"}),
        ):
            records = self._capture(tasks.manual_scan, t.id)
        ops = {getattr(r, "operation", "") for r in records}
        self.assertIn("manual_scan:start", ops)
        self.assertIn("manual_scan:finish", ops)
        for rec in records:
            if getattr(rec, "operation", "") == "manual_scan:finish":
                self.assertEqual(rec.status, "COMPLETED")
                self.assertIsNotNone(rec.duration_ms)


class CorrelationIdTests(TestCase):
    """P2-012: a scan is traceable end to end."""

    def test_chain_scan_run_to_observation_to_event(self):
        t = make_target(root_domain="corr1.example.com")
        # build the chain directly: run -> job -> tool -> observation -> event
        run = ScanRun.objects.create(
            target=t, scan_type="DISCOVERY", status="RUNNING", trigger="manual", requested_by="42"
        )
        self.assertIsNotNone(run.requested_by)
        job = ScanJob.objects.create(target=t, job_type="ports", status="RUNNING", scan_run=run)
        te = ToolExecution.objects.create(
            target=t, scan_run=run, job=job, tool_name="naabu", status="COMPLETED"
        )
        from apps.core.execution_context import (
            ScanContext,
            record_observation,
            scan_context,
        )
        from services.event_engine.engine import emit_event

        with scan_context(ScanContext(target_id=t.pk, scan_run=run, job=job, tool_execution=te)):
            obs = record_observation("PORT", "203.0.113.1:80")
            ev, _ = emit_event(
                "NEW_OPEN_PORT",
                target=t,
                asset_type="PORT",
                asset_id=None,
                asset_value="203.0.113.1:80",
                source="naabu",
                scan_run=run,
                correlation_id="corr-chain-1",
            )
        self.assertEqual(obs.scan_run_id, run.pk)
        self.assertEqual(obs.job_id, job.pk)
        self.assertEqual(obs.tool_execution_id, te.pk)
        self.assertEqual(ev.scan_run_id, run.pk)
        self.assertEqual(ev.correlation_id, "corr-chain-1")

    def test_children_inherit_the_parent_correlation_id(self):
        t = make_target(root_domain="corr2.example.com")
        js_url = "https://cdn.corr2.example.com/app.js"
        v1 = b'fetch("/api/a");\nfetch("/api/b");\nvar jquery=1;'
        v2 = b'fetch("/api/a");\nfetch("/api/c");\nvar react=1;'
        from services.correlation.ingest import ingest_js

        ingest_js(t, js_url, v1, source="test")
        ingest_js(t, js_url, v2, source="test")
        from apps.events.models import Event

        parent = Event.objects.get(target=t, event_type="JS_CHANGED")
        children = Event.objects.filter(target=t, parent_event=parent)
        self.assertTrue(children.exists())
        for child in children:
            self.assertEqual(child.correlation_id, parent.correlation_id)
            self.assertEqual(child.target_id, t.pk)

    def test_tool_execution_links_to_run_and_job(self):
        t = make_target(root_domain="corr3.example.com")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        job = ScanJob.objects.create(target=t, job_type="http", status="RUNNING", scan_run=run)
        te = ToolExecution.objects.create(
            target=t, scan_run=run, job=job, tool_name="httpx", status="COMPLETED"
        )
        self.assertEqual(te.scan_run_id, run.pk)
        self.assertEqual(te.job_id, job.pk)
        self.assertEqual(te.job.job_type, "http")


class SecretHygieneTests(TestCase):
    """P2-013: synthetic secrets must not be persisted anywhere."""

    def test_redaction_masks_the_synthetic_secrets(self):
        for secret in (SECRET, WEBHOOK, BEARER):
            self.assertNotIn(secret, redact_text(f"value={secret}"), f"{secret} not redacted")

    def test_tool_output_reference_is_redacted_on_disk(self):
        t = make_target(root_domain="sec13.example.com")
        with tempfile.TemporaryDirectory() as raw_dir:
            with override_settings(RAW_DIR=raw_dir):
                row = tasks._record_tool(
                    t, None, None, "secretfinder", "COMPLETED", stdout=f'{{"secret":"{SECRET}"}}'
                )
                import os

                with open(os.path.join(raw_dir, row.stdout_reference), encoding="utf-8") as fh:
                    body = fh.read()
        self.assertNotIn(SECRET, body)

    def test_command_is_redacted_before_persistence(self):
        t = make_target(root_domain="sec13b.example.com")
        from services.tool_adapters.base import redact_command

        cmd = ["nuclei", "-H", f"Authorization: {BEARER}"]
        row = tasks._record_tool(t, None, None, "nuclei", "COMPLETED", command=redact_command(cmd))
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", row.command)

    def test_event_evidence_is_not_written_with_raw_secrets(self):
        """JS secret-candidate events carry the type, never the value."""
        t = make_target(root_domain="sec13c.example.com")
        js_url = "https://cdn.sec13c.example.com/a.js"
        from services.correlation.ingest import ingest_js

        ingest_js(t, js_url, f'var k = "{SECRET}";'.encode(), source="test")
        from apps.events.models import Event

        for ev in Event.objects.filter(target=t):
            blob = json.dumps(ev.evidence, default=str)
            self.assertNotIn(SECRET, blob, f"{ev.event_type} leaked the secret")

    def test_job_log_messages_do_not_carry_secrets(self):
        """Job logs are operator-visible; a redaction failure would be a leak."""
        t = make_target(
            root_domain="sec13d.example.com", scan_profile="active", scan_config={"ports": "80"}
        )
        from apps.assets.models import IPAddress
        from services.tool_adapters.adapters import NaabuAdapter

        IPAddress.objects.create(target=t, ip="203.0.113.1")
        with patch.object(NaabuAdapter, "is_available", return_value=False):
            tasks.scan_ports(t.id)
        from apps.jobs.models import JobLog

        for log in JobLog.objects.filter(job__target=t):
            self.assertNotIn(SECRET, log.message)

    def test_exported_snapshot_carries_no_secret_material(self):
        """The finding's raw value stays internal; exports list URLs only."""
        import zipfile

        t = make_target(root_domain="sec13e.example.com")
        js_url = "https://cdn.sec13e.example.com/a.js"
        from services.correlation.ingest import ingest_js

        ingest_js(t, js_url, f'var k = "{SECRET}";'.encode(), source="test")
        from apps.monitoring.exports import build_snapshot

        with tempfile.TemporaryDirectory() as exports_dir:
            with override_settings(EXPORTS_DIR=exports_dir):
                path, _size, _rows = build_snapshot(t, {})
                with zipfile.ZipFile(path) as z:
                    body = "\n".join(z.read(n).decode() for n in z.namelist())
        self.assertNotIn(SECRET, body)
        self.assertIn("a.js", body)  # the asset itself is still exported
