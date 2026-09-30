"""P1-002/P1-003: complete tool-execution evidence, and no silent persistence loss.

Every tool execution must persist tool_name, redacted command, status,
started_at, finished_at, duration, exit_code, fallback, coverage, error and
stdout/stderr references. A lost evidence row must be visible and must not
leave a false clean-success state.
"""

import os
import tempfile
from unittest.mock import patch

from django.test import TestCase, override_settings

from apps.jobs import tasks
from apps.jobs.models import ToolExecution
from apps.targets.models import Target
from services.redaction import contains_secret, redact_text
from services.tool_adapters.base import AdapterResult, redact_command


class _TempRaw:
    """Redirect settings.RAW_DIR to a temp dir for evidence-file assertions."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="rawdir_")
        self._ctx = override_settings(RAW_DIR=self.dir)
        self._ctx.enable()
        return self.dir

    def __exit__(self, *exc):
        self._ctx.disable()
        return False


def _target():
    return Target.objects.create(
        name="ev.invalid", root_domain="ev.invalid", authorization_status=Target.AUTH_AUTHORIZED
    )


class RedactionTests(TestCase):
    def test_secret_assignments_are_masked(self):
        text = "api_key=AKIAIOSFODNN7EXAMPLE password: hunter2secret"
        out = redact_text(text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertNotIn("hunter2secret", out)
        self.assertTrue(contains_secret(text))

    def test_auth_headers_are_masked(self):
        out = redact_text("Authorization: Bearer abcdef1234567890")
        self.assertNotIn("abcdef1234567890", out)

    def test_url_credentials_are_masked(self):
        out = redact_text("http://user:pass@target.invalid/path")
        self.assertNotIn("user:pass", out)

    def test_pem_private_key_block_is_masked(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
        self.assertNotIn("MIIEow", redact_text(pem))

    def test_webhook_urls_are_masked(self):
        out = redact_text("posting to https://discord.com/api/webhooks/123/abcDEF")
        self.assertNotIn("123/abcDEF", out)

    def test_benign_text_is_untouched(self):
        text = "found 12 subdomains for example.invalid"
        self.assertEqual(redact_text(text), text)
        self.assertFalse(contains_secret(text))

    def test_truncation_is_bounded(self):
        out = redact_text("x" * 5000, limit=100)
        self.assertLess(len(out), 200)
        self.assertIn("truncated", out)


class AdapterEvidenceTests(TestCase):
    """The adapter result carries the evidence the DB row needs (P1-002)."""

    def test_missing_tool_result_carries_command(self):
        from services.tool_adapters.adapters import NaabuAdapter

        with patch.object(NaabuAdapter, "is_available", return_value=False):
            res = NaabuAdapter().run("1.2.3.4", ports="80")
        self.assertEqual(res.status, "SKIPPED")
        self.assertIn("naabu", res.command)

    def test_successful_run_persists_full_evidence(self):
        from services.tool_adapters.adapters import SubfinderAdapter

        with _TempRaw() as raw_dir:
            with (
                patch.object(SubfinderAdapter, "is_available", return_value=True),
                patch.object(
                    SubfinderAdapter,
                    "build_command",
                    return_value=["subfinder", "-d", "ev.invalid"],
                ),
                patch(
                    "services.tool_adapters.base._run_tool_process",
                    return_value=(0, "a.ev.invalid\nb.ev.invalid\n", ""),
                ),
            ):
                res = SubfinderAdapter().run("ev.invalid")
        self.assertEqual(res.status, "COMPLETED")
        self.assertEqual(res.exit_code, 0)
        self.assertIn("subfinder", res.command)
        self.assertIn("a.ev.invalid", res.stdout)
        self.assertIsInstance(res.duration_ms, int)
        # the row stores a *reference* to a real, readable file
        t = _target()
        with _TempRaw() as raw_dir:
            row = tasks._record_tool(
                t,
                None,
                None,
                "subfinder",
                res.status,
                error=res.error,
                coverage={"hosts": len(res.data)},
                started_at=None,
                finished_at=None,
                exit_code=res.exit_code,
                command=res.command,
                stdout=res.stdout,
                stderr=res.stderr,
                duration_ms=res.duration_ms,
            )
            self.assertTrue(row.stdout_reference)
            stored = os.path.join(raw_dir, row.stdout_reference)
            self.assertTrue(os.path.isfile(stored))
            with open(stored, encoding="utf-8") as fh:
                self.assertIn("a.ev.invalid", fh.read())
        self.assertIsNotNone(row.duration)

    def test_timeout_result_is_marked_failed(self):
        import subprocess

        from services.tool_adapters.adapters import NaabuAdapter

        with (
            patch.object(NaabuAdapter, "is_available", return_value=True),
            patch.object(NaabuAdapter, "build_command", return_value=["naabu", "1.2.3.4"]),
            patch(
                "services.tool_adapters.base._run_tool_process",
                side_effect=subprocess.TimeoutExpired(cmd="naabu", timeout=1),
            ),
        ):
            res = NaabuAdapter().run("1.2.3.4")
        self.assertEqual(res.status, "FAILED")
        self.assertEqual(res.error, "timeout")
        self.assertIsNone(res.exit_code)
        self.assertIn("naabu", res.command)

    def test_nonzero_exit_is_partial_with_exit_code(self):
        from services.tool_adapters.adapters import HttpxAdapter

        with (
            patch.object(HttpxAdapter, "is_available", return_value=True),
            patch.object(HttpxAdapter, "build_command", return_value=["httpx", "-l"]),
            patch(
                "services.tool_adapters.base._run_tool_process",
                return_value=(2, '{"url":"https://x.invalid"}', "warn: partial"),
            ),
        ):
            res = HttpxAdapter().run_stdin(["x.invalid"])
        self.assertEqual(res.status, "PARTIAL")
        self.assertEqual(res.exit_code, 2)
        self.assertIn("warn", res.stderr)

    def test_command_secrets_are_redacted_before_persistence(self):
        cmd = ["nuclei", "-t", "templates/", "-H", "X-API-Key: supersecretvalue123"]
        red = redact_command(cmd)
        self.assertNotIn("supersecretvalue123", red)
        t = _target()
        row = tasks._record_tool(t, None, None, "nuclei", "COMPLETED", command=red)
        self.assertNotIn("supersecretvalue123", row.command)

    def test_output_secrets_are_redacted_before_writing(self):
        with _TempRaw() as raw_dir:
            t = _target()
            row = tasks._record_tool(
                t,
                None,
                None,
                "secretfinder",
                "COMPLETED",
                stdout='{"secret":"AKIAIOSFODNN7EXAMPLE"}',
            )
            stored = os.path.join(raw_dir, row.stdout_reference)
            with open(stored, encoding="utf-8") as fh:
                body = fh.read()
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", body)
        self.assertIn("REDACTED", body)


class EvidenceLossTests(TestCase):
    """P1-003: a lost evidence row is visible and never looks clean."""

    def test_persistence_failure_is_logged_and_counted(self):
        t = _target()
        tasks._evidence_failures(reset=True)
        with patch(
            "apps.jobs.models.ToolExecution.objects.create", side_effect=RuntimeError("db down")
        ):
            row = tasks._record_tool(t, None, None, "naabu", "COMPLETED")
        self.assertIsNone(row)
        failures = tasks._evidence_failures()
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["kind"], "tool_execution")
        self.assertIn("naabu", failures[0]["detail"])

    def test_evidence_loss_emits_visible_event(self):
        from apps.events.models import Event

        t = _target()
        tasks._evidence_failures(reset=True)
        with patch(
            "apps.jobs.models.ToolExecution.objects.create", side_effect=RuntimeError("db down")
        ):
            tasks._record_tool(t, None, None, "naabu", "COMPLETED")
        ev = Event.objects.filter(
            target=t, event_type="JOB_FAILED", evidence__evidence_lost=True
        ).first()
        self.assertIsNotNone(ev)
        self.assertEqual(ev.evidence["tool"], "naabu")

    def test_lost_evidence_prevents_clean_stage_completion(self):
        from apps.assets.models import IPAddress
        from apps.jobs.models import ScanJob
        from services.tool_adapters.adapters import NaabuAdapter

        t = Target.objects.create(
            name="ev2.invalid",
            root_domain="ev2.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
            scan_profile="active",
            scan_config={"ports": "80"},
        )
        IPAddress.objects.create(target=t, ip="203.0.113.5")
        with (
            patch.object(NaabuAdapter, "is_available", return_value=False),
            patch(
                "apps.jobs.models.ToolExecution.objects.create", side_effect=RuntimeError("db down")
            ),
        ):
            out = tasks.scan_ports(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        self.assertEqual(ScanJob.objects.get(job_type="ports").status, "PARTIAL")

    def test_evidence_counter_resets_per_stage(self):
        from apps.core.execution_context import note_evidence_loss

        tasks._evidence_failures(reset=True)
        note_evidence_loss("tool_execution", "x FAILED: boom")
        self.assertEqual(len(tasks._evidence_failures()), 1)
        tasks._evidence_failures(reset=True)
        self.assertEqual(tasks._evidence_failures(), [])


class FullPipelineEvidenceTests(TestCase):
    """Real tool runs persist the whole evidence set end to end (P1-002)."""

    def test_dnsx_run_persists_evidence(self):
        from services.tool_adapters.adapters import DnsxAdapter

        t = _target()
        with _TempRaw():
            result = AdapterResult(
                "dnsx",
                status="COMPLETED",
                data=[{"hostname": "a.ev.invalid", "type": "A", "value": "1.2.3.4"}],
                command="dnsx -l hosts.txt",
                exit_code=0,
                stdout="a.ev.invalid 1.2.3.4",
                stderr="",
                duration_ms=1200,
            )
            with (
                patch.object(DnsxAdapter, "is_available", return_value=True),
                patch.object(DnsxAdapter, "run_stdin", return_value=result),
            ):
                out = tasks.resolve_dns(t.id)
        self.assertEqual(out["status"], "COMPLETED")
        row = ToolExecution.objects.filter(tool_name="dnsx").last()
        self.assertEqual(row.command, "dnsx -l hosts.txt")
        self.assertEqual(row.exit_code, 0)
        self.assertTrue(row.stdout_reference)
        self.assertIsNotNone(row.duration)
        self.assertIsNotNone(row.started_at)
        self.assertIsNotNone(row.finished_at)
        self.assertIsNotNone(row.scan_run_id)
        self.assertEqual(row.target_id, t.pk)
        self.assertIsNotNone(row.job_id)
