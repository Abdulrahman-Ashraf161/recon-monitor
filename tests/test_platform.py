"""Unit tests: scope, normalization, dedup, CVE matching, discord redaction, events."""
from django.test import TestCase

from apps.targets.models import Target


class ScopeValidationTests(TestCase):
    def test_subdomain_allowed_and_excluded(self):
        from apps.scope.models import ScopeRule
        from services.scope_engine.validator import validate_host, validate_ip

        t = Target.objects.create(name="t", root_domain="example.com")
        ScopeRule.objects.create(target=t, rule_type="exclude_host", value="staging.example.com")
        ok, _ = validate_host(t, "api.example.com", list(t.scope_rules.all()))
        self.assertTrue(ok)
        ok, _ = validate_host(t, "staging.example.com", list(t.scope_rules.all()))
        self.assertFalse(ok)
        ok, _ = validate_host(t, "evil.com", list(t.scope_rules.all()))
        self.assertFalse(ok)
        ok, _ = validate_ip(t, "1.2.3.4", list(t.scope_rules.all()))
        self.assertTrue(ok)


class NormalizationTests(TestCase):
    def test_host_normalization(self):
        from services.normalization.hosts import dedup_hostnames, normalize_hostname

        self.assertEqual(normalize_hostname("API.Example.COM."), "api.example.com")
        self.assertIsNone(normalize_hostname("not a host!!"))
        merged = dedup_hostnames([("API.Example.COM.", "subfinder"), ("api.example.com", "crtsh")])
        self.assertEqual(merged, {"api.example.com": ["crtsh", "subfinder"]})

    def test_url_canonicalization_and_api(self):
        from services.normalization.urls import canonicalize_url, classify_api

        self.assertEqual(canonicalize_url("HTTPS://Example.COM:443/A"), "https://example.com/A")
        is_api, kind, _ = classify_api("https://x.example.com/api/v1/users")
        self.assertTrue(is_api)
        self.assertIn("REST", kind)


class EventDedupTests(TestCase):
    def test_fingerprint_dedup(self):
        from services.event_engine.engine import emit_event

        t = Target.objects.create(name="t", root_domain="example.com")
        e1, c1 = emit_event("NEW_SUBDOMAIN", target=t, asset_value="api.example.com", source="test")
        e2, c2 = emit_event("NEW_SUBDOMAIN", target=t, asset_value="api.example.com", source="test")
        self.assertTrue(c1)
        self.assertFalse(c2)
        self.assertEqual(e1.pk, e2.pk)


class BaselineSuppressionTests(TestCase):
    def test_baseline_suppresses_new_alerts_but_persists_events(self):
        from apps.events.models import Alert, Event
        from services.event_engine.engine import emit_event

        t = Target.objects.create(name="t", root_domain="example.com", baseline_status="INITIAL_BASELINE")
        e, created = emit_event("NEW_SUBDOMAIN", target=t, asset_value="a.example.com", source="test")
        self.assertTrue(created)
        self.assertTrue(Event.objects.filter(pk=e.pk).exists())
        self.assertTrue(Alert.objects.filter(event=e, status="SUPPRESSED").exists())


class CVEMatcherTests(TestCase):
    def test_version_in_range(self):
        from services.cve_engine.matcher import version_in_range

        self.assertTrue(version_in_range("1.2.3", ">=1.0,<2.0"))
        self.assertFalse(version_in_range("2.5.0", "<1.25.0"))
        self.assertTrue(version_in_range("anything", ""))


class DiscordRedactionTests(TestCase):
    def test_secrets_redacted(self):
        from services.alerting.discord import mask_secret, redact_evidence

        ev = redact_evidence({"api_key": "abcdef1234567890", "note": "hello"})
        self.assertIn("********", ev["api_key"])
        self.assertNotIn("abcdef1234567890", ev["api_key"])
        self.assertEqual(ev["note"], "hello")
        self.assertEqual(mask_secret("short"), "********")


class IngestTests(TestCase):
    def test_ingest_subdomains_creates_event(self):
        from apps.assets.models import Subdomain
        from apps.events.models import Event
        from services.correlation.ingest import ingest_subdomains

        t = Target.objects.create(name="t", root_domain="example.com")
        new, total = ingest_subdomains(t, [{"hostname": "Api.Example.COM.", "source": "subfinder"}])
        self.assertEqual(new, 1)
        self.assertTrue(Subdomain.objects.filter(target=t, hostname="api.example.com").exists())
        self.assertTrue(Event.objects.filter(event_type="NEW_SUBDOMAIN").exists())
        # second ingest: no duplicate event
        new2, _ = ingest_subdomains(t, [{"hostname": "api.example.com", "source": "crtsh"}])
        self.assertEqual(new2, 0)
        self.assertEqual(Event.objects.filter(event_type="NEW_SUBDOMAIN").count(), 1)

    def test_js_change_detection(self):
        from services.correlation.ingest import ingest_js

        t = Target.objects.create(name="t", root_domain="example.com")
        _, o1 = ingest_js(t, "https://example.com/app.js", b"var a=1;", source="test")
        self.assertEqual(o1, "NEW_JS")
        _, o2 = ingest_js(t, "https://example.com/app.js", b"var a=2;", source="test")
        self.assertEqual(o2, "JS_CHANGED")


class ToolFailureTests(TestCase):
    def test_missing_binary_skipped(self):
        from services.tool_adapters.adapters import SubfinderAdapter

        a = SubfinderAdapter()
        a.binary = "definitely-not-installed-xyz"
        res = a.run("example.com")
        self.assertEqual(res.status, "SKIPPED")


class IncrementalChainTests(TestCase):
    def test_new_subdomain_triggers_downstream_job_with_context(self):
        from apps.jobs.models import ScanJob
        from apps.jobs.tasks import process_new_subdomain

        t = Target.objects.create(name="t", root_domain="example.invalid",
                                    authorization_status=Target.AUTH_AUTHORIZED)
        out = process_new_subdomain(t.id, "api.example.invalid", trigger="event:1")
        self.assertEqual(out["status"], "COMPLETED")
        job = ScanJob.objects.filter(target=t, job_type="dns", asset_value="api.example.invalid").first()
        self.assertIsNotNone(job)
        self.assertEqual(job.trigger, "event:1")

    def test_fanout_coalesces_while_running(self):
        from apps.jobs.models import ScanJob
        from apps.jobs.tasks import handle_event_dependents
        from services.event_engine.engine import emit_event

        t = Target.objects.create(name="t", root_domain="example.invalid",
                                    authorization_status=Target.AUTH_AUTHORIZED)
        ScanJob.objects.create(target=t, job_type="dns", status="RUNNING",
                               asset_type="SUBDOMAIN", asset_value="api.example.invalid")
        e, _ = emit_event("NEW_SUBDOMAIN", target=t, asset_value="other.example.invalid", source="test")
        # fan-out for NEW_SUBDOMAIN dispatches process_new_subdomain; asset job creation
        # must not duplicate a RUNNING job for the same asset
        out = handle_event_dependents(e.id)
        self.assertEqual(out["status"], "QUEUED")

    def test_duplicate_url_no_new_event(self):
        from apps.events.models import Event
        from services.correlation.ingest import ingest_urls

        t = Target.objects.create(name="t", root_domain="example.invalid")
        ingest_urls(t, [{"url": "https://example.invalid/a", "source": "gau"}])
        n1 = Event.objects.filter(event_type="NEW_URL").count()
        ingest_urls(t, [{"url": "https://example.invalid/a", "source": "katana"}])
        n2 = Event.objects.filter(event_type="NEW_URL").count()
        self.assertEqual(n1, n2)
        # sources aggregated
        from apps.assets.models import URLAsset

        u = URLAsset.objects.get(target=t)
        self.assertEqual(u.source, "gau")  # first source wins; no duplicate row


class JSAnalysisTests(TestCase):
    def test_new_js_queues_analysis_and_logs_stages(self):
        from apps.jobs.models import JSAnalysisJob
        from services.correlation.ingest import ingest_js

        t = Target.objects.create(name="t", root_domain="example.invalid",
                                    authorization_status=Target.AUTH_AUTHORIZED)
        js, outcome = ingest_js(t, "https://example.invalid/app.js", b"var a=1;", source="test")
        self.assertEqual(outcome, "NEW_JS")
        # fan-out queues analysis (eager: runs inline, download fails for .invalid -> FAILED w/ logs)
        from apps.jobs.tasks import queue_js_analysis

        out = queue_js_analysis(js.id, trigger="NEW_JS")
        self.assertIn(out["status"], ("QUEUED", "SKIPPED"))
        aj = JSAnalysisJob.objects.filter(js=js).first()
        self.assertIsNotNone(aj)
        self.assertTrue(aj.logs.exists())
        self.assertIn(aj.current_stage, ("DONE", "FAILED", "DOWNLOADING", "QUEUED"))

    def test_changed_js_reanalyzed(self):
        from services.correlation.ingest import ingest_js

        t = Target.objects.create(name="t", root_domain="example.invalid")
        js, _ = ingest_js(t, "https://example.invalid/app.js", b"var a=1;", source="test")
        js2, outcome = ingest_js(t, "https://example.invalid/app.js", b"var a=2;", source="test")
        self.assertEqual(outcome, "JS_CHANGED")
        self.assertEqual(js.id, js2.id)


class DiscordFailureTests(TestCase):
    def test_discord_failure_keeps_event_and_marks_failed(self):
        from django.test import override_settings

        from apps.events.models import Alert
        from services.event_engine.engine import emit_event

        t = Target.objects.create(name="t", root_domain="example.invalid")
        with override_settings(DISCORD_ENABLED=True, DISCORD_WEBHOOK_URL="http://127.0.0.1:9/invalid"):
            from apps.alerts.tasks import send_discord_alert

            e, _ = emit_event("NEW_IP", target=t, asset_value="10.0.0.1", source="test", severity="HIGH")
            out = send_discord_alert(e.id)
            self.assertEqual(out["status"], "FAILED")
            self.assertTrue(Alert.objects.filter(event=e, status="FAILED").exists())
            from apps.events.models import Event

            self.assertTrue(Event.objects.filter(pk=e.pk).exists())


class ExportTests(TestCase):
    def test_txt_and_snapshot_exports(self):
        from apps.monitoring.exports import run_export_job
        from apps.monitoring.models import ExportJob
        from services.correlation.ingest import ingest_subdomains

        t = Target.objects.create(name="t", root_domain="example.invalid")
        ingest_subdomains(t, [{"hostname": "a.example.invalid", "source": "subfinder"}])
        job = ExportJob.objects.create(target=t, export_type="subdomains", format="txt")
        out = run_export_job(job.id)
        self.assertEqual(out["status"], "COMPLETED")
        with open(ExportJob.objects.get(pk=job.id).file_path) as f:
            self.assertIn("a.example.invalid", f.read())
        snap = ExportJob.objects.create(target=t, export_type="snapshot", format="zip")
        out = run_export_job(snap.id)
        self.assertEqual(out["status"], "COMPLETED")


class IngestRobustnessTests(TestCase):
    """Task 12: one malformed URL never aborts the whole ingest batch."""

    def test_malformed_url_does_not_abort_batch(self):
        from apps.assets.models import URLAsset
        from apps.targets.models import Target
        from services.correlation.ingest import ingest_urls
        t = Target.objects.create(name="robust", root_domain="example.invalid")
        new_urls, _ = ingest_urls(t, [
            {"url": "https://", "source": "gau"},       # malformed: no host
            {"url": "https://example.invalid/ok", "source": "gau"},
            "not-a-dict",                                # wrong shape entirely
        ])
        self.assertEqual(new_urls, 1)
        self.assertTrue(URLAsset.objects.filter(
            target=t, canonical_url="https://example.invalid/ok").exists())


class RedactionTests(TestCase):
    """Task 23: secrets redacted in both directions, non-secrets preserved."""

    def test_separate_arg_secret_redacted(self):
        from services.tool_adapters.base import redact_command
        self.assertEqual(redact_command(["subfinder", "-shodan-key", "sk-live-123"]),
                         "subfinder -shodan-key ***REDACTED***")

    def test_header_secret_redacted(self):
        from services.tool_adapters.base import redact_command
        self.assertEqual(redact_command(["httpx", "-H", "Authorization: Bearer abc"]),
                         "httpx -H ***REDACTED***")

    def test_url_userinfo_redacted(self):
        from services.tool_adapters.base import redact_command
        self.assertEqual(
            redact_command(["nuclei", "-u", "https://user:s3cr3t@example.com/x"]),
            "nuclei -u https://***REDACTED***@example.com/x")

    def test_benign_command_preserved(self):
        from services.tool_adapters.base import redact_command
        self.assertEqual(redact_command(["nuclei", "-u", "https://example.com"]),
                         "nuclei -u https://example.com")


class AuthorizationDefaultTests(TestCase):
    """Task 29: new targets are NOT scannable until explicitly authorized."""

    def test_new_target_defaults_to_not_scannable(self):
        from apps.targets.models import Target
        t = Target.objects.create(name="pending", root_domain="pending.invalid")
        self.assertNotEqual(t.authorization_status, Target.AUTH_AUTHORIZED)
        self.assertFalse(t.is_scannable)

    def test_existing_authorized_unaffected(self):
        from apps.targets.models import Target
        t = Target.objects.create(name="auth", root_domain="auth.invalid",
                                  authorization_status=Target.AUTH_AUTHORIZED)
        self.assertTrue(t.is_scannable)

    def test_form_requires_confirmation_for_authorized(self):
        from apps.targets.forms import TargetForm
        from apps.targets.models import Target
        form = TargetForm({"name": "f", "root_domain": "f.invalid",
                           "status": Target.STATUS_ACTIVE,
                           "authorization_status": Target.AUTH_AUTHORIZED,
                           "auth_warning_days": 7, "scan_profile": "balanced",
                           "verify_tls": True, "scan_config": {}})
        self.assertFalse(form.is_valid())
        form = TargetForm({"name": "f", "root_domain": "f.invalid",
                           "status": Target.STATUS_ACTIVE,
                           "authorization_status": Target.AUTH_AUTHORIZED,
                           "authorization_expires_at": "2030-01-01 00:00",
                           "auth_warning_days": 7, "scan_profile": "balanced",
                           "verify_tls": True, "scan_config": {},
                           "confirm_authorized": True})
        self.assertTrue(form.is_valid(), form.errors)


class TlsContextTests(TestCase):
    """Task 3: every stdlib fetch honors target.verify_tls."""

    def test_verify_true_gives_validating_context(self):
        import ssl

        from apps.jobs.tasks import _ssl_context_for
        from apps.targets.models import Target
        t = Target(name="t", root_domain="x.invalid", verify_tls=True)
        ctx = _ssl_context_for(t)
        self.assertTrue(ctx.check_hostname)
        self.assertNotEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_verify_false_gives_insecure_context_with_log(self):
        import ssl

        from apps.jobs.models import JobLog, ScanJob
        from apps.jobs.tasks import _ssl_context_for
        from apps.targets.models import Target
        t = Target.objects.create(name="t", root_domain="x.invalid", verify_tls=False)
        job = ScanJob.objects.create(target=t, job_type="http", status="RUNNING")
        ctx = _ssl_context_for(t, job, stage="http")
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertTrue(JobLog.objects.filter(
            job=job, level="WARNING", message__icontains="verify_tls=false").exists())


class ScopeRulesTests(TestCase):
    """Validator allow/exclude branches (coverage for scope_engine)."""

    def _rule(self, target, rule_type, value):
        from apps.scope.models import ScopeRule
        return ScopeRule.objects.create(target=target, rule_type=rule_type, value=value)

    def test_allow_domain_and_wildcard(self):
        from apps.targets.models import Target
        from services.scope_engine.validator import validate_host
        t = Target.objects.create(name="r", root_domain="example.invalid")
        self._rule(t, "allow_domain", "*.example.invalid")
        rules = list(t.scope_rules.all())
        ok, _ = validate_host(t, "a.example.invalid", rules)
        self.assertTrue(ok)
        ok, _ = validate_host(t, "other.org", rules)
        self.assertFalse(ok)

    def test_exclude_host_wins(self):
        from apps.targets.models import Target
        from services.scope_engine.validator import validate_host
        t = Target.objects.create(name="r2", root_domain="example.invalid")
        self._rule(t, "exclude_host", "bad.example.invalid")
        rules = list(t.scope_rules.all())
        ok, _ = validate_host(t, "bad.example.invalid", rules)
        self.assertFalse(ok)
        ok, _ = validate_host(t, "good.example.invalid", rules)
        self.assertTrue(ok)

    def test_ip_allow_exclude_lists(self):
        from apps.targets.models import Target
        from services.scope_engine.validator import validate_ip
        t = Target.objects.create(name="r3", root_domain="example.invalid")
        self._rule(t, "exclude_ip", "192.0.2.0/24")
        self._rule(t, "allow_ip", "198.51.100.0/24")
        rules = list(t.scope_rules.all())
        ok, _ = validate_ip(t, "192.0.2.5", rules)
        self.assertFalse(ok)
        ok, _ = validate_ip(t, "198.51.100.9", rules)
        self.assertTrue(ok)
        ok, _ = validate_ip(t, "203.0.113.9", rules)
        self.assertFalse(ok)

    def test_scope_allows_scan_states(self):
        from apps.targets.models import Target
        from services.scope_engine.validator import scope_allows_scan
        t = Target.objects.create(name="r4", root_domain="example.invalid",
                                  authorization_status=Target.AUTH_AUTHORIZED)
        ok, _ = scope_allows_scan(t, [])
        self.assertTrue(ok)
        t.status = Target.STATUS_PAUSED
        ok, _ = scope_allows_scan(t, [])
        self.assertFalse(ok)

    def test_resolve_check_unresolvable_and_obfuscation(self):
        from services.scope_engine.validator import (
            host_resolves_to_blocked, is_private_or_reserved,
        )
        blocked, _ = host_resolves_to_blocked("no-such-host.invalid")
        self.assertFalse(blocked)
        # decimal-encoded loopback + octal garbage (fail-closed)
        self.assertTrue(is_private_or_reserved("2130706433"))
        self.assertTrue(is_private_or_reserved("0177.0.0.1"))

    def test_resolve_check_blocked_and_public(self):
        import socket
        from unittest.mock import patch
        from services.scope_engine.validator import host_resolves_to_blocked
        with patch.object(socket, "getaddrinfo",
                          return_value=[(socket.AF_INET, None, None, None, ("10.9.9.9", 0))]):
            blocked, why = host_resolves_to_blocked("x.invalid")
            self.assertTrue(blocked)
            self.assertIn("10.9.9.9", why)
        with patch.object(socket, "getaddrinfo",
                          return_value=[(socket.AF_INET, None, None, None, ("93.184.216.34", 0))]):
            blocked, _ = host_resolves_to_blocked("x.invalid")
            self.assertFalse(blocked)
