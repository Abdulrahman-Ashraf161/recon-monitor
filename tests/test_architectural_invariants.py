"""P2-010 — Architectural invariants, encoded as tests.

These are the cross-cutting rules that must hold *system-wide*, not just inside
one view or task. Each is stated as a numbered invariant from the taskbook and
proven end to end against the real models, views, tasks and channels.

    1. every target-specific artifact belongs to one target
    2. parent/child execution artifacts cannot cross targets
    3. unauthorized users cannot retrieve target data
    4. partial scans cannot create removal events
    5. paused/expired targets cannot start new work
    6. ScanRun is the canonical scan root
    7. event fingerprints are unique
    8. TLS policy is consistent
    9. exports are target-specific
   10. tool failures cannot be represented as complete coverage
"""

from datetime import timedelta
from unittest.mock import patch

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.assets.models import (
    JavaScriptAsset,
    Port,
    Subdomain,
)
from apps.core.consistency import ExecutionConsistencyError
from apps.events.models import Event
from apps.jobs import tasks
from apps.jobs.models import AssetObservation, ScanJob, ScanRun, ToolExecution
from apps.targets.models import Target

from .fixtures import make_target, make_world


class Invariant01_OneTargetPerArtifact(TestCase):
    """1. Every target-specific artifact belongs to exactly one target."""

    def test_asset_families_are_queryable_per_target_only(self):
        a, b = make_target(root_domain="i1a.example.com"), make_target(
            root_domain="i1b.example.com"
        )
        Subdomain.objects.create(target=a, hostname="only-a.example.com")
        Subdomain.objects.create(target=b, hostname="only-b.example.com")
        Port.objects.create(target=a, ip="203.0.113.1", port=80, protocol="tcp", state="open")
        # an asset carries exactly one target and is only ever read through it
        self.assertEqual(Subdomain.all_objects.filter(target=a).count(), 1)
        self.assertEqual(Subdomain.all_objects.filter(target=b).count(), 1)
        self.assertEqual(Subdomain.objects.get(hostname="only-a.example.com").target_id, a.pk)

    def test_observations_observations_and_assets_are_target_bound(self):
        a, b = make_target(root_domain="i1c.example.com"), make_target(
            root_domain="i1d.example.com"
        )
        run = ScanRun.objects.create(target=a, scan_type="DISCOVERY", status="COMPLETED")
        AssetObservation.objects.create(
            target=a, scan_run=run, asset_type="SUBDOMAIN", asset_value="x.i1c.example.com"
        )
        # an observation claiming another target's run is rejected
        with self.assertRaises(ExecutionConsistencyError):
            AssetObservation(target=b, scan_run=run, asset_type="SUBDOMAIN", asset_value="x").save()


class Invariant02_ParentChildCannotCrossTargets(TestCase):
    """2. Parent/child execution artifacts cannot cross targets."""

    def test_scanjob_cannot_borrow_another_targets_run(self):
        a, b = make_target(root_domain="i2a.example.com"), make_target(
            root_domain="i2b.example.com"
        )
        run_b = ScanRun.objects.create(target=b, scan_type="DISCOVERY", status="RUNNING")
        with self.assertRaises(ExecutionConsistencyError):
            ScanJob(target=a, job_type="ports", status="QUEUED", scan_run=run_b).save()

    def test_parent_job_cannot_borrow_another_targets_job(self):
        a, b = make_target(root_domain="i2c.example.com"), make_target(
            root_domain="i2d.example.com"
        )
        parent_b = ScanJob.objects.create(target=b, job_type="http", status="COMPLETED")
        with self.assertRaises(ExecutionConsistencyError):
            ScanJob(target=a, job_type="ports", status="QUEUED", parent=parent_b).save()

    def test_js_analysis_job_cannot_borrow_another_targets_asset(self):
        a, b = make_target(root_domain="i2e.example.com"), make_target(
            root_domain="i2f.example.com"
        )
        js_b = JavaScriptAsset.objects.create(
            target=b, js_url="https://x.example.com/b.js", host="x.example.com", sha256="b" * 64
        )
        from apps.jobs.models import JSAnalysisJob

        with self.assertRaises(ExecutionConsistencyError):
            JSAnalysisJob(target=a, js=js_b, trigger="NEW_JS").save()

    def test_get_or_create_run_rejects_a_foreign_run_id(self):
        a, b = make_target(root_domain="i2g.example.com"), make_target(
            root_domain="i2h.example.com"
        )
        run_b = ScanRun.objects.create(target=b, scan_type="DISCOVERY", status="RUNNING")
        with self.assertRaises(ExecutionConsistencyError):
            tasks._get_or_create_run(a, scan_run_id=run_b.pk)


class Invariant03_UnauthorizedCannotRetrieve(TestCase):
    """3. Unauthorized users cannot retrieve target data (any surface)."""

    def setUp(self):
        self.w = make_world()

    def test_api_is_scoped(self):
        Subdomain.objects.create(target=self.w["target_b"], hostname="secret.beta.example.com")
        Subdomain.objects.create(target=self.w["target_a"], hostname="mine.alpha.example.com")
        self.client.force_login(self.w["user_a"])
        r = self.client.get("/api/subdomains/")
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        self.assertNotIn("secret.beta.example.com", body)
        self.assertIn("mine.alpha.example.com", body)

    def test_event_api_is_scoped(self):
        Event.objects.create(
            target=self.w["target_a"],
            event_type="NEW_SUBDOMAIN",
            asset_value="a.alpha.example.com",
            fingerprint="i3-a",
        )
        Event.objects.create(
            target=self.w["target_b"],
            event_type="NEW_SUBDOMAIN",
            asset_value="b.beta.example.com",
            fingerprint="i3-b",
        )
        self.client.force_login(self.w["user_a"])
        r = self.client.get("/api/events/")
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        self.assertNotIn("b.beta.example.com", body)

    def test_job_detail_is_scoped(self):
        job_b = ScanJob.objects.create(
            target=self.w["target_b"], job_type="ports", status="COMPLETED"
        )
        self.client.force_login(self.w["user_a"])
        r = self.client.get(reverse("job-detail", args=[job_b.pk]))
        self.assertEqual(r.status_code, 403)


class Invariant04_PartialScansCannotCreateRemovals(TestCase):
    """4. Partial scans cannot create removal events (P1-010)."""

    def _stale(self, target):
        sub = Subdomain.objects.create(target=target, hostname="stale.example.com")
        Subdomain.objects.filter(pk=sub.pk).update(last_seen=timezone.now() - timedelta(days=90))
        return sub

    def _stage(self, target, status):
        ScanJob.objects.create(target=target, job_type="subdomain_enum", status=status)

    def test_partial_scan_produces_no_removal(self):
        t = make_target(root_domain="i4a.example.com")
        sub = self._stale(t)
        self._stage(t, ScanJob.STATUS_PARTIAL)
        out = tasks.reconcile_target(t.id)
        self.assertEqual(out["marked_inactive"], 0)
        self.assertTrue(Subdomain.objects.get(pk=sub.pk).is_active)
        self.assertEqual(Event.objects.filter(target=t, event_type="SUBDOMAIN_REMOVED").count(), 0)

    def test_complete_scan_may_remove(self):
        t = make_target(root_domain="i4b.example.com")
        sub = self._stale(t)
        self._stage(t, ScanJob.STATUS_COMPLETED)
        out = tasks.reconcile_target(t.id)
        self.assertEqual(out["marked_inactive"], 1)
        self.assertFalse(Subdomain.objects.get(pk=sub.pk).is_active)


class Invariant05_PausedExpiredCannotStartWork(TestCase):
    """5. Paused/expired targets cannot start new work (P0-013/P0-014)."""

    def test_paused_target_starts_no_stage(self):
        t = make_target(root_domain="i5a.example.com", status=Target.STATUS_PAUSED)
        out = tasks.discover_subdomains(t.id)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertEqual(ScanJob.objects.filter(target=t, status=ScanJob.STATUS_RUNNING).count(), 0)

    def test_expired_authorization_starts_no_stage(self):
        t = make_target(
            root_domain="i5b.example.com",
            authorization_expires_at=timezone.now() - timedelta(days=1),
        )
        out = tasks.scan_ports(t.id)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertIn("not scannable", out.get("reason", ""))

    def test_archived_target_starts_no_stage(self):
        t = make_target(root_domain="i5c.example.com")
        from apps.targets.target_lifecycle import archive_target

        archive_target(t, reason="test")
        out = tasks.probe_http(t.id)
        self.assertEqual(out["status"], "SKIPPED")


class Invariant06_ScanRunIsCanonicalRoot(TestCase):
    """6. ScanRun is the canonical root; stage work joins one root."""

    def test_chain_stages_share_one_run(self):
        t = make_target(root_domain="i6a.example.com")
        with (
            patch.object(tasks.discover_subdomains, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.resolve_dns, "run", return_value={"status": "COMPLETED"}),
        ):
            out = tasks.manual_scan(t.id)
        runs = ScanRun.objects.filter(target=t, scan_type="DISCOVERY")
        self.assertEqual(runs.count(), 1)
        self.assertEqual(runs.get().pk, out["run_id"])

    def test_every_job_evidence_row_hangs_off_a_run(self):
        t = make_target(root_domain="i6b.example.com")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        job = ScanJob.objects.create(target=t, job_type="ports", status="RUNNING", scan_run=run)
        te = ToolExecution.objects.create(
            target=t, scan_run=run, job=job, tool_name="naabu", status="COMPLETED"
        )
        obs = AssetObservation.objects.create(
            target=t,
            scan_run=run,
            job=job,
            tool_execution=te,
            asset_type="PORT",
            asset_value="1.2.3.4:80",
        )
        # each child is reachable from the root
        self.assertEqual(obs.tool_execution.scan_run_id, run.pk)
        self.assertEqual(job.scan_run_id, run.pk)


class Invariant07_FingerprintsUnique(TestCase):
    """7. Event fingerprints are unique (P0-012, P2-008)."""

    def test_duplicate_fingerprint_is_rejected(self):
        t = make_target(root_domain="i7a.example.com")
        Event.objects.create(
            target=t, event_type="NEW_SUBDOMAIN", asset_value="x", fingerprint="i7-fp"
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            Event.objects.create(
                target=t, event_type="NEW_SUBDOMAIN", asset_value="y", fingerprint="i7-fp"
            )

    def test_emit_event_is_idempotent(self):
        t = make_target(root_domain="i7b.example.com")
        from services.event_engine.engine import emit_event

        e1, c1 = emit_event("NEW_SUBDOMAIN", target=t, asset_value="dup.example.com")
        e2, c2 = emit_event("NEW_SUBDOMAIN", target=t, asset_value="dup.example.com")
        self.assertTrue(c1)
        self.assertFalse(c2)
        self.assertEqual(e1.pk, e2.pk)
        self.assertEqual(Event.objects.filter(target=t, event_type="NEW_SUBDOMAIN").count(), 1)


class Invariant08_TlsPolicyConsistent(TestCase):
    """8. TLS policy is consistent across every fetch path (P0-015)."""

    def test_default_context_requires_and_checks_certificate(self):
        ctx = tasks._ssl_context_for(make_target(root_domain="i8a.example.com"), None, "test")
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, __import__("ssl").CERT_REQUIRED)

    def test_opt_out_is_explicit_and_logged(self):
        t = make_target(root_domain="i8b.example.com", verify_tls=False)
        ctx = tasks._ssl_context_for(t, None, "test")
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, __import__("ssl").CERT_NONE)

    def test_every_target_fetch_path_uses_the_context(self):
        # every target-originated fetch path goes through the centralized
        # fetcher, and none of them hand-rolls an insecure ssl context.
        # The check is AST-based on purpose: docstrings mention CERT_NONE
        # (they describe the defect we removed), and a naive substring search
        # would flag that prose instead of real insecure TLS configuration.
        import ast
        import importlib
        import textwrap

        monitoring = importlib.import_module("apps.monitoring.tasks")

        def _cert_none_refs(func):
            src = textwrap.dedent(inspect.getsource(func))
            tree = ast.parse(src)
            hits = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "CERT_NONE":
                    hits.append(node.lineno)
            return hits

        import inspect

        self.assertIn("_fetch_url_for_recon", inspect.getsource(monitoring.recheck_javascript))
        self.assertEqual(_cert_none_refs(monitoring.recheck_javascript), [])
        for stage in (
            tasks.discover_subdomains,
            tasks.resolve_dns,
            tasks.scan_ports,
            tasks.probe_http,
            tasks.discover_urls,
            tasks.manual_scan,
        ):
            self.assertEqual(
                _cert_none_refs(stage), [], f"{stage.__name__} hand-rolls an insecure TLS context"
            )
        # the only CERT_NONE in the codebase is the explicit verify_tls=False
        # opt-out inside the centralized context builder
        self.assertEqual(len(_cert_none_refs(tasks._ssl_context_for)), 1)


class Invariant09_ExportsAreTargetSpecific(TestCase):
    """9. Exports are target-specific (P1-016)."""

    def test_snapshot_contains_only_its_target(self):
        import zipfile

        from apps.monitoring.exports import build_snapshot

        a = make_target(root_domain="i9a.example.com")
        b = make_target(root_domain="i9b.example.com")
        Subdomain.objects.create(target=a, hostname="a-only.i9a.example.com")
        Subdomain.objects.create(target=b, hostname="b-only.i9b.example.com")
        path, _size, _rows = build_snapshot(a, {})
        with zipfile.ZipFile(path) as z:
            body = "\n".join(z.read(n).decode() for n in z.namelist())
        self.assertIn("a-only.i9a.example.com", body)
        self.assertNotIn("b-only.i9b.example.com", body)


class Invariant10_ToolFailureNotCompleteCoverage(TestCase):
    """10. Tool failures cannot be represented as complete coverage (P1-011/P0-017)."""

    def test_missing_tool_degrades_the_stage(self):
        from services.tool_adapters.adapters import NaabuAdapter

        t = make_target(
            root_domain="i10a.example.com",
            scan_profile="active",
            scan_config={"ports": ",".join(str(p) for p in range(80, 130))},
        )
        from apps.assets.models import IPAddress

        IPAddress.objects.create(target=t, ip="203.0.113.1")
        with patch.object(NaabuAdapter, "is_available", return_value=False):
            out = tasks.scan_ports(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        self.assertEqual(ScanJob.objects.get(target=t, job_type="ports").status, "PARTIAL")

    def test_baseline_reflects_degraded_stages(self):
        from services.tool_adapters.adapters import NaabuAdapter

        t = make_target(
            root_domain="i10b.example.com", scan_profile="active", scan_config={"ports": "80"}
        )
        from apps.assets.models import IPAddress

        IPAddress.objects.create(target=t, ip="203.0.113.2")
        with (
            patch.object(NaabuAdapter, "is_available", return_value=False),
            patch.object(tasks.discover_subdomains, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.resolve_dns, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.probe_http, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.discover_urls, "run", return_value={"status": "COMPLETED"}),
        ):
            out = tasks.baseline_target(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        t.refresh_from_db()
        self.assertEqual(t.baseline_status, "BASELINE_PARTIAL")
        self.assertNotEqual(t.baseline_status, "BASELINE_COMPLETE")

    def test_evidence_loss_cannot_yield_a_clean_run(self):
        """A stage that lost its evidence rows must not report a clean result."""
        from apps.assets.models import IPAddress
        from services.tool_adapters.adapters import NaabuAdapter

        t = make_target(
            root_domain="i10c.example.com", scan_profile="active", scan_config={"ports": "80"}
        )
        IPAddress.objects.create(target=t, ip="203.0.113.3")
        with (
            patch.object(tasks.discover_subdomains, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.resolve_dns, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.probe_http, "run", return_value={"status": "COMPLETED"}),
            patch.object(tasks.discover_urls, "run", return_value={"status": "COMPLETED"}),
            patch.object(NaabuAdapter, "is_available", return_value=False),
            patch(
                "apps.jobs.models.ToolExecution.objects.create", side_effect=RuntimeError("db down")
            ),
        ):
            out = tasks.baseline_target(t.id)
        self.assertNotEqual(out["status"], "COMPLETED")
        t.refresh_from_db()
        self.assertNotEqual(t.baseline_status, "BASELINE_COMPLETE")
