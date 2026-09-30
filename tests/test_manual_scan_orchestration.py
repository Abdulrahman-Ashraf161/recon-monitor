"""P2-006: manual scans run through the canonical ScanRun orchestration.

1. authorize the target, 2. verify scannable, 3. create/reuse the correct
ScanRun, 4. dispatch the canonical chain, 5. attach all jobs/artifacts,
6. expose accurate status.
"""

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.core.authorization import grant_membership
from apps.jobs import tasks
from apps.jobs.models import ScanJob, ScanRun
from apps.targets.models import Target, TargetMembership

from .fixtures import make_user

STAGES = ("discover_subdomains", "resolve_dns", "scan_ports", "probe_http", "discover_urls")


def _target(baseline="BASELINE_COMPLETE", **kw):
    return Target.objects.create(
        name="ms.invalid",
        root_domain="ms.invalid",
        authorization_status=Target.AUTH_AUTHORIZED,
        baseline_status=baseline,
        **kw,
    )


class ManualScanTaskTests(TestCase):
    _calls = []

    def _patch_stages(self, outcomes=None):
        """Stub the five chain stages, recording the run id each one receives."""
        from contextlib import ExitStack

        stack = ExitStack()
        outcomes = outcomes or {}
        type(self)._calls = []
        for name in STAGES:
            result = outcomes.get(name, {"status": "COMPLETED", "new": 1})

            def _make(result=result, name=name):
                def _run(target_id, run_id):
                    type(self)._calls.append((name, run_id))
                    return result

                return _run

            stack.enter_context(patch.object(getattr(tasks, name), "run", side_effect=_make()))
        return stack

    def test_all_stages_join_one_execution_root(self):
        t = _target()
        with self._patch_stages():
            out = tasks.manual_scan(t.id, requested_by="7")
        self.assertEqual(out["status"], "COMPLETED")
        self.assertEqual(out["mode"], "scan")
        runs = ScanRun.all_objects.filter(target=t, scan_type="DISCOVERY")
        self.assertEqual(runs.count(), 1, "manual scan opened more than one execution root")
        run = runs.get()
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(run.requested_by, "7")
        # every stage received that run id (stages attach their own job/rows;
        # they are stubbed here, so the run id hand-off is what is asserted)
        handed_off = {run_id for _name, run_id in self._calls}
        self.assertEqual(handed_off, {run.pk}, "a stage did not receive the canonical run id")

    def test_incomplete_baseline_routes_to_the_baseline_chain(self):
        t = _target(baseline="INITIAL_BASELINE")
        with patch.object(
            tasks, "baseline_target", return_value={"status": "COMPLETED", "run_id": 1, "stats": {}}
        ) as base:
            out = tasks.manual_scan(t.id, requested_by="7")
        self.assertEqual(out["mode"], "baseline")
        self.assertTrue(base.called)
        self.assertEqual(out["status"], "COMPLETED")

    def test_unscannable_target_is_refused_before_dispatch(self):
        t = _target(status=Target.STATUS_PAUSED)
        with self._patch_stages():
            out = tasks.manual_scan(t.id)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertIn("not scannable", out["reason"])
        self.assertEqual(ScanJob.all_objects.filter(target=t).count(), 0)

    def test_expired_authorization_is_refused(self):
        t = _target(authorization_expires_at=timezone.now() - timedelta(days=1))
        with self._patch_stages():
            out = tasks.manual_scan(t.id)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertEqual(ScanJob.all_objects.filter(target=t).count(), 0)

    def test_stage_failure_produces_a_failed_run_with_accurate_status(self):
        t = _target()
        outcomes = {"probe_http": {"status": "FAILED", "error": "boom"}}
        with self._patch_stages(outcomes):
            out = tasks.manual_scan(t.id)
        # a required stage that FAILED makes the whole run FAILED, with the
        # failing stage named on the execution root
        self.assertEqual(out["status"], "FAILED")
        run = ScanRun.all_objects.get(target=t, scan_type="DISCOVERY")
        self.assertEqual(run.status, "FAILED")

    def test_partial_stage_reports_partial_not_completed(self):
        t = _target()
        outcomes = {"scan_ports": {"status": "PARTIAL"}}
        with self._patch_stages(outcomes):
            out = tasks.manual_scan(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        self.assertEqual(ScanRun.all_objects.get(target=t, scan_type="DISCOVERY").status, "PARTIAL")

    def test_coverage_summary_is_attached_to_the_run(self):
        t = _target()
        with self._patch_stages():
            tasks.manual_scan(t.id)
        run = ScanRun.all_objects.get(target=t, scan_type="DISCOVERY")
        self.assertIn("discover_subdomains", run.coverage_summary)
        self.assertIn("probe_http", run.coverage_summary)

    def test_pause_mid_scan_stops_the_chain(self):
        t = _target()
        from contextlib import ExitStack

        stack = ExitStack()
        executed = []
        for name in STAGES:
            if name == "scan_ports":

                def _pausing(target_id, run_id, _name=name):
                    executed.append(_name)
                    t.refresh_from_db()
                    t.status = Target.STATUS_PAUSED
                    t.save(update_fields=["status"])
                    return {"status": "COMPLETED"}

                stack.enter_context(patch.object(getattr(tasks, name), "run", side_effect=_pausing))
            else:

                def _plain(target_id, run_id, _name=name):
                    executed.append(_name)
                    return {"status": "COMPLETED"}

                stack.enter_context(patch.object(getattr(tasks, name), "run", side_effect=_plain))
        with stack:
            out = tasks.manual_scan(t.id)
        self.assertEqual(out["status"], "CANCELLED")
        # the target is re-checked before each stage, so the pause raised during
        # scan_ports is honoured before probe_http starts
        self.assertEqual(out["stopped_at"], "probe_http")
        self.assertNotIn("probe_http", executed)
        self.assertNotIn("discover_urls", executed)
        run = ScanRun.all_objects.get(target=t, scan_type="DISCOVERY")
        self.assertEqual(run.status, "CANCELLED")

    def test_evidence_loss_downgrades_the_run(self):

        t = _target()
        with (
            self._patch_stages(),
            patch(
                "apps.jobs.tasks._evidence_failures",
                return_value=[{"kind": "tool_execution", "detail": "db down"}],
            ),
        ):
            out = tasks.manual_scan(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        self.assertEqual(ScanRun.all_objects.get(target=t, scan_type="DISCOVERY").status, "PARTIAL")


class ManualScanViewTests(TestCase):
    def setUp(self):
        self.op = make_user(username="ms-op", role="OPERATOR")
        self.other = make_user(username="ms-other", role="OPERATOR")
        self.t = _target()
        grant_membership(self.op, self.t, TargetMembership.ROLE_OPERATOR)
        self.client.force_login(self.op)

    def test_scan_dispatches_the_orchestrator(self):
        with patch("apps.jobs.tasks.manual_scan.delay") as delay:
            r = self.client.post(reverse("target-scan", args=[self.t.id]))
        self.assertEqual(r.status_code, 302)
        self.assertTrue(delay.called, "manual scan did not go through manual_scan")
        args, _kwargs = delay.call_args
        self.assertEqual(args[0], self.t.id)
        self.assertIn("run=", r["Location"])

    def test_scan_requires_operate_capability_on_the_target(self):
        self.client.force_login(self.other)  # operator, but not a member here
        with patch("apps.jobs.tasks.manual_scan.delay") as delay:
            r = self.client.post(reverse("target-scan", args=[self.t.id]))
        self.assertEqual(r.status_code, 403)
        self.assertFalse(delay.called)

    def test_scan_refused_for_paused_target(self):
        self.t.status = Target.STATUS_PAUSED
        self.t.save(update_fields=["status"])
        with patch("apps.jobs.tasks.manual_scan.delay") as delay:
            r = self.client.post(reverse("target-scan", args=[self.t.id]))
        self.assertEqual(r.status_code, 403)
        self.assertFalse(delay.called)

    def test_run_detail_requires_membership(self):
        run = ScanRun.all_objects.create(target=self.t, scan_type="DISCOVERY", status="RUNNING")
        self.assertEqual(
            self.client.get(reverse("scan-run-detail", args=[run.pk])).status_code, 200
        )
        self.client.force_login(self.other)
        self.assertEqual(
            self.client.get(reverse("scan-run-detail", args=[run.pk])).status_code, 403
        )
