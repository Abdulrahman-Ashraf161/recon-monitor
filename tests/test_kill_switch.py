"""P0-013: the pause button is a real kill switch, not a status label.

Covers the taskbook matrix:
  queued    - queued jobs pause and nothing new starts while paused;
  running   - RUNNING jobs detect the trip at the next cooperative check;
  multi     - a multi-stage baseline stops between stages and never claims
              completion;
  subprocess- the tool subprocess process group is terminated, including any
              grandchild it spawned;
  resume    - resume reactivates the target, re-queues PAUSED jobs and frees
              a fresh execution root (P1-001 interplay);
  child     - per-asset handlers / child-job creators gate on is_scannable.
"""

import os
import subprocess
import sys
import tempfile
import time
from unittest import mock

from django.test import TestCase

from apps.jobs import tasks
from apps.jobs.models import ScanJob, ScanRun
from apps.monitoring.models import Baseline
from apps.targets.models import Target
from services.tool_adapters.base import _run_tool_process

from .fixtures import make_scan_job, make_scan_run, make_target, make_world


class _FakeStage:
    """Stand-in for a Celery stage task with the same .name/.run shape."""

    def __init__(self, name, fn=None):
        self.name = f"apps.jobs.tasks.{name}"
        self.fn = fn or (lambda target_id, run_id: {"status": "COMPLETED"})

    def run(self, target_id, run_id):
        return self.fn(target_id, run_id)


class KillSwitchUnitTests(TestCase):
    """Gate + child-job creators must refuse work on a paused target."""

    def setUp(self):
        self.target = make_target()

    def test_paused_target_is_not_scannable_and_gate_fails(self):
        self.assertTrue(self.target.is_scannable)
        self.target.status = Target.STATUS_PAUSED
        self.target.save(update_fields=["status"])
        self.assertFalse(self.target.is_scannable)
        ok, reason = tasks._gate(self.target)
        self.assertFalse(ok)
        self.assertIn("not scannable", reason)

    def test_blocking_reason_reports_pause(self):
        self.target.status = Target.STATUS_PAUSED
        self.target.save(update_fields=["status"])
        self.assertIn("paused", self.target.blocking_reason())

    def test_cancel_reason_vocabulary_for_pause(self):
        self.target.status = Target.STATUS_PAUSED
        self.target.save(update_fields=["status"])
        self.assertEqual(tasks._cancel_reason(self.target), "TARGET_PAUSED")

    def test_asset_job_not_created_while_paused(self):
        self.target.status = Target.STATUS_PAUSED
        self.target.save(update_fields=["status"])
        job, msg = tasks._asset_job(self.target, "http", tool="httpx")
        self.assertIsNone(job)
        self.assertIn("not scannable", msg)
        self.assertEqual(ScanJob.objects.filter(target=self.target).count(), 0)

    def test_event_dependents_skip_paused_target_no_child_work(self):
        from django.utils import timezone

        from apps.events.models import Event

        self.target.status = Target.STATUS_PAUSED
        self.target.save(update_fields=["status"])
        event = Event.objects.create(
            event_type="NEW_SUBDOMAIN",
            target=self.target,
            asset_value=f"a.{self.target.root_domain}",
            fingerprint="fp-kill-switch-child",
            created_at=timezone.now(),
        )
        out = tasks.handle_event_dependents(event.pk)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertIn("not scannable", out["reason"])
        self.assertEqual(ScanJob.objects.filter(target=self.target).count(), 0)


class CooperativeCancellationTests(TestCase):
    """RUNNING jobs detect the trip at the next check and finalize correctly."""

    def test_running_job_detects_pause_at_next_check(self):
        target = make_target()
        run = make_scan_run(target, status="RUNNING")
        job = make_scan_job(target, status="RUNNING", scan_run=run)
        with tasks._cancellable(target, job=job, run=run) as check:
            target.status = Target.STATUS_PAUSED
            target.save(update_fields=["status"])
            with self.assertRaises(tasks._Cancelled) as cm:
                check()
        self.assertEqual(cm.exception.target_id, target.pk)

    def test_stop_if_cancelled_finalizes_job_and_run_cancelled(self):
        target = make_target()
        run = make_scan_run(target, status="RUNNING")
        job = make_scan_job(target, status="RUNNING", scan_run=run)
        target.status = Target.STATUS_PAUSED
        target.save(update_fields=["status"])
        exc = tasks._Cancelled(target.pk)
        out = tasks._stop_if_cancelled(exc, job, target)
        self.assertEqual(out, {"status": "CANCELLED", "reason": "TARGET_PAUSED"})
        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.STATUS_CANCELLED_KILL_SWITCH)
        self.assertEqual(job.stats, {"cancel_reason": "TARGET_PAUSED"})
        self.assertIn("target_paused", job.error)
        run.refresh_from_db()
        self.assertEqual(run.status, "CANCELLED")
        self.assertIsNotNone(run.cancel_requested_at)
        self.assertEqual(run.cancel_reason, "TARGET_PAUSED")

    def test_first_check_reads_db_so_no_prior_poll_is_needed(self):
        target = make_target()
        run = make_scan_run(target, status="RUNNING")
        job = make_scan_job(target, status="RUNNING", scan_run=run)
        with tasks._cancellable(target, job=job, run=run) as check:
            target.status = Target.STATUS_PAUSED
            target.save(update_fields=["status"])
            # The very first check() must raise immediately; the 5s poll
            # interval exists to save DB round-trips inside a loop, not to
            # delay the trip itself.
            with self.assertRaises(tasks._Cancelled):
                check()
        # Not finalized until the caller decides: _stop_if_cancelled owns that.
        job.refresh_from_db()
        run.refresh_from_db()
        self.assertEqual(job.status, "RUNNING")
        self.assertEqual(run.status, "RUNNING")


class MultiStageBaselineKillSwitchTests(TestCase):
    """A baseline that pauses after stage N must stop and never claim done."""

    STAGES = ("discover_subdomains", "resolve_dns", "scan_ports", "probe_http", "discover_urls")

    def _patch_stages(self, pause_after=None):
        """Stub all five chain stages; pause the target when `pause_after` runs."""
        from contextlib import ExitStack

        stack = ExitStack()
        for name in self.STAGES:

            def make_fn(name=name):
                def fn(target_id, run_id):
                    if name == pause_after:
                        t = Target.objects.get(pk=target_id)
                        t.status = Target.STATUS_PAUSED
                        t.save(update_fields=["status"])
                    return {"status": "COMPLETED"}

                return fn

            stack.enter_context(mock.patch.object(tasks, name, _FakeStage(name, make_fn())))
        return stack

    def test_mid_baseline_pause_stops_chain_and_does_not_complete(self):
        target = make_target(baseline_status="INITIAL_BASELINE")
        with self._patch_stages(pause_after="resolve_dns"):
            out = tasks.baseline_target(target.pk)
        self.assertEqual(out["status"], "CANCELLED")
        self.assertEqual(out["reason"], "TARGET_PAUSED")
        self.assertEqual(out["stopped_at"], "scan_ports")

        target.refresh_from_db()
        self.assertEqual(target.baseline_status, "INITIAL_BASELINE")
        self.assertEqual(Baseline.objects.get(target=target).status, "CANCELLED")
        run = ScanRun.objects.get(target=target, scan_type="DISCOVERY")
        self.assertEqual(run.status, "CANCELLED")

    def test_uninterrupted_baseline_still_completes(self):
        target = make_target(baseline_status="INITIAL_BASELINE")
        with self._patch_stages(pause_after=None):
            out = tasks.baseline_target(target.pk)
        self.assertEqual(out["status"], "COMPLETED")
        target.refresh_from_db()
        self.assertEqual(target.baseline_status, "BASELINE_COMPLETE")
        self.assertEqual(Baseline.objects.get(target=target).status, "COMPLETE")
        run = ScanRun.objects.get(target=target, scan_type="DISCOVERY")
        self.assertEqual(run.status, "COMPLETED")


class SubprocessGroupCancellationTests(TestCase):
    """The tool subprocess group is terminated, grandchild included."""

    def _spawn_self(self, code, *args, cancel_check=None):
        return _run_tool_process(
            [sys.executable, "-u", "-c", code, *args], timeout=60, cancel_check=cancel_check
        )

    def test_cancel_terminates_process_group_including_grandchild(self):
        # Grandchild: after 4s it would prove survival by writing the marker.
        grandchild = "import sys,time;" "time.sleep(4);" "open(sys.argv[1],'a').write('survived')"
        wrapper = (
            "import subprocess,sys,time;"
            "p=subprocess.Popen([sys.executable,'-c',"
            f'"{grandchild}",sys.argv[2]]);'
            "open(sys.argv[1],'w').write(str(p.pid));"
            "time.sleep(60)"
        )
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "grandchild.pid")
            marker = os.path.join(d, "marker.txt")
            calls = {"n": 0}

            def cancel_check():
                calls["n"] += 1
                if calls["n"] >= 2:
                    raise tasks._Cancelled(999)

            start = time.monotonic()
            with self.assertRaises(tasks._Cancelled):
                self._spawn_self(wrapper, pidfile, marker, cancel_check=cancel_check)
            self.assertLess(time.monotonic() - start, 10)

            with open(pidfile) as fh:
                gpid = int(fh.read().strip())
            deadline = time.monotonic() + 5
            survived = True
            while time.monotonic() < deadline:
                try:
                    os.kill(gpid, 0)
                except (ProcessLookupError, PermissionError):
                    survived = False
                    break
                time.sleep(0.1)
            self.assertFalse(survived, "grandchild survived the group kill")
            self.assertFalse(os.path.exists(marker))

    def test_timeout_terminates_process_group(self):
        with tempfile.TemporaryDirectory():
            start = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                _run_tool_process(
                    [sys.executable, "-u", "-c", "import time;time.sleep(30)"], timeout=1
                )
            self.assertLess(time.monotonic() - start, 10)

    def test_clean_run_collects_output_without_cancel(self):
        code, out, err = self._spawn_self("import sys;print('hello')")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "hello")
        self.assertEqual(err, "")


class PauseResumeViewTests(TestCase):
    """End-to-end through the pause/resume views (B0 kill switch front door)."""

    def setUp(self):
        world = make_world()
        self.operator = world["operator_a"]
        self.target = world["target_a"]
        self.client.force_login(self.operator)

    def _pause(self):
        resp = self.client.post(f"/targets/{self.target.pk}/pause/")
        self.assertRedirects(resp, f"/targets/{self.target.pk}/")
        self.target.refresh_from_db()
        return resp

    def test_pause_pauses_queued_and_trips_live_run(self):
        try:
            run = make_scan_run(self.target, status="RUNNING")
            queued = make_scan_job(self.target, status="QUEUED", scan_run=run)
            running = make_scan_job(self.target, status="RUNNING", scan_run=run)
            self._pause()
            self.assertEqual(self.target.status, Target.STATUS_PAUSED)
            queued.refresh_from_db()
            self.assertEqual(queued.status, "PAUSED")
            # RUNNING jobs are left for the cooperative kill switch, never
            # relabelled (they must finalize as CANCELLED with a real reason).
            running.refresh_from_db()
            self.assertEqual(running.status, "RUNNING")
            run.refresh_from_db()
            self.assertEqual(run.status, "RUNNING")  # still live: run has a live job
            self.assertIsNotNone(run.cancel_requested_at)
            self.assertEqual(run.cancel_reason, "TARGET_PAUSED")
        finally:
            self.client.post(f"/targets/{self.target.pk}/resume/")

    def test_pause_without_live_jobs_finalizes_run_now(self):
        run = make_scan_run(self.target, status="RUNNING")
        self._pause()
        run.refresh_from_db()
        # No RUNNING job remains to close the root from below -> close it now so
        # P1-001 never mistakes it for a live run.
        self.assertEqual(run.status, "CANCELLED")
        self.assertIsNotNone(run.cancel_requested_at)
        self.assertEqual(run.cancel_reason, "TARGET_PAUSED")

    def test_resume_reactivates_and_frees_a_fresh_execution_root(self):
        run = make_scan_run(self.target, status="RUNNING")
        paused_job = make_scan_job(self.target, status="PAUSED")
        self._pause()
        resp = self.client.post(f"/targets/{self.target.pk}/resume/")
        self.assertRedirects(resp, f"/targets/{self.target.pk}/")
        self.target.refresh_from_db()
        self.assertEqual(self.target.status, Target.STATUS_ACTIVE)
        self.assertTrue(self.target.is_scannable)
        paused_job.refresh_from_db()
        self.assertEqual(paused_job.status, "QUEUED")
        run.refresh_from_db()
        self.assertEqual(run.status, "CANCELLED")
        # P1-001 must not be blocked by the old cancelled run.
        fresh = tasks._get_or_create_run(self.target, scan_type="MONITORING", trigger="event")
        fresh.refresh_from_db()
        self.assertEqual(fresh.status, "RUNNING")
