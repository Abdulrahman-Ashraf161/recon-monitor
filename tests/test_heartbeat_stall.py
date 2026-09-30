"""P1-006: heartbeat-driven liveness and stall detection.

The heartbeat is the *primary* liveness signal; logs are secondary evidence.
A stale heartbeat means stalled, a fresh one means working, a failed heartbeat
write is surfaced distinctly, and a genuinely dead job is moved out of RUNNING
so it cannot hold an execution root open forever.
"""

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.events.models import Event
from apps.jobs.models import JobLog, ScanJob, ScanRun
from apps.monitoring.tasks import detect_stalled_jobs
from apps.targets.models import Target


def _target(name="hb.invalid"):
    return Target.objects.create(
        name=name, root_domain=name, authorization_status=Target.AUTH_AUTHORIZED
    )


def _running_job(target, age_seconds, heartbeat_age=None, stats=None):
    now = timezone.now()
    job = ScanJob.objects.create(
        target=target,
        job_type="ports",
        status=ScanJob.STATUS_RUNNING,
        started_at=now - timedelta(seconds=age_seconds),
        heartbeat_at=(
            now - timedelta(seconds=heartbeat_age)
            if heartbeat_age is not None
            else now - timedelta(seconds=age_seconds)
        ),
        stats=stats or {},
    )
    return job


@override_settings(JOB_STALL_SECONDS=1800, JOB_STALL_MARK_FAILED=True)
class StallDetectionTests(TestCase):
    def test_fresh_heartbeat_is_not_flagged(self):
        t = _target()
        _running_job(t, age_seconds=3600, heartbeat_age=5)
        out = detect_stalled_jobs()
        self.assertEqual(out["stalled"], 0)
        self.assertEqual(
            ScanJob.objects.get(status=ScanJob.STATUS_RUNNING).stats.get("stalled_flagged"), None
        )

    def test_stale_heartbeat_is_flagged_and_closed(self):
        t = _target()
        job = _running_job(t, age_seconds=7200, heartbeat_age=3600)
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", trigger="manual")
        job.scan_run = run
        job.save(update_fields=["scan_run"])
        out = detect_stalled_jobs()
        self.assertEqual(out["stalled"], 1)
        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.STATUS_FAILED)
        self.assertIn("stalled", job.error)
        self.assertTrue(job.stats["stalled_flagged"])
        self.assertEqual(job.stats["stalled_reason"], "heartbeat_expired")
        ev = Event.objects.filter(target=t, event_type="JOB_STALLED").first()
        self.assertIsNotNone(ev)
        self.assertEqual(ev.evidence["liveness_signal"], "heartbeat")
        run.refresh_from_db()
        self.assertIn(run.status, ("FAILED", "COMPLETED"))

    def test_recent_logs_do_not_rescue_a_stale_heartbeat(self):
        """Logs are secondary evidence: a chatty-but-wedged job is still stalled."""
        t = _target()
        job = _running_job(t, age_seconds=7200, heartbeat_age=3600)
        JobLog.objects.create(job=job, level="INFO", message="still working", stage="ports")
        out = detect_stalled_jobs()
        self.assertEqual(out["stalled"], 1)

    def test_heartbeat_is_the_deciding_signal(self):
        t = _target()
        _running_job(t, age_seconds=7200, heartbeat_age=3600)
        out = detect_stalled_jobs()
        self.assertEqual(out["stalled"], 1)
        self.assertEqual(out["stall_seconds"], 1800)

    def test_heartbeat_write_failure_is_reported_distinctly(self):
        t = _target()
        _running_job(
            t,
            age_seconds=7200,
            heartbeat_age=3600,
            stats={"last_heartbeat_error": "OperationalError"},
        )
        detect_stalled_jobs()
        job = ScanJob.objects.get(job_type="ports")
        self.assertEqual(job.stats["stalled_reason"], "heartbeat_write_failed")
        ev = Event.objects.get(event_type="JOB_STALLED")
        self.assertEqual(ev.evidence["heartbeat_write_error"], "OperationalError")

    def test_already_flagged_job_is_not_reported_twice(self):
        t = _target()
        _running_job(t, age_seconds=7200, heartbeat_age=3600)
        detect_stalled_jobs()
        second = detect_stalled_jobs()
        self.assertEqual(second["stalled"], 0)
        self.assertEqual(Event.objects.filter(event_type="JOB_STALLED").count(), 1)

    def test_flag_only_mode_leaves_status_untouched(self):
        t = _target()
        with override_settings(JOB_STALL_MARK_FAILED=False):
            out = detect_stalled_jobs()
        # no job was created by the sweep itself; create one explicitly
        job = _running_job(t, age_seconds=7200, heartbeat_age=3600)
        with override_settings(JOB_STALL_MARK_FAILED=False):
            out = detect_stalled_jobs()
        self.assertEqual(out["stalled"], 1)
        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.STATUS_RUNNING)
        self.assertTrue(job.stats["stalled_flagged"])

    def test_job_without_heartbeat_is_judged_from_start_time(self):
        t = _target()
        job = ScanJob.objects.create(
            target=t,
            job_type="dns",
            status=ScanJob.STATUS_RUNNING,
            started_at=timezone.now() - timedelta(seconds=7200),
            heartbeat_at=None,
        )
        out = detect_stalled_jobs()
        self.assertEqual(out["stalled"], 1)
        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.STATUS_FAILED)

    def test_terminal_jobs_are_never_flagged(self):
        t = _target()
        ScanJob.objects.create(
            target=t,
            job_type="dns",
            status=ScanJob.STATUS_COMPLETED,
            started_at=timezone.now() - timedelta(days=2),
            heartbeat_at=timezone.now() - timedelta(days=2),
        )
        out = detect_stalled_jobs()
        self.assertEqual(out["stalled"], 0)

    def test_long_running_job_that_keeps_beating_is_safe(self):
        """A long tool execution that refreshes its heartbeat is never flagged."""
        t = _target()
        job = _running_job(t, age_seconds=7200, heartbeat_age=7200)
        for _ in range(3):
            job.beat()
        out = detect_stalled_jobs()
        self.assertEqual(out["stalled"], 0)
        self.assertEqual(ScanJob.objects.get(pk=job.pk).status, ScanJob.STATUS_RUNNING)

    def test_beat_failure_does_not_kill_work(self):
        t = _target()
        job = _running_job(t, age_seconds=60, heartbeat_age=60)
        real_qs = ScanJob._base_manager.get_queryset()

        def _boom(*a, **kw):
            raise RuntimeError("db down")

        # Simulate the storage outage at the write itself; beat() must swallow
        # it (and record why) rather than abort the running work.
        with patch.object(type(real_qs), "update", _boom):
            job.beat()  # must not raise
        self.assertTrue(job.heartbeat_at)


class JsAnalysisHeartbeatTests(TestCase):
    def test_analyzer_heartbeat_checker_refreshes_liveness(self):
        from apps.assets.models import JavaScriptAsset
        from apps.jobs.models import JSAnalysisJob
        from services.correlation.jsanalysis import _heartbeat_checker

        t = _target("hbjs.invalid")
        js = JavaScriptAsset.objects.create(target=t, js_url="https://x.hbjs.invalid/a.js")
        job = JSAnalysisJob.objects.create(target=t, js=js, trigger="NEW_JS")
        real_qs = JSAnalysisJob._base_manager.get_queryset()
        seen = []
        with patch.object(type(real_qs), "update", lambda self, **kw: seen.append(kw) or 0):
            check = _heartbeat_checker(job, interval=0.0)
            check()
        self.assertTrue(seen, "heartbeat checker did not write a heartbeat")
        self.assertIn("heartbeat_at", seen[0])
