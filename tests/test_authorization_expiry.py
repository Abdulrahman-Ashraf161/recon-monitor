"""P0-014: authorization expiry stops execution like a pause does.

Taskbook matrix: expiry while queued, running, and between stages. Same root
cause chain as P0-013 (is_scannable -> _cancellable -> _stop_if_cancelled), but
triggered by the scheduler flipping AUTHORIZED -> AUTH_EXPIRED, not by an
operator clicking pause. The distinct assertions are:

  - the periodic task pauses queued jobs, trips live runs and records the
    AUTHORIZATION_EXPIRED lifecycle event exactly once;
  - a RUNNING job detects the trip at its next check and finalizes with reason
    AUTH_EXPIRED (not TARGET_PAUSED);
  - a multi-stage baseline stops between stages and never claims completion;
  - steams of child work are refused once the expiry lands.
"""

from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from apps.events.models import Event
from apps.jobs import tasks
from apps.jobs.models import ScanJob, ScanRun
from apps.monitoring.models import Baseline
from apps.monitoring.tasks import check_authorization_expiry
from apps.targets.models import Target

from .fixtures import make_scan_job, make_scan_run, make_target


class _FakeStage:
    """Stand-in for a Celery stage task with the same .name/.run shape."""

    def __init__(self, name, fn=None):
        self.name = f"apps.jobs.tasks.{name}"
        self.fn = fn or (lambda target_id, run_id: {"status": "COMPLETED"})

    def run(self, target_id, run_id):
        return self.fn(target_id, run_id)


def expire(target):
    """Flip authorization to expired, exactly as the scheduler task does."""
    target.authorization_status = Target.AUTH_EXPIRED
    target.status = Target.STATUS_PAUSED
    target.authorization_expires_at = timezone.now() - timedelta(seconds=1)
    target.save(update_fields=["authorization_status", "status", "authorization_expires_at"])
    target.refresh_from_db()
    return target


class ExpirySchedulerTests(TestCase):
    """check_authorization_expiry performs the halt + lifecycle event once."""

    def test_expiry_while_queued_pauses_jobs_and_finalizes_idle_run(self):
        from .fixtures import make_world

        world = make_world()
        target = world["target_a"]
        target.authorization_expires_at = timezone.now() - timedelta(seconds=1)
        target.save(update_fields=["authorization_expires_at"])
        run = make_scan_run(target, status="RUNNING")
        queued = make_scan_job(target, status="QUEUED", scan_run=run)

        out = check_authorization_expiry()
        self.assertEqual(out["paused"], 1)

        target.refresh_from_db()
        self.assertEqual(target.authorization_status, Target.AUTH_EXPIRED)
        self.assertEqual(target.status, Target.STATUS_PAUSED)
        self.assertFalse(target.is_scannable)

        queued.refresh_from_db()
        self.assertEqual(queued.status, "PAUSED")
        run.refresh_from_db()
        self.assertIsNotNone(run.cancel_requested_at)
        self.assertEqual(run.cancel_reason, "AUTH_EXPIRED")
        self.assertEqual(run.status, "CANCELLED")  # no live job left -> closed now

        event = Event.objects.get(target=target, event_type="AUTHORIZATION_EXPIRED")
        self.assertEqual(event.severity, "HIGH")
        self.assertIn("expired_at", event.evidence)

    def test_expiry_event_is_emitted_only_once(self):
        from .fixtures import make_world

        world = make_world()
        target = world["target_a"]
        target.authorization_expires_at = timezone.now() - timedelta(seconds=1)
        target.save(update_fields=["authorization_expires_at"])

        check_authorization_expiry()
        check_authorization_expiry()
        check_authorization_expiry()

        self.assertEqual(
            Event.objects.filter(target=target, event_type="AUTHORIZATION_EXPIRED").count(), 1
        )
        target.refresh_from_db()
        self.assertEqual(target.authorization_status, Target.AUTH_EXPIRED)

    def test_expiry_while_running_trips_run_but_leaves_live_job_to_worker(self):
        from .fixtures import make_world

        world = make_world()
        target = world["target_a"]
        target.authorization_expires_at = timezone.now() - timedelta(seconds=1)
        target.save(update_fields=["authorization_expires_at"])
        run = make_scan_run(target, status="RUNNING")
        running = make_scan_job(target, status="RUNNING", scan_run=run)

        check_authorization_expiry()
        target.refresh_from_db()

        # The run is tripped but stays RUNNING while a live job remains; the
        # worker's cooperative check owns the final state.
        run.refresh_from_db()
        self.assertEqual(run.status, "RUNNING")
        self.assertIsNotNone(run.cancel_requested_at)
        self.assertEqual(run.cancel_reason, "AUTH_EXPIRED")
        running.refresh_from_db()
        self.assertEqual(running.status, "RUNNING")

        # The very next cooperative check raises and finalizes with AUTH_EXPIRED.
        with (
            tasks._cancellable(target, job=running, run=run) as check,
            self.assertRaises(tasks._Cancelled),
        ):
            check()
        out = tasks._stop_if_cancelled(tasks._Cancelled(target.pk), running, target)
        self.assertEqual(out, {"status": "CANCELLED", "reason": "AUTH_EXPIRED"})
        running.refresh_from_db()
        self.assertEqual(running.status, ScanJob.STATUS_CANCELLED_KILL_SWITCH)
        self.assertEqual(running.stats, {"cancel_reason": "AUTH_EXPIRED"})
        run.refresh_from_db()
        self.assertEqual(run.status, "CANCELLED")


class ExpiryBetweenStagesTests(TestCase):
    """A baseline whose authorization lapses mid-chain stops and never completes."""

    STAGES = ("discover_subdomains", "resolve_dns", "scan_ports", "probe_http", "discover_urls")

    def _patch_stages(self, expire_after=None):
        from contextlib import ExitStack

        stack = ExitStack()
        for name in self.STAGES:

            def make_fn(name=name):
                def fn(target_id, run_id):
                    if name == expire_after:
                        expire(Target.objects.get(pk=target_id))
                    return {"status": "COMPLETED"}

                return fn

            stack.enter_context(mock.patch.object(tasks, name, _FakeStage(name, make_fn())))
        return stack

    def test_expiry_after_dns_stops_chain_with_expiry_reason(self):
        target = make_target(
            baseline_status="INITIAL_BASELINE",
            authorization_expires_at=timezone.now() + timedelta(days=7),
        )
        with self._patch_stages(expire_after="resolve_dns"):
            out = tasks.baseline_target(target.pk)
        self.assertEqual(out["status"], "CANCELLED")
        self.assertEqual(out["reason"], "AUTH_EXPIRED")
        self.assertEqual(out["stopped_at"], "scan_ports")

        target.refresh_from_db()
        self.assertEqual(target.baseline_status, "INITIAL_BASELINE")
        self.assertEqual(Baseline.objects.get(target=target).status, "CANCELLED")
        run = ScanRun.objects.get(target=target, scan_type="DISCOVERY")
        self.assertEqual(run.status, "CANCELLED")
        self.assertEqual(run.cancel_reason, "AUTH_EXPIRED")

    def test_expiry_does_not_block_a_future_run_on_refresh(self):
        # After re-authorization (AUTHORIZED + future window) a fresh execution
        # root must be creatable — the expired run is terminal, not live.
        target = make_target(authorization_expires_at=timezone.now() - timedelta(seconds=1))
        expire(target)
        run = make_scan_run(target, status="RUNNING")
        tasks._halt_work(target, "AUTH_EXPIRED")
        run.refresh_from_db()
        self.assertEqual(run.status, "CANCELLED")

        target.authorization_status = Target.AUTH_AUTHORIZED
        target.status = Target.STATUS_ACTIVE
        target.authorization_expires_at = timezone.now() + timedelta(days=30)
        target.save(update_fields=["authorization_status", "status", "authorization_expires_at"])
        target.refresh_from_db()
        self.assertTrue(target.is_scannable)
        fresh = tasks._get_or_create_run(target, scan_type="MONITORING", trigger="event")
        fresh.refresh_from_db()
        self.assertEqual(fresh.status, "RUNNING")


class ExpiryChildWorkTests(TestCase):
    """No child work is launched for an expired target (queued fan-out too)."""

    def test_asset_job_and_event_dependents_refuse_expired_target(self):
        target = make_target()
        expire(target)
        job, msg = tasks._asset_job(target, "http", tool="httpx")
        self.assertIsNone(job)
        self.assertIn("not scannable", msg)

        from django.utils import timezone as tz

        from apps.events.models import Event

        event = Event.objects.create(
            event_type="NEW_SUBDOMAIN",
            target=target,
            asset_value=f"a.{target.root_domain}",
            fingerprint="fp-expiry-child",
            created_at=tz.now(),
        )
        out = tasks.handle_event_dependents(event.pk)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertIn("not scannable", out["reason"])
        self.assertEqual(ScanJob.objects.filter(target=target).count(), 0)

    def test_cancel_reason_reports_expiry_before_paused_status(self):
        # The scheduler pauses expired targets; the reason trail must say
        # AUTH_EXPIRED, not TARGET_PAUSED.
        target = make_target()
        expire(target)
        self.assertEqual(tasks._cancel_reason(target), "AUTH_EXPIRED")
        # A plain pause with a healthy window still reports TARGET_PAUSED.
        target2 = make_target(authorization_expires_at=timezone.now() + timedelta(days=7))
        target2.status = Target.STATUS_PAUSED
        target2.save(update_fields=["status"])
        self.assertEqual(tasks._cancel_reason(target2), "TARGET_PAUSED")
