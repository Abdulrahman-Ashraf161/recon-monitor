"""P1-010: an asset is removed only when a complete successful scan proves absence.

The four states are distinguished:
    OBSERVED / NOT_OBSERVED_DURING_SUCCESSFUL_SCAN / SCAN_PARTIAL / SCAN_FAILED

A partial scan, a failed scan, a cancelled (timeout/kill-switch) scan and a
scan with reduced port coverage must never manufacture a removal.
"""

from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.assets.models import Port, Subdomain
from apps.events.models import Event
from apps.jobs.models import ScanJob, ScanRun
from apps.jobs.tasks import (
    NOT_OBSERVED_DURING_SUCCESSFUL_SCAN,
    OBSERVED,
    SCAN_FAILED,
    SCAN_PARTIAL,
    reconcile_target,
)
from apps.targets.models import Target


def _target(name="rec.invalid", grace=14):
    t = Target.objects.create(
        name=name,
        root_domain=name,
        authorization_status=Target.AUTH_AUTHORIZED,
        baseline_status="BASELINE_COMPLETE",
        reconciliation_grace_days=grace,
    )
    ScanRun.objects.create(target=t, scan_type="DISCOVERY", trigger="baseline", status="COMPLETED")
    return t


def _stale_subdomain(target, hostname):
    sub = Subdomain.objects.create(target=target, hostname=hostname, is_active=True, state="ACTIVE")
    _age(sub, days=90)
    return sub


def _age(obj, days=90):
    """Force ``last_seen`` into the past (the field is auto_now)."""
    obj.__class__.all_objects.filter(pk=obj.pk).update(
        last_seen=timezone.now() - timedelta(days=days)
    )
    return obj


def _age_all(model, target, count, days=90):
    model.all_objects.filter(target=target).update(last_seen=timezone.now() - timedelta(days=days))
    return count


def _stage(target, job_type, status, age_minutes=1):
    return ScanJob.objects.create(
        target=target,
        job_type=job_type,
        status=status,
        tool="test",
        started_at=timezone.now() - timedelta(minutes=age_minutes),
    )


def _all_stages(target, status):
    for job_type in ("subdomain_enum", "dns", "ports", "http", "urls", "js"):
        _stage(target, job_type, status)


class RemovalRequiresProofTests(TestCase):
    def test_complete_successful_scan_removes_and_labels_the_state(self):
        t = _target()
        _all_stages(t, ScanJob.STATUS_COMPLETED)
        sub = _stale_subdomain(t, "gone.rec.invalid")
        out = reconcile_target(t.id)
        self.assertEqual(out["marked_inactive"], 1)
        self.assertEqual(out["withheld"], 0)
        sub.refresh_from_db()
        self.assertFalse(sub.is_active)
        self.assertEqual(sub.state, "REMOVED")
        ev = Event.objects.get(target=t, event_type="SUBDOMAIN_REMOVED")
        self.assertEqual(ev.evidence["absence"], NOT_OBSERVED_DURING_SUCCESSFUL_SCAN)
        self.assertEqual(ev.evidence["scan_state"], OBSERVED)
        self.assertEqual(out["scan_states"]["SUBDOMAIN"], OBSERVED)

    def test_partial_scan_never_removes(self):
        t = _target()
        _all_stages(t, ScanJob.STATUS_PARTIAL)
        sub = _stale_subdomain(t, "alive.rec.invalid")
        out = reconcile_target(t.id)
        self.assertEqual(out["marked_inactive"], 0)
        self.assertEqual(out["withheld"], 1)
        self.assertEqual(out["withheld_by_type"], {"SUBDOMAIN": 1})
        self.assertEqual(out["scan_states"]["SUBDOMAIN"], SCAN_PARTIAL)
        sub.refresh_from_db()
        self.assertTrue(sub.is_active)
        self.assertEqual(Event.objects.filter(event_type="SUBDOMAIN_REMOVED").count(), 0)

    def test_failed_scan_never_removes(self):
        t = _target()
        _all_stages(t, ScanJob.STATUS_FAILED)
        sub = _stale_subdomain(t, "alive.rec.invalid")
        out = reconcile_target(t.id)
        self.assertEqual(out["marked_inactive"], 0)
        self.assertEqual(out["scan_states"]["SUBDOMAIN"], SCAN_FAILED)
        sub.refresh_from_db()
        self.assertTrue(sub.is_active)

    def test_timeout_or_cancellation_never_removes(self):
        t = _target()
        _all_stages(t, ScanJob.STATUS_CANCELLED)
        sub = _stale_subdomain(t, "alive.rec.invalid")
        out = reconcile_target(t.id)
        self.assertEqual(out["marked_inactive"], 0)
        self.assertEqual(out["scan_states"]["SUBDOMAIN"], SCAN_PARTIAL)
        sub.refresh_from_db()
        self.assertTrue(sub.is_active)

    def test_reduced_port_coverage_blocks_only_port_removals(self):
        t = _target()
        _all_stages(t, ScanJob.STATUS_COMPLETED)
        # naabu missing -> the ports stage degraded (P1-011/P1-012)
        _stage(t, "ports", ScanJob.STATUS_PARTIAL)
        port = _age(
            Port.objects.create(target=t, ip="203.0.113.5", port=80, protocol="tcp", state="open")
        )
        sub = _stale_subdomain(t, "gone.rec.invalid")
        out = reconcile_target(t.id)
        self.assertEqual(out["scan_states"]["PORT"], SCAN_PARTIAL)
        self.assertEqual(out["scan_states"]["SUBDOMAIN"], OBSERVED)
        self.assertEqual(out["marked_inactive"], 1)  # the subdomain only
        self.assertEqual(out["withheld_by_type"], {"PORT": 1})
        port.refresh_from_db()
        self.assertEqual(port.state, "open")  # not closed on thin evidence
        sub.refresh_from_db()
        self.assertFalse(sub.is_active)

    def test_never_run_stage_proves_nothing(self):
        t = _target()
        _all_stages(t, ScanJob.STATUS_COMPLETED)
        ScanJob.all_objects.filter(target=t, job_type="ports").delete()
        port = _age(
            Port.objects.create(target=t, ip="203.0.113.6", port=443, protocol="tcp", state="open")
        )
        out = reconcile_target(t.id)
        self.assertEqual(out["scan_states"]["PORT"], SCAN_PARTIAL)
        port.refresh_from_db()
        self.assertEqual(port.state, "open")

    def test_profile_skipped_stage_proves_nothing(self):
        """A stage skipped by profile was never a coverage promise."""
        t = _target()
        _all_stages(t, ScanJob.STATUS_COMPLETED)
        _stage(t, "ports", ScanJob.STATUS_SKIPPED)
        port = _age(
            Port.objects.create(target=t, ip="203.0.113.7", port=8080, protocol="tcp", state="open")
        )
        out = reconcile_target(t.id)
        self.assertEqual(out["scan_states"]["PORT"], SCAN_PARTIAL)
        port.refresh_from_db()
        self.assertEqual(port.state, "open")

    def test_withheld_assets_are_reported_not_silent(self):
        t = _target()
        _all_stages(t, ScanJob.STATUS_PARTIAL)
        for i in range(5):
            _stale_subdomain(t, f"g{i}.rec.invalid")
        out = reconcile_target(t.id)
        self.assertEqual(out["withheld"], 5)
        job = ScanJob.objects.get(target=t, job_type="reconcile")
        self.assertEqual(job.stats["withheld"], 5)
        self.assertEqual(job.stats["withheld_by_type"], {"SUBDOMAIN": 5})


class ReconcileBatchingTests(TestCase):
    @override_settings(RECONCILE_BATCH_SIZE=10)
    def test_more_than_one_page_of_stale_assets_is_fully_reconciled(self):
        t = _target()
        _all_stages(t, ScanJob.STATUS_COMPLETED)
        total = 45  # above the old [:500]/[:200] style truncation regime
        Subdomain.objects.bulk_create(
            [
                Subdomain(target=t, hostname=f"g{i}.rec.invalid", is_active=True, state="ACTIVE")
                for i in range(total)
            ]
        )
        _age_all(Subdomain, t, total)
        out = reconcile_target(t.id)
        self.assertEqual(out["marked_inactive"], total)
        self.assertEqual(Subdomain.objects.filter(target=t, is_active=True).count(), 0)
        self.assertEqual(
            Event.objects.filter(target=t, event_type="SUBDOMAIN_REMOVED").count(), total
        )

    def test_grace_period_still_protects_recent_assets(self):
        t = _target(grace=14)
        _all_stages(t, ScanJob.STATUS_COMPLETED)
        recent = Subdomain.objects.create(
            target=t, hostname="new.rec.invalid", is_active=True, state="ACTIVE"
        )
        out = reconcile_target(t.id)
        self.assertEqual(out["marked_inactive"], 0)
        self.assertTrue(Subdomain.objects.get(pk=recent.pk).is_active)
