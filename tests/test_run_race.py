"""P1-001 — race-safe ScanRun creation.

The taskbook requires: "Audit `_get_or_create_run()` in `apps/jobs/tasks.py`.
Use a transaction, lock, unique constraint, or equivalent atomic strategy so
concurrent workers cannot accidentally create duplicate active runs for the
same logical operation. Add concurrency tests."

The guarantee is a conditional unique index — at most one *live* run per
``(target, scan_type)`` — combined with insert-and-catch in the helper. These
tests cover both halves: the database constraint, and the helper's behaviour
when N workers race for the same logical operation.
"""

import threading
import time

from django.db import IntegrityError, OperationalError, connections, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.jobs.models import ScanRun
from apps.jobs.tasks import _get_or_create_run
from apps.targets.models import Target


class LiveRunConstraintTests(TestCase):
    """The database-level guarantee, independent of the helper."""

    def setUp(self):
        now = timezone.now()
        self.target = Target.objects.create(root_domain="uniq.test", created_at=now, updated_at=now)

    def test_second_live_run_for_same_target_and_type_is_rejected(self):
        ScanRun.objects.create(target=self.target, scan_type="MONITORING", status="RUNNING")
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanRun.objects.create(target=self.target, scan_type="MONITORING", status="RUNNING")

    def test_pending_also_counts_as_live(self):
        ScanRun.objects.create(target=self.target, scan_type="MONITORING", status="PENDING")
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanRun.objects.create(target=self.target, scan_type="MONITORING", status="RUNNING")

    def test_different_scan_type_may_run_concurrently(self):
        ScanRun.objects.create(target=self.target, scan_type="MONITORING", status="RUNNING")
        ScanRun.objects.create(target=self.target, scan_type="BASELINE", status="RUNNING")
        self.assertEqual(
            ScanRun.objects.filter(target=self.target, status__in=ScanRun.LIVE_STATUSES).count(), 2
        )

    def test_different_target_may_run_concurrently(self):
        other = Target.objects.create(
            root_domain="uniq2.test", created_at=timezone.now(), updated_at=timezone.now()
        )
        ScanRun.objects.create(target=self.target, scan_type="MONITORING", status="RUNNING")
        ScanRun.objects.create(target=other, scan_type="MONITORING", status="RUNNING")
        self.assertEqual(
            ScanRun.objects.filter(
                scan_type="MONITORING", status__in=ScanRun.LIVE_STATUSES
            ).count(),
            2,
        )

    def test_terminal_runs_are_unconstrained_so_history_accumulates(self):
        """The constraint must not stop a target accumulating run history."""
        for status in ("COMPLETED", "FAILED", "COMPLETED", "PARTIAL"):
            ScanRun.objects.create(target=self.target, scan_type="MONITORING", status=status)
        self.assertEqual(
            ScanRun.objects.filter(target=self.target, scan_type="MONITORING").count(), 4
        )

    def test_a_new_run_is_allowed_once_the_previous_one_finishes(self):
        first = ScanRun.objects.create(target=self.target, scan_type="MONITORING", status="RUNNING")
        first.status = "COMPLETED"
        first.finished_at = timezone.now()
        first.save()
        second = ScanRun.objects.create(
            target=self.target, scan_type="MONITORING", status="RUNNING"
        )
        self.assertNotEqual(first.pk, second.pk)


class GetOrCreateRunTests(TestCase):
    """The helper's contract, single-threaded."""

    def setUp(self):
        now = timezone.now()
        self.target = Target.objects.create(
            root_domain="helper.test", created_at=now, updated_at=now
        )

    def test_first_call_creates_a_run(self):
        run = _get_or_create_run(self.target, scan_type="MONITORING")
        self.assertEqual(run.status, "RUNNING")
        self.assertEqual(run.target_id, self.target.pk)

    def test_second_call_reuses_the_live_run(self):
        first = _get_or_create_run(self.target, scan_type="MONITORING")
        second = _get_or_create_run(self.target, scan_type="MONITORING")
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(ScanRun.objects.filter(target=self.target).count(), 1)

    def test_reentrancy_rejoins_a_pending_run(self):
        """A re-entrant stage must adopt the live run, not orphan a new one."""
        pending = ScanRun.objects.create(
            target=self.target, scan_type="MONITORING", status="PENDING"
        )
        run = _get_or_create_run(self.target, scan_type="MONITORING")
        self.assertEqual(run.pk, pending.pk)

    def test_a_finished_run_does_not_block_a_new_one(self):
        done = ScanRun.objects.create(
            target=self.target,
            scan_type="MONITORING",
            status="COMPLETED",
            finished_at=timezone.now(),
        )
        run = _get_or_create_run(self.target, scan_type="MONITORING")
        self.assertNotEqual(run.pk, done.pk)

    def test_explicit_scan_run_id_is_honoured(self):
        existing = ScanRun.objects.create(
            target=self.target, scan_type="MONITORING", status="RUNNING"
        )
        run = _get_or_create_run(self.target, scan_type="MONITORING", scan_run_id=existing.pk)
        self.assertEqual(run.pk, existing.pk)

    def test_explicit_scan_run_id_cannot_be_borrowed_across_targets(self):
        from apps.core.consistency import ExecutionConsistencyError

        other = Target.objects.create(
            root_domain="other.test", created_at=timezone.now(), updated_at=timezone.now()
        )
        foreign = ScanRun.objects.create(target=other, scan_type="MONITORING", status="RUNNING")
        with self.assertRaises(ExecutionConsistencyError):
            _get_or_create_run(self.target, scan_type="MONITORING", scan_run_id=foreign.pk)

    def test_missing_explicit_scan_run_id_is_rejected(self):
        from apps.core.consistency import ExecutionConsistencyError

        with self.assertRaises(ExecutionConsistencyError):
            _get_or_create_run(self.target, scan_type="MONITORING", scan_run_id=999999)


class ConcurrentRunCreationTests(TransactionTestCase):
    """N workers racing to start the same logical operation -> one live run."""

    reset_sequences = True
    WORKERS = 8

    def setUp(self):
        super().setUp()
        self.target = Target.objects.create(
            root_domain="race-run.test", created_at=timezone.now(), updated_at=timezone.now()
        )

    @staticmethod
    def _tune_sqlite_connection():
        if connections["default"].vendor != "sqlite":
            return
        with connections["default"].cursor() as cursor:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA busy_timeout=20000;")

    def _call_with_sqlite_retry(self, scan_type="MONITORING"):
        """Retry only the SQLite single-writer artefact; never the race itself."""
        deadline = time.monotonic() + 30
        last = None
        while time.monotonic() < deadline:
            try:
                return _get_or_create_run(self.target, scan_type=scan_type)
            except OperationalError as exc:
                message = str(exc).lower()
                if "locked" not in message and "busy" not in message:
                    raise
                last = exc
                time.sleep(0.05)
        raise last

    def test_concurrent_workers_produce_exactly_one_live_run(self):
        results, errors = [], []
        barrier = threading.Barrier(self.WORKERS)

        def worker():
            try:
                self._tune_sqlite_connection()
                barrier.wait(timeout=30)
                results.append(self._call_with_sqlite_retry().pk)
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                connections.close_all()

        threads = [threading.Thread(target=worker) for _ in range(self.WORKERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=90)
            self.assertFalse(t.is_alive(), "worker thread deadlocked")

        self.assertEqual(errors, [], f"_get_or_create_run raised instead of rejoining: {errors}")
        self.assertEqual(len(results), self.WORKERS)
        self.assertEqual(
            len(set(results)), 1, f"workers received different runs: {sorted(set(results))}"
        )
        self.assertEqual(
            ScanRun.objects.filter(
                target=self.target, scan_type="MONITORING", status__in=ScanRun.LIVE_STATUSES
            ).count(),
            1,
            "more than one live run exists for the same logical operation",
        )

    def test_concurrent_runs_for_different_scan_types_do_not_collide(self):
        results, errors = [], []
        barrier = threading.Barrier(2)

        def worker(scan_type):
            try:
                self._tune_sqlite_connection()
                barrier.wait(timeout=30)
                results.append(self._call_with_sqlite_retry(scan_type).scan_type)
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                connections.close_all()

        threads = [threading.Thread(target=worker, args=(t,)) for t in ("MONITORING", "BASELINE")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=90)

        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), ["BASELINE", "MONITORING"])
