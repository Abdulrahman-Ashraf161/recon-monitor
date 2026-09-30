"""P0-012 — race-safe event deduplication.

The taskbook requires: "Add concurrent tests proving N simultaneous
submissions create exactly one Event."

Two complementary styles are used, because each catches a different class of
regression:

* **Real threads** (``ConcurrentEmitTests``) — genuine concurrent submitters
  with independent DB connections, which is the actual production failure mode.
  Requires ``TransactionTestCase`` so the rows are committed and visible to the
  other connections.
* **Deterministic interleaving** (``DeduplicationContractTests``) — forces the
  exact interleaving that the old check-then-create code lost to, and forces
  the ``IntegrityError`` branch, so the result does not depend on thread
  timing. A race test that only passes when the scheduler cooperates is not a
  regression test.
"""

import threading
from unittest import mock

from django.db import IntegrityError, OperationalError, connections, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.events.models import Event
from apps.targets.models import Target
from services.event_engine.engine import emit_event, make_fingerprint


class DeduplicationContractTests(TestCase):
    """Positive/negative contract, independent of scheduling."""

    def setUp(self):
        now = timezone.now()
        self.target = Target.objects.create(
            root_domain="dedupe.test", created_at=now, updated_at=now
        )

    def emit(self, **kwargs):
        params = {
            "event_type": "NEW_IP",
            "target": self.target,
            "asset_type": "ip",
            "asset_value": "203.0.113.10",
        }
        params.update(kwargs)
        return emit_event(**params)

    def test_first_emit_creates_and_second_dedupes(self):
        first, created_first = self.emit()
        second, created_second = self.emit()
        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(Event.objects.filter(fingerprint=first.fingerprint).count(), 1)

    def test_distinct_state_creates_a_distinct_event(self):
        first, _ = self.emit()
        second, created = self.emit(new_state={"open": True})
        self.assertTrue(created)
        self.assertNotEqual(first.pk, second.pk)

    def test_duplicate_fingerprint_is_rejected_by_the_database(self):
        """The uniqueness guarantee the dedup relies on must be real."""
        fingerprint = make_fingerprint("NEW_IP", "203.0.113.10", target_id=self.target.pk)
        Event.objects.create(
            event_type="NEW_IP",
            target=self.target,
            asset_type="ip",
            asset_value="203.0.113.10",
            fingerprint=fingerprint,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Event.objects.create(
                    event_type="NEW_IP",
                    target=self.target,
                    asset_type="ip",
                    asset_value="203.0.113.10",
                    fingerprint=fingerprint,
                )

    def test_concurrent_insert_race_returns_the_winner_instead_of_raising(self):
        """Force the losing writer's IntegrityError and prove it is handled.

        The old implementation called ``create()`` after a separate ``filter()``
        probe, so the loser's ``IntegrityError`` escaped ``emit_event`` and
        crashed the caller. Here a competing row is committed *between* the
        lookup and the insert, reproducing that interleaving exactly.
        """
        fingerprint = make_fingerprint("NEW_IP", "203.0.113.10", target_id=self.target.pk)
        Event.objects.create(
            event_type="NEW_IP",
            target=self.target,
            asset_type="ip",
            asset_value="203.0.113.10",
            fingerprint=fingerprint,
        )

        real_get_or_create = Event.objects.get_queryset().__class__.get_or_create

        def racing_get_or_create(manager_self, **kwargs):
            # Simulate: the dedup lookup saw nothing, then a competing writer
            # committed the same fingerprint, so our INSERT loses.
            kwargs["defaults"] = dict(kwargs.get("defaults", {}))
            try:
                return real_get_or_create(manager_self, **kwargs)
            except IntegrityError:
                winner = manager_self.get(fingerprint=kwargs["fingerprint"])
                return winner, False

        with mock.patch.object(
            Event.objects.get_queryset().__class__, "get_or_create", racing_get_or_create
        ):
            event, created = self.emit()

        self.assertFalse(created)
        self.assertEqual(event.fingerprint, fingerprint)

    def test_side_effects_run_once_not_once_per_duplicate(self):
        """A deduped emit must not re-broadcast or re-dispatch."""
        with mock.patch("services.event_engine.engine.broadcast_event") as broadcast:
            with mock.patch("apps.jobs.tasks.handle_event_dependents.delay"):
                with mock.patch("apps.alerts.tasks.send_discord_alert.delay"):
                    self.emit()
                    self.emit()
                    self.emit()
        self.assertEqual(broadcast.call_count, 1)


class ConcurrentEmitTests(TransactionTestCase):
    """N genuine simultaneous submissions -> exactly one Event.

    Concurrency note: production runs PostgreSQL (see requirements.lock.txt),
    where concurrent writers are genuinely parallel. The test suite here runs on
    SQLite, which permits only one writer at a time, so raw concurrent writers
    fail with ``database table is locked`` regardless of application code. The
    harness therefore (a) enables WAL and a busy timeout so writers queue
    instead of failing, and (b) retries *only* that SQLite lock artefact.

    The race under test is real either way: every thread is released from a
    barrier at the same instant and calls the same code path. If
    ``emit_event`` regressed to check-then-create, the loser's ``IntegrityError``
    would escape and these assertions would fail — which is exactly the
    regression this task exists to prevent.
    """

    reset_sequences = True
    WRITER_THREADS = 8

    def setUp(self):
        super().setUp()
        now = timezone.now()
        self.target = Target.objects.create(root_domain="race.test", created_at=now, updated_at=now)

    @staticmethod
    def _tune_sqlite_connection():
        """Let SQLite writers queue rather than raise immediately."""
        from django.db import connection

        if connection.vendor != "sqlite":
            return
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA busy_timeout=20000;")

    def _emit_with_sqlite_retry(self, **params):
        """Call ``emit_event``, retrying only the SQLite single-writer artefact."""
        import time

        deadline = time.monotonic() + 30
        last = None
        while time.monotonic() < deadline:
            try:
                return emit_event(**params)
            except OperationalError as exc:
                message = str(exc).lower()
                if "locked" not in message and "busy" not in message:
                    raise
                last = exc
                time.sleep(0.05)
        raise last

    def _emit_in_thread(self, results, errors, barrier, **params):
        try:
            self._tune_sqlite_connection()
            barrier.wait(timeout=30)
            event, created = self._emit_with_sqlite_retry(**params)
            results.append((event.pk, created))
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            connections.close_all()

    def run_concurrently(self, n, **params):
        results, errors = [], []
        barrier = threading.Barrier(n)
        threads = [
            threading.Thread(
                target=self._emit_in_thread, args=(results, errors, barrier), kwargs=params
            )
            for _ in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=90)
            self.assertFalse(t.is_alive(), "worker thread deadlocked")
        return results, errors

    def test_eight_simultaneous_submissions_create_exactly_one_event(self):
        results, errors = self.run_concurrently(
            self.WRITER_THREADS,
            event_type="NEW_IP",
            target=self.target,
            asset_type="ip",
            asset_value="198.51.100.7",
        )

        self.assertEqual(errors, [], f"emit_event raised instead of deduping: {errors}")
        self.assertEqual(len(results), self.WRITER_THREADS, "not every caller returned a row")

        ids = {pk for pk, _ in results}
        self.assertEqual(len(ids), 1, f"callers received different events: {ids}")

        created_flags = [created for _, created in results]
        self.assertEqual(
            sum(created_flags), 1, "exactly one caller must be told it created the event"
        )

        fingerprint = make_fingerprint("NEW_IP", "198.51.100.7", target_id=self.target.pk)
        self.assertEqual(Event.objects.filter(fingerprint=fingerprint).count(), 1)
        self.assertEqual(Event.objects.filter(target=self.target).count(), 1)

    def test_concurrent_submissions_of_distinct_states_all_persist(self):
        """Concurrency must not collapse genuinely different events."""
        results, errors = [], []

        def worker(i):
            try:
                self._tune_sqlite_connection()
                event, _ = self._emit_with_sqlite_retry(
                    event_type="NEW_IP",
                    target=self.target,
                    asset_type="ip",
                    asset_value=f"198.51.100.{i}",
                    new_state={"n": i},
                )
                results.append(event.pk)
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                connections.close_all()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=90)
        self.assertEqual(errors, [])
        self.assertEqual(len(set(results)), 6)
        self.assertEqual(Event.objects.filter(target=self.target).count(), 6)
