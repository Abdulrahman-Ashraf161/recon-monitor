"""P2-001/P2-002: distinct expiring/expired lifecycle events, deduplicated.

P2-001 requires separate lifecycle events (AUTHORIZATION_EXPIRING for the
warning window, AUTHORIZATION_EXPIRED for the actual lapse). Before this change
both branches emitted "AUTHORIZATION_EXPIRED"; because emit_event's fingerprint
ignores evidence (the event_type + target + asset are identical), the earlier
MEDIUM warning event *claimed* the fingerprint and the later HIGH expired event
was silently swallowed by the P0-012 dedup — warned targets never got their
expiry alert.

P2-002 requires that repeated scheduler runs do not produce an unbounded stream
of identical warning events. The fingerprint now includes the window state
(expires_at + warning_days), so:

  - a stable window dedups across every scheduler run -> exactly one event;
  - a renewed window (expires_at changed) re-arms -> a fresh, *distinct* event.
"""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.events.models import Event
from apps.monitoring.tasks import check_authorization_expiry
from apps.targets.models import Target

from .fixtures import make_target

WINDOW_DAYS = 3


def _warned_target():
    """Active target sitting inside the warning window but not yet expired."""
    return make_target(
        auth_warning_days=WINDOW_DAYS,
        authorization_expires_at=timezone.now() + timedelta(days=1),
    )


class ExpiringWarningTests(TestCase):
    """The warning window emits AUTHORIZATION_EXPIRING, not EXPIRED."""

    def test_window_emits_expiring_medium_event_once(self):
        t = _warned_target()
        events = Event.objects.filter(target=t)

        for _ in range(6):
            out = check_authorization_expiry()
            self.assertEqual(out["paused"], 0)  # never expired

        self.assertEqual(events.filter(event_type="AUTHORIZATION_EXPIRING").count(), 1)
        self.assertEqual(events.filter(event_type="AUTHORIZATION_EXPIRED").count(), 0)
        ev = events.get(event_type="AUTHORIZATION_EXPIRING")
        self.assertEqual(ev.severity, "MEDIUM")
        self.assertTrue(ev.evidence.get("warning"))
        self.assertIn("expires_at", ev.evidence)

        # Scheduler never touches the target state inside the window.
        t.refresh_from_db()
        self.assertEqual(t.authorization_status, Target.AUTH_AUTHORIZED)
        self.assertEqual(t.status, Target.STATUS_ACTIVE)

    def test_renewal_rearms_the_warning(self):
        # Same window -> one event; bump the window (renewal) -> a fresh event.
        t = _warned_target()
        check_authorization_expiry()
        check_authorization_expiry()
        self.assertEqual(
            Event.objects.filter(target=t, event_type="AUTHORIZATION_EXPIRING").count(), 1
        )

        t.authorization_expires_at = timezone.now() + timedelta(days=2)
        t.save(update_fields=["authorization_expires_at"])
        check_authorization_expiry()
        self.assertEqual(
            Event.objects.filter(target=t, event_type="AUTHORIZATION_EXPIRING").count(), 2
        )

    def test_outside_window_emits_nothing(self):
        t = make_target(
            auth_warning_days=WINDOW_DAYS,
            authorization_expires_at=timezone.now() + timedelta(days=30),
        )
        check_authorization_expiry()
        self.assertEqual(Event.objects.filter(target=t).count(), 0)


class DistinguishExpiredTests(TestCase):
    """Actual expiry produces a distinct HIGH event even after a warning."""

    def test_warned_target_still_gets_its_high_expiry_event(self):
        """Regression for the pre-P2-001 fingerprint collision."""
        t = _warned_target()
        check_authorization_expiry()
        self.assertEqual(
            Event.objects.filter(target=t, event_type="AUTHORIZATION_EXPIRING").count(), 1
        )

        t.authorization_expires_at = timezone.now() - timedelta(seconds=1)
        t.save(update_fields=["authorization_expires_at"])
        out = check_authorization_expiry()
        self.assertEqual(out["paused"], 1)

        t.refresh_from_db()
        self.assertEqual(t.authorization_status, Target.AUTH_EXPIRED)
        self.assertEqual(t.status, Target.STATUS_PAUSED)

        events = Event.objects.filter(target=t)
        self.assertEqual(events.filter(event_type="AUTHORIZATION_EXPIRING").count(), 1)
        expired = events.get(event_type="AUTHORIZATION_EXPIRED")
        self.assertEqual(expired.severity, "HIGH")
        self.assertIn("expired_at", expired.evidence)
        self.assertEqual(expired.new_state.get("authorization"), "EXPIRED")

    def test_expired_event_is_deduplicated_across_runs(self):
        t = _warned_target()
        t.authorization_expires_at = timezone.now() - timedelta(seconds=1)
        t.save(update_fields=["authorization_expires_at"])
        for _ in range(5):
            check_authorization_expiry()
        self.assertEqual(
            Event.objects.filter(target=t, event_type="AUTHORIZATION_EXPIRED").count(), 1
        )

    def test_renewal_rearms_high_expiry(self):
        t = _warned_target()
        t.authorization_expires_at = timezone.now() - timedelta(seconds=1)
        t.save(update_fields=["authorization_expires_at"])
        check_authorization_expiry()
        self.assertEqual(
            Event.objects.filter(target=t, event_type="AUTHORIZATION_EXPIRED").count(), 1
        )

        # Re-authorize (renew) and let the *new* window lapse -> fresh event.
        t.authorization_status = Target.AUTH_AUTHORIZED
        t.status = Target.STATUS_ACTIVE
        t.authorization_expires_at = timezone.now() - timedelta(seconds=1)
        t.save(update_fields=["authorization_status", "status", "authorization_expires_at"])
        check_authorization_expiry()
        self.assertEqual(
            Event.objects.filter(target=t, event_type="AUTHORIZATION_EXPIRED").count(), 2
        )
