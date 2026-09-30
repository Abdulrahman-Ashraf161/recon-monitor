"""P2-005 / P2-007: target lifecycle policy.

P2-005: removal is archive-first (soft delete, evidence survives); hard delete
        requires explicit confirmation and reports exactly what it destroyed.
P2-007: lifecycle transitions are centralized -- legal transitions enforced,
        illegal ones rejected, and the required side effects (work halt,
        re-queue, events, audit) always run.
"""

from django.test import TestCase
from django.urls import reverse

from apps.core.authorization import grant_membership
from apps.events.models import Event
from apps.jobs.models import ScanJob, ScanRun
from apps.targets.models import Target, TargetMembership
from apps.targets.target_lifecycle import (
    InvalidTransition,
    archive_target,
    purge_target,
    restore_target,
    transition_to,
)

from .fixtures import make_user


def _target(name="life.invalid", status=Target.STATUS_ACTIVE, auth=Target.AUTH_AUTHORIZED):
    return Target.objects.create(
        name=name, root_domain=name, status=status, authorization_status=auth
    )


def _running_job(t, job_type="ports"):
    return ScanJob.all_objects.create(
        target=t, job_type=job_type, status=ScanJob.STATUS_RUNNING, started_at=None
    )


class ArchivePolicyTests(TestCase):
    """P2-005"""

    def test_archive_keeps_all_historical_evidence(self):
        from apps.assets.models import Subdomain
        from apps.jobs.models import AssetObservation

        t = _target()
        sub = Subdomain.objects.create(target=t, hostname="a.life.invalid")
        run = ScanRun.all_objects.create(target=t, scan_type="DISCOVERY", status="COMPLETED")
        job = ScanJob.all_objects.create(
            target=t, job_type="ports", status=ScanJob.STATUS_COMPLETED
        )
        AssetObservation.all_objects.create(
            target=t,
            scan_run=run,
            asset_type="SUBDOMAIN",
            asset_id=sub.id,
            asset_value=sub.hostname,
        )
        ev = Event.objects.create(
            target=t,
            event_type="NEW_SUBDOMAIN",
            asset_type="SUBDOMAIN",
            asset_value=sub.hostname,
            fingerprint="fp-archive",
        )

        archive_target(t, reason="test", actor="pytest")

        t.refresh_from_db()
        self.assertEqual(t.status, Target.STATUS_ARCHIVED)
        self.assertIsNotNone(t.archived_at)
        self.assertFalse(t.is_scannable)
        # everything survives
        self.assertTrue(Subdomain.all_objects.filter(pk=sub.pk).exists())
        self.assertTrue(ScanRun.all_objects.filter(pk=run.pk).exists())
        self.assertTrue(ScanJob.all_objects.filter(pk=job.pk).exists())
        self.assertTrue(AssetObservation.all_objects.filter(target=t).exists())
        self.assertTrue(Event.all_objects.filter(pk=ev.pk).exists())
        # and an archive event records the decision
        self.assertTrue(Event.objects.filter(target=t, event_type="TARGET_ARCHIVED").exists())

    def test_archive_halts_in_flight_work(self):
        t = _target()
        run = ScanRun.all_objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        _running_job(t)
        archive_target(t, reason="test", actor="pytest")
        t.refresh_from_db()
        run.refresh_from_db()
        # the execution root is tripped so it is never mistaken for live work
        self.assertIsNotNone(run.cancel_requested_at)
        self.assertIn(run.status, ("CANCELLED", "FAILED", "COMPLETED"))
        self.assertFalse(t.is_scannable)

    def test_restore_makes_the_target_scannable_again(self):
        t = _target()
        archive_target(t, reason="test")
        t.refresh_from_db()
        self.assertFalse(t.is_scannable)
        restore_target(t, reason="restored")
        t.refresh_from_db()
        self.assertEqual(t.status, Target.STATUS_ACTIVE)
        self.assertIsNone(t.archived_at)
        self.assertTrue(t.is_scannable)

    def test_purge_requires_explicit_confirmation(self):
        t = _target()
        with self.assertRaises(ValueError):
            purge_target(t, confirmation=None, reason="oops")
        with self.assertRaises(ValueError):
            purge_target(t, confirmation="yes", reason="oops")
        with self.assertRaises(ValueError):
            purge_target(t, confirmation="delete", reason="oops")
        # the target is untouched by a refused purge
        self.assertTrue(Target.all_objects.filter(pk=t.pk).exists())

    def test_purge_with_confirmation_returns_a_manifest(self):
        from apps.assets.models import Subdomain

        t = _target()
        for i in range(3):
            Subdomain.objects.create(target=t, hostname=f"h{i}.life.invalid")
        ScanJob.all_objects.create(target=t, job_type="ports", status=ScanJob.STATUS_COMPLETED)
        manifest = purge_target(t, confirmation="PURGE", reason="gdpr", actor="pytest")
        self.assertEqual(manifest["subdomains"], 3)
        self.assertEqual(manifest["scan_jobs"], 1)
        self.assertTrue(any(v for v in manifest.values()))
        self.assertFalse(Target.all_objects.filter(pk=t.pk).exists())
        self.assertFalse(Subdomain.all_objects.filter(target_id=t.pk).exists())

    def test_purge_halts_work_before_destroying(self):
        t = _target()
        ScanRun.all_objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        _running_job(t)
        purge_target(t, confirmation="PURGE", reason="test")
        # nothing survives, and no worker could have been left writing
        self.assertFalse(ScanRun.all_objects.filter(target_id=t.pk).exists())


class ArchiveViewTests(TestCase):
    def setUp(self):
        self.admin = make_user(username="lc-admin", role="ADMIN", superuser=True)
        self.op = make_user(username="lc-op", role="OPERATOR")
        self.t = _target("vt.invalid")
        grant_membership(self.op, self.t, TargetMembership.ROLE_OPERATOR)
        grant_membership(self.admin, self.t, TargetMembership.ROLE_OWNER)
        self.client.force_login(self.admin)

    def test_delete_without_confirmation_archives(self):
        r = self.client.post(reverse("target-delete", args=[self.t.id]))
        self.assertEqual(r.status_code, 302)
        self.t.refresh_from_db()
        self.assertEqual(self.t.status, Target.STATUS_ARCHIVED)
        self.assertTrue(Target.all_objects.filter(pk=self.t.pk).exists())

    def test_delete_with_purge_token_hard_deletes(self):
        r = self.client.post(
            reverse("target-delete", args=[self.t.id]), {"confirm": "PURGE", "reason": "gdpr"}
        )
        self.assertEqual(r.status_code, 302)
        self.assertFalse(Target.all_objects.filter(pk=self.t.pk).exists())

    def test_wrong_confirmation_is_refused(self):
        r = self.client.post(reverse("target-delete", args=[self.t.id]), {"confirm": "yes"})
        self.assertEqual(r.status_code, 403)
        self.t.refresh_from_db()
        self.assertEqual(self.t.status, Target.STATUS_ACTIVE)

    def test_non_admin_cannot_delete(self):
        self.client.force_login(self.op)
        r = self.client.post(reverse("target-delete", args=[self.t.id]))
        self.assertIn(r.status_code, (302, 403))
        self.t.refresh_from_db()
        self.assertEqual(self.t.status, Target.STATUS_ACTIVE)

    def test_pause_and_resume_go_through_the_policy(self):
        self.client.post(reverse("target-pause", args=[self.t.id]))
        self.t.refresh_from_db()
        self.assertEqual(self.t.status, Target.STATUS_PAUSED)
        self.client.post(reverse("target-resume", args=[self.t.id]))
        self.t.refresh_from_db()
        self.assertEqual(self.t.status, Target.STATUS_ACTIVE)


class TransitionPolicyTests(TestCase):
    """P2-007: transitions are validated centrally."""

    def test_legal_transitions_are_allowed(self):
        for current, requested in [
            (Target.STATUS_ACTIVE, Target.STATUS_PAUSED),
            (Target.STATUS_ACTIVE, Target.STATUS_DISABLED),
            (Target.STATUS_ACTIVE, Target.STATUS_ARCHIVED),
            (Target.STATUS_PAUSED, Target.STATUS_ACTIVE),
            (Target.STATUS_DISABLED, Target.STATUS_ARCHIVED),
            (Target.STATUS_ARCHIVED, Target.STATUS_ACTIVE),
        ]:
            t = _target(f"x-{current}-{requested}.invalid", status=current)
            transition_to(t, new_status=requested, reason="test")
            t.refresh_from_db()
            self.assertEqual(t.status, requested, f"{current} -> {requested} should be legal")

    def test_illegal_transitions_are_rejected(self):
        # ARCHIVED can only go back to ACTIVE, never straight to PAUSED/DISABLED
        t = _target("ill.invalid", status=Target.STATUS_ARCHIVED)
        for illegal in (Target.STATUS_PAUSED, Target.STATUS_DISABLED):
            with self.assertRaises(InvalidTransition):
                transition_to(t, new_status=illegal, reason="test")
        t.refresh_from_db()
        self.assertEqual(t.status, Target.STATUS_ARCHIVED)  # unchanged

    def test_idempotent_transition_is_a_noop(self):
        t = _target("noop.invalid", status=Target.STATUS_ACTIVE)
        transition_to(t, new_status=Target.STATUS_ACTIVE, reason="same")
        t.refresh_from_db()
        self.assertEqual(t.status, Target.STATUS_ACTIVE)

    def test_authorization_transitions_are_validated(self):
        t = _target("auth.invalid", auth=Target.AUTH_PENDING)
        transition_to(t, new_auth=Target.AUTH_AUTHORIZED, reason="confirmed")
        t.refresh_from_db()
        self.assertEqual(t.authorization_status, Target.AUTH_AUTHORIZED)
        transition_to(t, new_auth=Target.AUTH_EXPIRED, reason="lapsed")
        t.refresh_from_db()
        self.assertEqual(t.authorization_status, Target.AUTH_EXPIRED)

    def test_expiry_transition_emits_the_event_and_stops_work(self):
        t = _target("exp.invalid")
        run = ScanRun.all_objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        _running_job(t)
        transition_to(t, new_auth=Target.AUTH_EXPIRED, reason="lapsed", actor="pytest")
        t.refresh_from_db()
        self.assertFalse(t.is_scannable)
        self.assertTrue(Event.objects.filter(target=t, event_type="AUTHORIZATION_EXPIRED").exists())
        # in-flight work on the expired target is halted
        run.refresh_from_db()
        self.assertNotEqual(run.status, "RUNNING")
        self.assertIsNotNone(run.cancel_requested_at)

    def test_reauthorization_emits_its_own_event(self):
        t = _target("reauth.invalid", auth=Target.AUTH_EXPIRED)
        transition_to(t, new_auth=Target.AUTH_AUTHORIZED, reason="renewed")
        self.assertTrue(
            Event.objects.filter(target=t, event_type="AUTHORIZATION_REAUTHORIZED").exists()
        )

    def test_resume_requeues_paused_jobs(self):
        t = _target(status=Target.STATUS_PAUSED)
        job = ScanJob.all_objects.create(target=t, job_type="ports", status=ScanJob.STATUS_PAUSED)
        transition_to(t, new_status=Target.STATUS_ACTIVE, reason="resume")
        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.STATUS_QUEUED)

    def test_force_bypasses_the_table_but_still_writes(self):
        t = _target("force.invalid", status=Target.STATUS_ARCHIVED)
        transition_to(t, new_status=Target.STATUS_DISABLED, reason="repair", force=True)
        t.refresh_from_db()
        self.assertEqual(t.status, Target.STATUS_DISABLED)


class PurgeManifestCompletenessTests(TestCase):
    """P2-005/P2-007: the destruction manifest must never silently drop keys.

    The manifest is the audit record of what a hard purge destroyed. Counting
    baselines/exports shared one try/except whose handler was a bare `pass`, so a
    failure removed *both* keys and the manifest still looked complete. Each
    count is now recorded independently and a failure is recorded as None, the
    same convention the per-model loop already used.
    """

    def test_manifest_includes_every_documented_key(self):
        from apps.targets.models import Target
        from apps.targets.target_lifecycle import purge_target

        t = Target.objects.create(
            root_domain="manifest-keys.invalid", authorization_status=Target.AUTH_AUTHORIZED
        )
        m = purge_target(t, confirmation="PURGE")
        for key in (
            "subdomains",
            "dns_records",
            "ips",
            "ports",
            "http_services",
            "urls",
            "api_endpoints",
            "javascript",
            "technologies",
            "cves",
            "security_findings",
            "scan_runs",
            "scan_jobs",
            "tool_executions",
            "asset_observations",
            "events",
            "baselines",
            "exports",
        ):
            self.assertIn(key, m, f"manifest is missing {key!r}")

    def test_manifest_marks_a_failed_count_as_none_instead_of_omitting_it(self):
        from unittest.mock import patch

        from apps.targets import target_lifecycle as tl
        from apps.targets.models import Target

        t = Target.objects.create(
            root_domain="manifest-fail.invalid", authorization_status=Target.AUTH_AUTHORIZED
        )

        class Boom:
            @classmethod
            def all_objects(cls):
                class Q:
                    def filter(self, **kw):
                        raise RuntimeError("count failed")

                return Q()

        import apps.monitoring.models as mm

        with patch.object(mm, "Baseline", Boom):
            m = tl.purge_target(t, confirmation="PURGE")
        self.assertIn("baselines", m)
        self.assertIsNone(m["baselines"], "a failed count must be None, not a missing key")
        self.assertIn("exports", m, "the sibling count must still be recorded")
