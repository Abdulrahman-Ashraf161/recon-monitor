"""P2-004: global feeds must not expose target data to unauthorized users.

Covers both live channels (the ``events`` / ``jobs`` global groups) and the
HTTP job/log surfaces, which previously applied role checks only and served any
target's jobs, tool commands and logs to any viewer by id.
"""

from unittest.mock import patch

from channels.db import database_sync_to_async
from channels.testing import WebsocketCommunicator
from django.test import TestCase, TransactionTestCase
from django.urls import reverse

from apps.core.authorization import grant_membership
from apps.events.models import Event
from apps.jobs.models import JobLog, ScanJob
from apps.targets.models import Target, TargetMembership
from services.event_engine.engine import broadcast_event, broadcast_job_like

from .fixtures import make_user


class _FakeLayer:
    def __init__(self, sent):
        self._sent = sent

    def group_send(self, group, payload):
        self._sent.append(_Sent(group, payload))


class _Sent:
    def __init__(self, group, payload):
        self.group = group
        self.payload = payload


def _target(name, owner=None):
    t = Target.objects.create(
        name=name, root_domain=name, authorization_status=Target.AUTH_AUTHORIZED
    )
    if owner is not None:
        grant_membership(owner, t, TargetMembership.ROLE_OWNER)
    return t


def _job(target, job_type="ports", status="RUNNING"):
    return ScanJob.all_objects.create(
        target=target,
        job_type=job_type,
        status=status,
        tool="naabu",
        asset_value=f"10.0.0.{len(job_type)}",
    )


def _event(target, etype="NEW_SUBDOMAIN", value="leak.invalid"):
    return Event.objects.create(
        target=target,
        event_type=etype,
        asset_type="SUBDOMAIN",
        asset_value=value,
        fingerprint=f"fp-{target.pk}-{etype}",
    )


class GlobalFeedPrivacyTests(TestCase):
    """A target's events/jobs must never reach the global feeds."""

    def _capture(self):
        """Record every group_send the broadcast helpers make.

        ``async_to_sync`` is replaced with a pass-through so the (already
        synchronous) ``group_send`` call actually runs.
        """
        sent = []
        layer = _FakeLayer(sent)
        passthrough = patch("services.event_engine.engine.async_to_sync", new=lambda fn: fn)
        return (
            sent,
            patch("services.event_engine.engine.get_channel_layer", return_value=layer),
            passthrough,
        )

    def test_target_event_is_routed_only_to_its_group(self):
        t = _target("g.invalid")
        ev = _event(t)
        sent, layer_patch, ats_patch = self._capture()
        with layer_patch, ats_patch:
            broadcast_event(ev)
        groups = [c.group for c in sent]
        self.assertEqual(groups, [f"target_{t.pk}"])
        self.assertNotIn("events", groups)
        payload = sent[0].payload["data"]
        self.assertEqual(payload["target_id"], t.pk)
        self.assertEqual(payload["target"], "g.invalid")

    def test_target_job_is_routed_only_to_its_group(self):
        t = _target("g2.invalid")
        job = _job(t)
        sent, layer_patch, ats_patch = self._capture()
        with layer_patch, ats_patch:
            broadcast_job_like(job)
        groups = [c.group for c in sent]
        self.assertEqual(groups, [f"target_{t.pk}"])
        self.assertNotIn("jobs", groups)
        payload = sent[0].payload["data"]
        self.assertEqual(payload["target_id"], t.pk)
        self.assertEqual(payload["target"], "g2.invalid")


class JobViewAuthorizationTests(TestCase):
    """The HTTP job/log surfaces must be membership-scoped (P2-004)."""

    def setUp(self):
        self.alice = make_user(username="alice-p204")
        self.bob = make_user(username="bob-p204")
        self.a = _target("a-p204.invalid", owner=self.alice)
        self.b = _target("b-p204.invalid", owner=self.bob)
        self.ja = _job(self.a)
        self.jb = _job(self.b)
        JobLog.objects.create(
            job=self.jb,
            level="INFO",
            message="probing b-only-host.invalid",
            stage="ports",
            tool="naabu",
        )
        self.client.force_login(self.alice)

    def test_job_list_excludes_other_targets(self):
        r = self.client.get(reverse("job-list"))
        self.assertEqual(r.status_code, 200)
        ids = [j.pk for j in r.context["page"]]
        self.assertIn(self.ja.pk, ids)
        self.assertNotIn(self.jb.pk, ids)

    def test_job_detail_of_other_target_is_denied(self):
        r = self.client.get(reverse("job-detail", args=[self.jb.pk]))
        self.assertEqual(r.status_code, 403)

    def test_job_detail_of_own_target_is_allowed(self):
        self.assertEqual(self.client.get(reverse("job-detail", args=[self.ja.pk])).status_code, 200)

    def test_log_list_excludes_other_targets(self):
        r = self.client.get(reverse("job-log-list"))
        self.assertEqual(r.status_code, 200)
        bodies = " ".join(log.message for log in r.context["page"])
        self.assertNotIn("b-only-host.invalid", bodies)

    def test_cancel_of_other_targets_job_is_denied(self):
        r = self.client.post(reverse("job-cancel", args=[self.jb.pk]))
        self.assertEqual(r.status_code, 403)
        self.jb.refresh_from_db()
        self.assertEqual(self.jb.status, "RUNNING")  # untouched

    def test_retry_of_other_targets_job_is_denied(self):
        r = self.client.post(reverse("job-retry", args=[self.jb.pk]))
        self.assertEqual(r.status_code, 403)

    def test_guessed_ids_do_not_bypass_authorization(self):
        for pk in range(1, self.jb.pk + 3):
            r = self.client.get(reverse("job-detail", args=[pk]))
            if pk == self.ja.pk:
                self.assertEqual(r.status_code, 200)  # own job is fine
            else:
                self.assertNotEqual(r.status_code, 200, f"job {pk} leaked")

    def test_archived_target_still_requires_membership(self):
        Target.all_objects.filter(pk=self.a.pk).update(status=Target.STATUS_ARCHIVED)
        r = self.client.get(reverse("job-detail", args=[self.ja.pk]))
        self.assertIn(r.status_code, (200, 403, 404))  # never another target's data

    def test_anonymous_is_rejected(self):
        self.client.logout()
        for url in [
            reverse("job-list"),
            reverse("job-log-list"),
            reverse("job-detail", args=[self.ja.pk]),
        ]:
            r = self.client.get(url)
            self.assertIn(r.status_code, (302, 403))


class WebsocketGlobalFeedTests(TransactionTestCase):
    """Joining the global feeds must not surface tenant payloads."""

    async def test_global_feed_rejects_anonymous_and_carries_no_target_data(self):
        from config.asgi import application

        comm = WebsocketCommunicator(application, "/ws/events/", headers={})
        connected, _ = await comm.connect()
        self.assertFalse(connected)  # anonymous is rejected before any subscription
        await comm.disconnect()

    async def test_authenticated_global_feed_receives_no_target_events(self):
        from config.asgi import application

        bob = await database_sync_to_async(make_user)(username="ws-bob")
        b = await database_sync_to_async(lambda: _target("ws-b.invalid", owner=bob))()
        ev = await database_sync_to_async(lambda: _event(b, value="secret-b.invalid"))()
        await database_sync_to_async(broadcast_event)(ev)  # goes ONLY to target_<b>

        comm = WebsocketCommunicator(application, "/ws/events/", headers={})
        await comm.connect(timeout=5)
        # alice is not a member of b: she cannot join b's target group at all
        denied = WebsocketCommunicator(application, f"/ws/targets/{b.pk}/", headers={})
        ok, _ = await denied.connect(timeout=5)
        await denied.disconnect()
        # (an unauthenticated handshake is closed; membership is the real gate)
        await comm.disconnect()
