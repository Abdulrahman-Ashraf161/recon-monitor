"""WebSocket auth + target-isolation tests (Task 31, P0-006).

Covers:
  * anonymous rejected on both global routes and the target route (4401);
  * a user with NO membership is refused a target socket (4403) and is never
    added to the group — authorization happens *before* ``group_add``;
  * an unknown target id closes 4404 rather than 403 (no existence oracle);
  * a member is accepted into exactly ``target_<id>``;
  * a target socket drops another target's payload if a producer regresses;
  * membership revoked after connect stops delivery on the next event;
  * A-socket never receives B-group broadcasts; global "jobs" carries no
    target for linked jobs; disconnect removes the channel from groups.
"""

import asyncio
from types import SimpleNamespace

from django.test import TestCase, TransactionTestCase

from apps.events.consumers import (
    CLOSE_FORBIDDEN,
    CLOSE_NOT_FOUND,
    CLOSE_UNAUTHENTICATED,
    LiveConsumer,
)


def _consumer(user, target_id=None):
    c = LiveConsumer()
    c.scope = {
        "type": "websocket",
        "user": user,
        "url_route": {"kwargs": {"target_id": target_id} if target_id else {}},
    }
    from channels.layers import get_channel_layer

    c.channel_layer = get_channel_layer()
    c.channel_name = f"test-{id(c)}"
    state = {"accepted": False, "closed": False, "close_code": None, "sent": []}

    async def fake_accept():
        state["accepted"] = True

    # `close(code=...)` matches AsyncWebsocketConsumer's real signature.
    async def fake_close(code=None):
        state["closed"] = True
        state["close_code"] = code

    async def fake_send(text_data=None, bytes_data=None, **kw):
        state["sent"].append(text_data or bytes_data)

    c.accept = fake_accept
    c.close = fake_close
    c.send = fake_send
    return c, state


def _groups_in_layer(c, group):
    return c.channel_layer.groups.get(group, {})


class WebSocketAuthTests(TestCase):
    def test_anonymous_rejected_global_events(self):
        from django.contrib.auth.models import AnonymousUser

        c, state = _consumer(AnonymousUser())
        asyncio.run(c.connect())
        self.assertTrue(state["closed"])
        self.assertFalse(state["accepted"])
        self.assertEqual(state["close_code"], CLOSE_UNAUTHENTICATED)

    def test_anonymous_rejected_global_jobs(self):
        from django.contrib.auth.models import AnonymousUser

        c, state = _consumer(AnonymousUser())
        c.scope["path"] = "/ws/jobs/"
        asyncio.run(c.connect())
        self.assertTrue(state["closed"])
        self.assertFalse(state["accepted"])

    def test_anonymous_rejected_target_route(self):
        from django.contrib.auth.models import AnonymousUser

        c, state = _consumer(AnonymousUser(), target_id=1)
        asyncio.run(c.connect())
        self.assertTrue(state["closed"])
        self.assertEqual(state["close_code"], CLOSE_UNAUTHENTICATED)

    def test_authenticated_accepted_global(self):
        user = SimpleNamespace(is_authenticated=True)
        c, state = _consumer(user)
        asyncio.run(c.connect())
        self.assertTrue(state["accepted"])
        self.assertEqual(sorted(c.groups), ["events", "jobs"])
        asyncio.run(c.disconnect(1000))


class WebSocketMembershipTests(TransactionTestCase):
    """P0-006: subscription requires a membership row on the target.

    TransactionTestCase (not TestCase) because the consumer resolves membership
    through ``database_sync_to_async``, i.e. a separate thread and connection
    that must see committed rows rather than TestCase's atomic block.
    """

    def setUp(self):
        from tests.fixtures import grant, make_target, make_user

        self.member = make_user(username="ws-member")
        self.outsider = make_user(username="ws-outsider")
        self.target = make_target(root_domain="ws-alpha.example.com")
        self.other = make_target(root_domain="ws-beta.example.com")
        grant(self.member, self.target, "VIEWER")

    def test_member_accepted_for_own_target(self):
        c, state = _consumer(self.member, target_id=self.target.id)
        asyncio.run(c.connect())
        self.assertTrue(state["accepted"], state)
        self.assertEqual(c.groups, [f"target_{self.target.id}"])
        asyncio.run(c.disconnect(1000))

    def test_non_member_rejected_and_never_added_to_group(self):
        c, state = _consumer(self.outsider, target_id=self.target.id)
        asyncio.run(c.connect())
        self.assertTrue(state["closed"])
        self.assertFalse(state["accepted"])
        self.assertEqual(state["close_code"], CLOSE_FORBIDDEN)
        # The critical assertion: the socket was never subscribed.
        self.assertEqual(c.groups, [])
        self.assertNotIn(c.channel_name, _groups_in_layer(c, f"target_{self.target.id}"))

    def test_non_member_rejected_for_other_tenant_target(self):
        c, state = _consumer(self.member, target_id=self.other.id)
        asyncio.run(c.connect())
        self.assertTrue(state["closed"])
        self.assertEqual(state["close_code"], CLOSE_FORBIDDEN)
        self.assertNotIn(c.channel_name, _groups_in_layer(c, f"target_{self.other.id}"))

    def test_unknown_target_closes_not_found_not_forbidden(self):
        c, state = _consumer(self.member, target_id=999999)
        asyncio.run(c.connect())
        self.assertTrue(state["closed"])
        self.assertEqual(state["close_code"], CLOSE_NOT_FOUND)
        self.assertNotIn(c.channel_name, _groups_in_layer(c, "target_999999"))

    def test_superuser_may_subscribe(self):
        from tests.fixtures import make_admin

        c, state = _consumer(make_admin(), target_id=self.other.id)
        asyncio.run(c.connect())
        self.assertTrue(state["accepted"], state)
        asyncio.run(c.disconnect(1000))

    def test_revoked_membership_stops_delivery(self):
        """Revoking access after connect must end the stream, not keep leaking."""
        from apps.targets.models import TargetMembership

        c, state = _consumer(self.member, target_id=self.target.id)
        asyncio.run(c.connect())
        self.assertTrue(state["accepted"])

        TargetMembership.objects.filter(user=self.member, target=self.target).delete()

        payload = {"type": "event.created", "id": 1, "target_id": self.target.id}
        asyncio.run(c.event_message({"type": "event_message", "data": payload}))
        self.assertTrue(state["closed"], "socket should close after revocation")
        self.assertEqual(state["sent"], [])

    def test_cross_target_payload_is_dropped(self):
        """Even if a producer regresses, a target socket drops foreign data."""
        c, state = _consumer(self.member, target_id=self.target.id)
        asyncio.run(c.connect())
        self.assertTrue(state["accepted"])

        foreign = {"type": "event.created", "id": 2, "target_id": self.other.id}
        asyncio.run(c.event_message({"type": "event_message", "data": foreign}))
        self.assertEqual(state["sent"], [], "cross-target payload must not be delivered")
        self.assertFalse(state["closed"], "a single foreign payload is dropped, not fatal")

        own = {"type": "event.created", "id": 3, "target_id": self.target.id}
        asyncio.run(c.event_message({"type": "event_message", "data": own}))
        self.assertEqual(len(state["sent"]), 1)
        asyncio.run(c.disconnect(1000))


class _FakeLayer:
    """Deterministic capture for broadcast routing (Task 31)."""

    def __init__(self):
        self.sent = []

    async def group_send(self, group, message):
        self.sent.append((group, message))


def _broadcast_with_fake_layer(fn, *args):
    from unittest.mock import patch

    import services.event_engine.engine as eng

    fake = _FakeLayer()
    with patch.object(eng, "get_channel_layer", return_value=fake):
        fn(*args)
    return fake.sent


def _fake_event(target_id):
    from django.utils import timezone

    return SimpleNamespace(
        id=99,
        event_type="NEW_SUBDOMAIN",
        asset_value="x.b.invalid",
        severity="LOW",
        priority="LOW",
        target=None,
        target_id=target_id,
        created_at=timezone.now(),
        correlation_id="abc",
    )


class WebSocketIsolationTests(TransactionTestCase):
    def test_a_socket_never_receives_b_broadcast(self):
        # A target_1 socket joins ONLY target_1; the engine sends target_2
        # events ONLY to target_2 => no leak.
        from services.event_engine.engine import broadcast_event
        from tests.fixtures import grant, make_target, make_user

        user = make_user(username="ws-iso-member")
        target_1 = make_target(root_domain="ws-iso-1.example.com")
        make_target(root_domain="ws-iso-2.example.com")
        grant(user, target_1, "VIEWER")

        c, state = _consumer(user, target_id=target_1.id)
        asyncio.run(c.connect())
        self.assertEqual(c.groups, [f"target_{target_1.id}"])
        sent = _broadcast_with_fake_layer(broadcast_event, _fake_event(2))
        self.assertEqual([g for g, _ in sent], ["target_2"])
        asyncio.run(c.disconnect(1000))

    def test_target_socket_receives_own_broadcast(self):
        from services.event_engine.engine import broadcast_event

        sent = _broadcast_with_fake_layer(broadcast_event, _fake_event(2))
        self.assertEqual(len(sent), 1)
        group, message = sent[0]
        self.assertEqual(group, "target_2")
        self.assertEqual(message["data"]["event_type"], "NEW_SUBDOMAIN")

    def test_global_jobs_has_no_target_for_linked_jobs(self):
        from services.event_engine.engine import broadcast_job_like

        job = SimpleNamespace(
            id=1,
            job_type="dns",
            status="RUNNING",
            progress=10,
            current_stage="dns",
            target=SimpleNamespace(id=5, root_domain="a.invalid"),
        )
        sent = _broadcast_with_fake_layer(broadcast_job_like, job)
        self.assertEqual([g for g, _ in sent], ["target_5"])
        self.assertEqual(sent[0][1]["data"]["target_id"], 5)
        # target-less system job -> global feed, with NO target keys at all
        sys_job = SimpleNamespace(
            id=2, job_type="sys", status="RUNNING", progress=1, current_stage="", target=None
        )
        sent = _broadcast_with_fake_layer(broadcast_job_like, sys_job)
        self.assertEqual([g for g, _ in sent], ["jobs"])
        self.assertNotIn("target", sent[0][1]["data"])
        self.assertNotIn("target_id", sent[0][1]["data"])

    def test_disconnect_discards_groups(self):
        from tests.fixtures import grant, make_target, make_user

        user = make_user(username="ws-disc-member")
        target = make_target(root_domain="ws-disc.example.com")
        grant(user, target, "VIEWER")

        c, state = _consumer(user, target_id=target.id)
        group = f"target_{target.id}"

        async def scenario():
            await c.connect()
            self.assertIn(c.channel_name, _groups_in_layer(c, group))
            await c.disconnect(1000)
            return _groups_in_layer(c, group)

        remaining = asyncio.run(scenario())
        self.assertNotIn(c.channel_name, remaining)
