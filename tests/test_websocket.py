"""WebSocket auth + isolation tests (Task 31).

Covers: anonymous rejected on both global routes, authenticated accepted,
A-socket never receives B-group broadcasts, global "jobs" carries no target
for linked jobs, disconnect removes the channel from groups.
"""
import asyncio
from types import SimpleNamespace

from django.test import TestCase

from apps.events.consumers import LiveConsumer


def _consumer(user, target_id=None):
    c = LiveConsumer()
    c.scope = {"type": "websocket", "user": user,
               "url_route": {"kwargs": {"target_id": target_id} if target_id else {}}}
    from channels.layers import get_channel_layer
    c.channel_layer = get_channel_layer()
    c.channel_name = f"test-{id(c)}"
    state = {"accepted": False, "closed": False, "sent": []}

    async def fake_accept():
        state["accepted"] = True

    async def fake_close():
        state["closed"] = True

    async def fake_send(text_data=None, bytes_data=None, **kw):
        state["sent"].append(text_data or bytes_data)

    c.accept = fake_accept
    c.close = fake_close
    c.send = fake_send
    return c, state


class WebSocketAuthTests(TestCase):
    def test_anonymous_rejected_global_events(self):
        from django.contrib.auth.models import AnonymousUser
        c, state = _consumer(AnonymousUser())
        asyncio.run(c.connect())
        self.assertTrue(state["closed"])
        self.assertFalse(state["accepted"])

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

    def test_authenticated_accepted_global(self):
        user = SimpleNamespace(is_authenticated=True)
        c, state = _consumer(user)
        asyncio.run(c.connect())
        self.assertTrue(state["accepted"])
        self.assertEqual(sorted(c.groups), ["events", "jobs"])
        asyncio.run(c.disconnect(1000))

    def test_authenticated_target_socket_only_own_group(self):
        user = SimpleNamespace(is_authenticated=True)
        c, state = _consumer(user, target_id=7)
        asyncio.run(c.connect())
        self.assertTrue(state["accepted"])
        self.assertEqual(c.groups, ["target_7"])
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
        id=99, event_type="NEW_SUBDOMAIN", asset_value="x.b.invalid",
        severity="LOW", priority="LOW", target=None, target_id=target_id,
        created_at=timezone.now(), correlation_id="abc")


class WebSocketIsolationTests(TestCase):
    def test_a_socket_never_receives_b_broadcast(self):
        # A target_1 socket joins ONLY target_1 (proven below); the engine
        # sends target_2 events ONLY to target_2 (proven here) => no leak.
        from services.event_engine.engine import broadcast_event
        user = SimpleNamespace(is_authenticated=True)
        c, state = _consumer(user, target_id=1)
        asyncio.run(c.connect())
        self.assertEqual(c.groups, ["target_1"])
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
        job = SimpleNamespace(id=1, job_type="dns", status="RUNNING", progress=10,
                              current_stage="dns",
                              target=SimpleNamespace(id=5, root_domain="a.invalid"))
        sent = _broadcast_with_fake_layer(broadcast_job_like, job)
        self.assertEqual([g for g, _ in sent], ["target_5"])
        self.assertEqual(sent[0][1]["data"]["target_id"], 5)
        # target-less system job -> global feed, with NO target keys at all
        sys_job = SimpleNamespace(id=2, job_type="sys", status="RUNNING", progress=1,
                                  current_stage="", target=None)
        sent = _broadcast_with_fake_layer(broadcast_job_like, sys_job)
        self.assertEqual([g for g, _ in sent], ["jobs"])
        self.assertNotIn("target", sent[0][1]["data"])
        self.assertNotIn("target_id", sent[0][1]["data"])

    def test_disconnect_discards_groups(self):
        user = SimpleNamespace(is_authenticated=True)
        c, state = _consumer(user, target_id=3)

        async def scenario():
            await c.connect()
            layer = c.channel_layer
            self.assertIn(c.channel_name, layer.groups.get("target_3", {}))
            await c.disconnect(1000)
            return layer.groups.get("target_3", {})

        remaining = asyncio.run(scenario())
        self.assertNotIn(c.channel_name, remaining)
