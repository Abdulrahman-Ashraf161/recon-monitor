"""Target-isolated live channels (TASK-043, TASK-080, Task 18, P0-006).

- ``/ws/targets/<target_id>/``: receives ONLY that target's events + jobs, and
  only for users who hold a membership row on it.
- ``/ws/events/`` and ``/ws/jobs/``: system feeds. Producers only route
  *target-less* system messages to these groups
  (:func:`services.event_engine.engine.broadcast_event` /
  `broadcast_job_like`), so joining them exposes no tenant data.

P0-006
------
Authorization is checked **before** ``group_add``, and again at delivery time:

* ``connect()`` resolves membership via
  :func:`apps.core.authorization.require_websocket_target_access` and closes
  with 4403 (``PermissionDenied``) / 4404 (``Http404``) instead of subscribing.
  The previous implementation authenticated the socket but never checked
  membership, so any logged-in user could attach to ``target_<id>`` and
  receive another tenant's live asset and job telemetry.
* ``event_message()`` re-checks that the payload's ``target_id`` matches the
  subscribed target, so a mis-routed broadcast cannot cross targets even if a
  future producer regresses.
* Membership is also re-validated on every delivery, so a revocation that lands
  after the socket connected stops the stream on the next event instead of
  leaking indefinitely.
"""

import json
import logging

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.core.exceptions import PermissionDenied
from django.http import Http404

logger = logging.getLogger(__name__)

CLOSE_UNAUTHENTICATED = 4401
CLOSE_FORBIDDEN = 4403
CLOSE_NOT_FOUND = 4404
CLOSE_MEMBERSHIP_REVOKED = 4403


class LiveConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.groups = []
        self.target_id = None

        user = self.scope.get("user")
        if not user or not getattr(user, "is_authenticated", False):
            await self.close(code=CLOSE_UNAUTHENTICATED)
            return

        target_id = (self.scope.get("url_route", {}).get("kwargs") or {}).get("target_id")
        if target_id:
            try:
                target = await self._authorize(user, target_id)
            except PermissionDenied:
                await self.close(code=CLOSE_FORBIDDEN)
                return
            except Http404:
                await self.close(code=CLOSE_NOT_FOUND)
                return
            self.target_id = target.id
            self.groups = [f"target_{target.id}"]
        else:
            self.groups = ["events", "jobs"]

        for g in self.groups:
            await self.channel_layer.group_add(g, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        for g in getattr(self, "groups", []) or []:
            await self.channel_layer.group_discard(g, self.channel_name)
        self.groups = []

    async def event_message(self, event):
        """Deliver, but only to a still-authorized, still-matching target."""
        data = event.get("data", {}) or {}

        # A target socket must never carry another target's payload, even if a
        # producer regresses and group_send's to the wrong group.
        if self.target_id is not None and data.get("target_id") not in (None, self.target_id):
            logger.warning(
                "websocket cross-target delivery blocked",
                extra={
                    "operation": "ws_deliver",
                    "status": "DENIED",
                    "subscribed_target_id": self.target_id,
                    "payload_target_id": data.get("target_id"),
                    "message_type": data.get("type"),
                },
            )
            return

        # Membership can be revoked after the socket connected; re-check so the
        # stream ends promptly instead of continuing to leak.
        if self.target_id is not None:
            user = self.scope.get("user")
            try:
                await self._authorize(user, self.target_id)
            except (PermissionDenied, Http404):
                await self.close(code=CLOSE_MEMBERSHIP_REVOKED)
                return

        await self.send(text_data=json.dumps(data))

    @database_sync_to_async
    def _authorize(self, user, target_id):
        from apps.core.authorization import require_websocket_target_access

        return require_websocket_target_access(user, target_id)
