"""Target-isolated live channels (TASK-043, TASK-080).

- /ws/events/ and /ws/jobs/: global feeds (system + job progress only, no asset detail).
- /ws/targets/<target_id>/: receives ONLY that target's events + jobs.
  A browser subscribed to Target A never receives Target B payloads.
"""
import json

from channels.generic.websocket import AsyncWebsocketConsumer


class LiveConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        target_id = self.scope["url_route"]["kwargs"].get("target_id")
        user = self.scope.get("user")
        if target_id:
            # Target-scoped socket: only this target's group. Auth required.
            if not user or not getattr(user, "is_authenticated", False):
                await self.close()
                return
            self.groups = [f"target_{target_id}"]
        else:
            self.groups = ["events", "jobs"]
        for g in self.groups:
            await self.channel_layer.group_add(g, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        for g in getattr(self, "groups", []):
            await self.channel_layer.group_discard(g, self.channel_name)

    async def event_message(self, event):
        await self.send(text_data=json.dumps(event.get("data", {})))
