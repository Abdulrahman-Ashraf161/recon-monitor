"""Target-isolated live channels (TASK-043, TASK-080, Task 18).

- /ws/targets/<target_id>/: receives ONLY that target's events + jobs.
- /ws/events/ and /ws/jobs/: global feeds for target-less system messages only.
- Task 18: EVERY route requires authentication (anonymous sockets are closed
  immediately — previously the global feeds accepted anonymous connections and
  broadcast_job_like() leaked every engagement's domains/scan progress there).
"""
import json

from channels.generic.websocket import AsyncWebsocketConsumer


class LiveConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        if not user or not getattr(user, "is_authenticated", False):
            await self.close()
            return
        target_id = self.scope["url_route"]["kwargs"].get("target_id")
        if target_id:
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
