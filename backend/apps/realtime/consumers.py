from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError

from .groups import comments_group_name, inbox_group_name


class EventsConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4401)
            return

        self.comment_groups = set()
        self.inbox_group = inbox_group_name(user.id)
        await self.channel_layer.group_add(self.inbox_group, self.channel_name)
        await self.accept()
        await self.send_json({"type": "realtime.connected"})

    async def disconnect(self, close_code):
        if hasattr(self, "inbox_group"):
            await self.channel_layer.group_discard(self.inbox_group, self.channel_name)
        for group_name in getattr(self, "comment_groups", set()):
            await self.channel_layer.group_discard(group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        message_type = content.get("type")
        if message_type == "comments.subscribe":
            await self._subscribe_comments(content)
            return
        if message_type == "comments.unsubscribe":
            await self._unsubscribe_comments(content)
            return
        await self.send_json({"type": "realtime.error", "payload": {"detail": "Unknown message type."}})

    async def _subscribe_comments(self, content):
        content_type = str(content.get("content_type") or "")
        object_id = str(content.get("object_id") or "")
        if not await self._can_subscribe_to_record(content_type, object_id):
            await self.send_json({
                "type": "realtime.error",
                "payload": {"detail": "Cannot subscribe to record comments."},
            })
            return

        group_name = comments_group_name(content_type, object_id)
        await self.channel_layer.group_add(group_name, self.channel_name)
        self.comment_groups.add(group_name)
        await self.send_json({
            "type": "comments.subscribed",
            "payload": {"content_type": content_type, "object_id": object_id},
        })

    async def _unsubscribe_comments(self, content):
        content_type = str(content.get("content_type") or "")
        object_id = str(content.get("object_id") or "")
        group_name = comments_group_name(content_type, object_id)
        if group_name in self.comment_groups:
            self.comment_groups.remove(group_name)
            await self.channel_layer.group_discard(group_name, self.channel_name)
        await self.send_json({
            "type": "comments.unsubscribed",
            "payload": {"content_type": content_type, "object_id": object_id},
        })

    @database_sync_to_async
    def _can_subscribe_to_record(self, content_type, object_id):
        if not content_type or not object_id:
            return False
        try:
            content_type_obj = ContentType.objects.get(model=content_type)
        except ContentType.DoesNotExist:
            return False

        model_class = content_type_obj.model_class()
        if not model_class:
            return False

        try:
            return model_class._default_manager.filter(pk=object_id).exists()
        except (ValidationError, ValueError):
            return False

    async def realtime_event(self, event):
        await self.send_json(event["event"])

