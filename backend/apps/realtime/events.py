import uuid
import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib.auth import get_user_model
from django.utils import timezone
from redis.exceptions import RedisError

from .groups import comments_group_name, inbox_group_name

User = get_user_model()
logger = logging.getLogger(__name__)


def _event(event_type, payload, *, actor_id=None):
    return {
        "type": event_type,
        "event_id": str(uuid.uuid4()),
        "occurred_at": timezone.now().isoformat(),
        "actor_id": actor_id,
        "payload": payload,
    }


def _send_group(group_name, event):
    channel_layer = get_channel_layer()
    if channel_layer is None:
        logger.warning("Realtime channel layer is not configured; skipped event type=%s group=%s", event.get("type"), group_name)
        return
    try:
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "realtime.event",
                "event": event,
            },
        )
    except RedisError:
        logger.exception("Failed to publish realtime event type=%s group=%s", event.get("type"), group_name)


def _unread_count(user_id):
    from apps.inbox.models import InboxMessageRecipient

    return InboxMessageRecipient.objects.filter(user_id=user_id, read_at__isnull=True).count()


def _send_unread_count_changed(user_id):
    _send_group(
        inbox_group_name(user_id),
        _event(
            "inbox.unread_count_changed",
            {"count": _unread_count(user_id)},
        ),
    )


def _serialize_inbox_message(message, user):
    from types import SimpleNamespace

    from apps.inbox.serializers import InboxMessageSerializer

    return InboxMessageSerializer(message, context={"request": SimpleNamespace(user=user)}).data


def broadcast_inbox_message_created(message_id):
    from apps.inbox.models import InboxMessage

    message = (
        InboxMessage.objects
        .select_related("sender", "content_type", "parent", "parent__sender")
        .prefetch_related("attachments", "recipients")
        .get(pk=message_id)
    )
    users = list(message.recipients.all())
    if message.sender_id and all(user.id != message.sender_id for user in users):
        users.append(message.sender)

    for user in users:
        _send_group(
            inbox_group_name(user.id),
            _event(
                "inbox.message_created",
                {"message": _serialize_inbox_message(message, user)},
                actor_id=message.sender_id,
            ),
        )
        _send_unread_count_changed(user.id)


def broadcast_inbox_message_deleted(message_id, user_ids, *, actor_id=None):
    for user_id in user_ids:
        _send_group(
            inbox_group_name(user_id),
            _event(
                "inbox.message_deleted",
                {"message_id": message_id},
                actor_id=actor_id,
            ),
        )
        _send_unread_count_changed(user_id)


def broadcast_inbox_message_read(message_id, user_id, read_at):
    _send_group(
        inbox_group_name(user_id),
        _event(
            "inbox.message_read",
            {"message_id": message_id, "read_at": read_at.isoformat()},
            actor_id=user_id,
        ),
    )
    _send_unread_count_changed(user_id)


def broadcast_inbox_all_read(user_id, message_ids, read_at):
    _send_group(
        inbox_group_name(user_id),
        _event(
            "inbox.all_read",
            {"message_ids": message_ids, "read_at": read_at.isoformat()},
            actor_id=user_id,
        ),
    )
    _send_unread_count_changed(user_id)


def _serialize_comment(comment):
    from apps.comments.serializers import CommentSerializer

    return CommentSerializer(comment).data


def broadcast_comment_created(comment_id):
    from apps.comments.models import Comment

    comment = (
        Comment.objects
        .select_related("author", "content_type", "parent", "parent__author")
        .prefetch_related("mentions", "attachments")
        .get(pk=comment_id)
    )
    content_type = comment.content_type.model
    _send_group(
        comments_group_name(content_type, comment.object_id),
        _event(
            "comment.created",
            {
                "content_type": content_type,
                "object_id": comment.object_id,
                "comment": _serialize_comment(comment),
            },
            actor_id=comment.author_id,
        ),
    )


def broadcast_comment_deleted(comment_id, content_type, object_id, *, actor_id=None):
    _send_group(
        comments_group_name(content_type, object_id),
        _event(
            "comment.deleted",
            {
                "content_type": content_type,
                "object_id": object_id,
                "comment_id": comment_id,
            },
            actor_id=actor_id,
        ),
    )
