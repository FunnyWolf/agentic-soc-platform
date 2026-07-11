from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from apps.inbox.models import InboxMessage
from apps.inbox.services import create_inbox_message
from .models import Comment


def create_record_comment(
    *,
    author,
    content_object=None,
    content_type=None,
    object_id="",
    body="",
    parent=None,
    mentions=None,
    attachments=None,
):
    """Create a record comment as a specific user, for API and automation code.

    Use this helper when backend/automation code needs to comment on a record
    (for example, case_000001) as a real user such as ``automation``. It creates
    the comment, attaches files, stores mentions, and sends inbox notifications
    to mentioned users just like the public comments API.
    """
    if content_object and not content_type:
        content_type = ContentType.objects.get_for_model(content_object, for_concrete_model=False)
        object_id = str(content_object.pk)

    mention_users = list(mentions or [])
    attachment_items = list(attachments or [])

    with transaction.atomic():
        comment = Comment.objects.create(
            content_type=content_type,
            object_id=str(object_id or ""),
            author=author,
            parent=parent,
            body=body or "",
        )
        if mention_users:
            comment.mentions.set(mention_users)
        if attachment_items:
            comment.attachments.set(attachment_items)

        recipients = [user for user in mention_users if user.id != author.id]
        if recipients:
            content_object = content_object or comment.content_object
            create_inbox_message(
                kind=InboxMessage.KIND_USER,
                sender=author,
                recipients=recipients,
                body=comment.body,
                attachments=attachment_items,
                content_object=content_object,
                content_type=comment.content_type,
                object_id=comment.object_id,
                metadata={"source": "comment", "comment_id": comment.id},
            )
        transaction.on_commit(lambda comment_id=comment.id: _broadcast_comment_created(comment_id))

    return comment


def _broadcast_comment_created(comment_id):
    from apps.realtime.events import broadcast_comment_created

    broadcast_comment_created(comment_id)
