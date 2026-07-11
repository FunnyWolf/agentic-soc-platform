from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import transaction

from apps.attachments.models import Attachment
from .models import InboxMessage, InboxMessageRecipient

User = get_user_model()

RESOURCE_KEY_BY_MODEL = {
    "case": "cases",
    "alert": "alerts",
    "artifact": "artifacts",
    "enrichment": "enrichments",
    "playbook": "playbooks",
    "knowledge": "knowledge",
    "user": "users",
}

READABLE_ID_FIELD_BY_MODEL = {
    "case": "case_id",
    "alert": "alert_id",
    "artifact": "artifact_id",
    "enrichment": "enrichment_id",
    "playbook": "playbook_id",
    "knowledge": "knowledge_id",
    "user": "username",
}


def resource_key_for_content_type(content_type):
    if not content_type:
        return ""
    return RESOURCE_KEY_BY_MODEL.get(content_type.model, content_type.model)


def label_for_content_object(content_object, fallback=""):
    if not content_object:
        return fallback
    model_name = getattr(getattr(content_object, "_meta", None), "model_name", "")
    readable_id_field = READABLE_ID_FIELD_BY_MODEL.get(model_name)
    if readable_id_field:
        value = getattr(content_object, readable_id_field, None)
        if value:
            return str(value)

    for field in (
        "case_id",
        "alert_id",
        "artifact_id",
        "enrichment_id",
        "playbook_id",
        "knowledge_id",
        "username",
        "name",
        "value",
        "title",
    ):
        value = getattr(content_object, field, None)
        if value:
            return str(value)
    return str(content_object)


def _content_object_for_identity(content_type, object_id):
    if not content_type or not object_id:
        return None

    model_class = content_type.model_class()
    if not model_class:
        return None

    try:
        return model_class._default_manager.get(pk=object_id)
    except (model_class.DoesNotExist, ValidationError, ValueError):
        return None


def _display_label_fallback(resource_label, object_id):
    label = str(resource_label or "")
    if label and label != str(object_id or ""):
        return label
    return ""


def resolve_resource_identity(
    *,
    content_object=None,
    content_type=None,
    object_id="",
    resource_key="",
    resource_label="",
):
    resolved_content_object = content_object
    resolved_content_type = content_type
    resolved_object_id = str(object_id or "")

    if resolved_content_object:
        if not resolved_content_type:
            resolved_content_type = ContentType.objects.get_for_model(resolved_content_object, for_concrete_model=False)
        resolved_object_id = str(resolved_content_object.pk)
    elif resolved_content_type and resolved_object_id:
        resolved_content_object = _content_object_for_identity(resolved_content_type, resolved_object_id)

    resolved_resource_key = resource_key or ""
    if resolved_content_type and not resolved_resource_key:
        resolved_resource_key = resource_key_for_content_type(resolved_content_type)

    resolved_resource_label = _display_label_fallback(resource_label, resolved_object_id)
    if resolved_content_object:
        resolved_resource_label = label_for_content_object(resolved_content_object, fallback=resolved_resource_label)

    return {
        "content_type": resolved_content_type,
        "object_id": resolved_object_id,
        "content_object": resolved_content_object,
        "resource_key": resolved_resource_key,
        "resource_label": resolved_resource_label,
    }


def _normalize_users(users):
    if users is None:
        return []
    if hasattr(users, "all"):
        users = users.all()

    user_ids = []
    normalized = []
    for user in users:
        user_id = getattr(user, "id", user)
        if user_id and user_id not in user_ids:
            user_ids.append(user_id)
    if user_ids:
        normalized = list(User.objects.filter(id__in=user_ids, is_active=True))
    return normalized


def create_inbox_message(
    *,
    kind,
    recipients,
    body="",
    sender=None,
    parent=None,
    attachments=None,
    content_type=None,
    object_id="",
    content_object=None,
    resource_key="",
    resource_label="",
    metadata=None,
):
    normalized_recipients = _normalize_users(recipients)
    if not normalized_recipients:
        return None

    identity = resolve_resource_identity(
        content_object=content_object,
        content_type=content_type,
        object_id=object_id,
        resource_key=resource_key,
        resource_label=resource_label,
    )

    attachment_ids = []
    for attachment in attachments or []:
        attachment_id = getattr(attachment, "id", attachment)
        if attachment_id and attachment_id not in attachment_ids:
            attachment_ids.append(attachment_id)

    with transaction.atomic():
        message = InboxMessage.objects.create(
            kind=kind,
            sender=sender if kind == InboxMessage.KIND_USER else None,
            parent=parent,
            content_type=identity["content_type"],
            object_id=identity["object_id"],
            resource_key=identity["resource_key"],
            resource_label=identity["resource_label"],
            body=body or "",
            metadata=metadata or {},
        )
        InboxMessageRecipient.objects.bulk_create([
            InboxMessageRecipient(message=message, user=user)
            for user in normalized_recipients
        ])
        if attachment_ids:
            message.attachments.set(Attachment.objects.filter(id__in=attachment_ids))
        transaction.on_commit(lambda message_id=message.id: _broadcast_inbox_message_created(message_id))
    return message


def _broadcast_inbox_message_created(message_id):
    from apps.realtime.events import broadcast_inbox_message_created

    broadcast_inbox_message_created(message_id)


def send_system_message(
    *,
    recipients,
    body,
    content_object=None,
    content_type=None,
    object_id="",
    resource_key="",
    resource_label="",
    attachments=None,
    metadata=None,
):
    return create_inbox_message(
        kind=InboxMessage.KIND_SYSTEM,
        recipients=recipients,
        body=body,
        content_object=content_object,
        content_type=content_type,
        object_id=object_id,
        resource_key=resource_key,
        resource_label=resource_label,
        attachments=attachments,
        metadata=metadata,
    )


def send_user_message(
    *,
    sender,
    recipients,
    body="",
    content_object=None,
    content_type=None,
    object_id="",
    resource_key="",
    resource_label="",
    attachments=None,
    metadata=None,
):
    """Send an inbox message from a real user account, including automation users.

    Use this from backend jobs/playbooks when a named sender such as
    ``automation`` should appear in the inbox. The message is a normal user
    message, so recipients can see the sender, reply, and open the optional
    linked record supplied via ``content_object`` or ``content_type``/``object_id``.
    """
    return create_inbox_message(
        kind=InboxMessage.KIND_USER,
        sender=sender,
        recipients=recipients,
        body=body,
        content_object=content_object,
        content_type=content_type,
        object_id=object_id,
        resource_key=resource_key,
        resource_label=resource_label,
        attachments=attachments,
        metadata=metadata,
    )
