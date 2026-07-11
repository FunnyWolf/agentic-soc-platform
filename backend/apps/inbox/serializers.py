from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers

from apps.accounts.serializers import UserSerializer
from apps.attachments.models import Attachment
from apps.attachments.serializers import AttachmentSerializer
from apps.comments.models import Comment
from apps.common.serializers import ContentTypeField
from .models import InboxMessage, InboxMessageRecipient
from .services import create_inbox_message, resolve_resource_identity

User = get_user_model()


class InboxMessageSerializer(serializers.ModelSerializer):
    sender_name = serializers.CharField(source="sender.get_full_name", read_only=True)
    sender_username = serializers.CharField(source="sender.username", read_only=True)
    sender_avatar_url = serializers.SerializerMethodField()
    recipients = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    recipient_users = serializers.SerializerMethodField()
    attachments = AttachmentSerializer(many=True, read_only=True)
    content_type = ContentTypeField(required=False, allow_null=True)
    resource_label = serializers.SerializerMethodField()
    parent_author_name = serializers.SerializerMethodField()
    parent_author_username = serializers.SerializerMethodField()
    parent_body = serializers.SerializerMethodField()
    read_at = serializers.SerializerMethodField()
    is_read = serializers.SerializerMethodField()
    can_delete = serializers.SerializerMethodField()

    class Meta:
        model = InboxMessage
        fields = (
            "id",
            "kind",
            "sender",
            "sender_name",
            "sender_username",
            "sender_avatar_url",
            "parent",
            "recipients",
            "recipient_users",
            "attachments",
            "content_type",
            "object_id",
            "resource_key",
            "resource_label",
            "parent_author_name",
            "parent_author_username",
            "parent_body",
            "body",
            "metadata",
            "created_at",
            "read_at",
            "is_read",
            "can_delete",
        )
        read_only_fields = (
            "id",
            "kind",
            "sender",
            "sender_name",
            "sender_username",
            "sender_avatar_url",
            "parent",
            "recipients",
            "recipient_users",
            "attachments",
            "resource_key",
            "resource_label",
            "parent_author_name",
            "parent_author_username",
            "parent_body",
            "metadata",
            "created_at",
            "read_at",
            "is_read",
            "can_delete",
        )

    def _recipient_state(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return None
        prefetched = getattr(obj, "current_user_states", None)
        if prefetched:
            return prefetched[0]
        return obj.recipient_states.filter(user=request.user).first()

    def get_sender_avatar_url(self, obj):
        if not obj.sender:
            return ""
        return UserSerializer(obj.sender, context=self.context).data["avatar_url"]

    def get_read_at(self, obj):
        state = self._recipient_state(obj)
        return state.read_at if state else None

    def get_is_read(self, obj):
        request = self.context.get("request")
        state = self._recipient_state(obj)
        if not state and request and obj.sender_id == request.user.id:
            return True
        return bool(state and state.read_at)

    def get_can_delete(self, obj):
        request = self.context.get("request")
        return bool(
            request
            and request.user.is_authenticated
            and obj.kind == InboxMessage.KIND_USER
            and obj.sender_id == request.user.id
        )

    def get_recipient_users(self, obj):
        return [
            {"id": user.id, "username": user.username, "name": user.get_full_name()}
            for user in obj.recipients.all()
        ]

    def get_resource_label(self, obj):
        identity = resolve_resource_identity(
            content_object=obj.content_object,
            content_type=obj.content_type,
            object_id=obj.object_id,
            resource_key=obj.resource_key,
            resource_label=obj.resource_label,
        )
        return identity["resource_label"]

    def get_parent_author_name(self, obj):
        if not obj.parent or not obj.parent.sender:
            return ""
        return obj.parent.sender.get_full_name()

    def get_parent_author_username(self, obj):
        if not obj.parent or not obj.parent.sender:
            return ""
        return obj.parent.sender.username

    def get_parent_body(self, obj):
        if not obj.parent:
            return ""
        return obj.parent.body


class InboxMessageCreateSerializer(serializers.Serializer):
    body = serializers.CharField(required=False, allow_blank=True)
    recipients = serializers.PrimaryKeyRelatedField(many=True, queryset=User.objects.filter(is_active=True))
    attachments = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Attachment.objects.all(),
        required=False,
    )
    content_type = ContentTypeField(required=False, allow_null=True)
    object_id = serializers.CharField(required=False, allow_blank=True)
    resource_key = serializers.CharField(required=False, allow_blank=True)
    resource_label = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        body = attrs.get("body", "")
        attachments = attrs.get("attachments", [])
        if not body.strip() and not attachments:
            raise serializers.ValidationError("Message body or attachments are required.")
        sender = self.context["request"].user
        recipients = [user for user in attrs["recipients"] if user.id != sender.id]
        if not recipients:
            raise serializers.ValidationError("At least one recipient other than yourself is required.")
        attrs["recipients"] = recipients
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        return create_inbox_message(
            kind=InboxMessage.KIND_USER,
            sender=request.user,
            recipients=validated_data["recipients"],
            body=validated_data.get("body", ""),
            attachments=validated_data.get("attachments", []),
            content_type=validated_data.get("content_type"),
            object_id=validated_data.get("object_id", ""),
            resource_key=validated_data.get("resource_key", ""),
            resource_label=validated_data.get("resource_label", ""),
        )


class InboxReplySerializer(serializers.Serializer):
    body = serializers.CharField(required=False, allow_blank=True)
    attachments = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Attachment.objects.all(),
        required=False,
    )

    def validate(self, attrs):
        body = attrs.get("body", "")
        attachments = attrs.get("attachments", [])
        parent = self.context["parent"]
        request = self.context["request"]
        if parent.kind != InboxMessage.KIND_USER or parent.sender_id is None:
            raise serializers.ValidationError("Only user messages can be replied to.")
        if parent.sender_id == request.user.id:
            raise serializers.ValidationError("You cannot reply to your own message.")
        if not body.strip() and not attachments:
            raise serializers.ValidationError("Reply body or attachments are required.")
        return attrs

    def create(self, validated_data):
        parent = self.context["parent"]
        request = self.context["request"]
        attachments = validated_data.get("attachments", [])
        message = create_inbox_message(
            kind=InboxMessage.KIND_USER,
            sender=request.user,
            parent=parent,
            recipients=[parent.sender],
            body=validated_data.get("body", ""),
            attachments=attachments,
            content_type=parent.content_type,
            object_id=parent.object_id,
            resource_key=parent.resource_key,
            resource_label=parent.resource_label,
            metadata={"reply_to": parent.id},
        )
        if parent.metadata.get("source") == "comment" and parent.content_type_id and parent.object_id:
            comment = Comment.objects.create(
                content_type=parent.content_type,
                object_id=parent.object_id,
                author=request.user,
                parent_id=parent.metadata.get("comment_id"),
                body=validated_data.get("body", ""),
            )
            if attachments:
                comment.attachments.set(attachments)
        return message


def mark_message_read(message, user):
    read_at = timezone.now()
    updated = InboxMessageRecipient.objects.filter(
        message=message,
        user=user,
        read_at__isnull=True,
    ).update(read_at=read_at)
    if updated:
        from django.db import transaction
        from apps.realtime.events import broadcast_inbox_message_read

        transaction.on_commit(
            lambda message_id=message.id, user_id=user.id, timestamp=read_at: broadcast_inbox_message_read(
                message_id,
                user_id,
                timestamp,
            )
        )
