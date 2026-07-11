from django.db import transaction
from django.db.models import Prefetch, Q
from django.utils import timezone
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from apps.accounts.permissions import is_business_writer
from apps.common.cursor_pagination import cursor_response_payload, paginate_created_at_cursor
from .models import InboxMessage, InboxMessageRecipient
from .serializers import (
    InboxMessageCreateSerializer,
    InboxMessageSerializer,
    InboxReplySerializer,
    mark_message_read,
)


class InboxMessageViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ["get", "post", "delete", "head", "options"]

    def get_queryset(self):
        user = self.request.user
        current_user_states = InboxMessageRecipient.objects.filter(user=user)
        queryset = InboxMessage.objects.select_related("sender", "content_type", "parent", "parent__sender").prefetch_related(
            "attachments",
            "recipients",
            Prefetch("recipient_states", queryset=current_user_states, to_attr="current_user_states"),
        )

        if self.action == "list":
            queryset = queryset.filter(
                Q(recipient_states__user=user) | Q(sender=user)
            )
        else:
            queryset = queryset.filter(Q(recipient_states__user=user) | Q(sender=user))

        unread = self.request.query_params.get("unread")
        if unread and unread.lower() in {"1", "true", "yes"}:
            queryset = queryset.filter(recipient_states__user=user, recipient_states__read_at__isnull=True)
        return queryset.distinct().order_by("-created_at")

    def get_serializer_class(self):
        if self.action == "create":
            return InboxMessageCreateSerializer
        if self.action == "reply":
            return InboxReplySerializer
        return InboxMessageSerializer

    def create(self, request, *args, **kwargs):
        if not is_business_writer(request.user):
            raise PermissionDenied("Viewer users cannot send messages.")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message = serializer.save()
        output = InboxMessageSerializer(message, context=self.get_serializer_context())
        return Response(output.data, status=status.HTTP_201_CREATED)
        return Response(output.data, status=status.HTTP_201_CREATED)
    def list(self, request, *args, **kwargs):
        page = paginate_created_at_cursor(self.get_queryset(), request)
        serializer = self.get_serializer(page.results, many=True)
        return Response(cursor_response_payload(page, serializer.data))

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        mark_message_read(instance, request.user)
        if hasattr(instance, "current_user_states"):
            delattr(instance, "current_user_states")
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def perform_destroy(self, instance):
        if not is_business_writer(self.request.user):
            raise PermissionDenied("Viewer users cannot delete messages.")
        if instance.kind != InboxMessage.KIND_USER or instance.sender_id != self.request.user.id:
            raise PermissionDenied("You can only delete your own user messages.")
        user_ids = set(instance.recipients.values_list("id", flat=True))
        if instance.sender_id:
            user_ids.add(instance.sender_id)
        message_id = instance.id
        actor_id = self.request.user.id
        instance.delete()
        transaction.on_commit(
            lambda: _broadcast_inbox_message_deleted(message_id, list(user_ids), actor_id=actor_id)
        )

    @action(detail=False, methods=["get"], url_path="unread-count")
    def unread_count(self, request):
        count = InboxMessageRecipient.objects.filter(
            user=request.user,
            read_at__isnull=True,
        ).count()
        return Response({"count": count})

    @action(detail=True, methods=["post"], url_path="mark-read")
    def mark_read(self, request, pk=None):
        message = self.get_object()
        mark_message_read(message, request.user)
        if hasattr(message, "current_user_states"):
            delattr(message, "current_user_states")
        serializer = self.get_serializer(message)
        return Response(serializer.data)

    @action(detail=False, methods=["post"], url_path="mark-all-read")
    def mark_all_read(self, request):
        message_ids = list(
            InboxMessageRecipient.objects.filter(
                user=request.user,
                read_at__isnull=True,
            ).values_list("message_id", flat=True)
        )
        read_at = timezone.now()
        updated = InboxMessageRecipient.objects.filter(
            user=request.user,
            read_at__isnull=True,
        ).update(read_at=read_at)
        if updated:
            transaction.on_commit(
                lambda: _broadcast_inbox_all_read(request.user.id, message_ids, read_at)
            )
        return Response({"updated": updated})

    @action(detail=True, methods=["post"])
    def reply(self, request, pk=None):
        if not is_business_writer(request.user):
            raise PermissionDenied("Viewer users cannot send messages.")
        parent = self.get_object()
        serializer = self.get_serializer(data=request.data, context={**self.get_serializer_context(), "parent": parent})
        serializer.is_valid(raise_exception=True)
        message = serializer.save()
        output = InboxMessageSerializer(message, context=self.get_serializer_context())
        return Response(output.data, status=status.HTTP_201_CREATED)


def _broadcast_inbox_message_deleted(message_id, user_ids, *, actor_id):
    from apps.realtime.events import broadcast_inbox_message_deleted

    broadcast_inbox_message_deleted(message_id, user_ids, actor_id=actor_id)


def _broadcast_inbox_all_read(user_id, message_ids, read_at):
    from apps.realtime.events import broadcast_inbox_all_read

    broadcast_inbox_all_read(user_id, message_ids, read_at)
