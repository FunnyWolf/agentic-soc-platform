from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from rest_framework import viewsets, permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from apps.common.cursor_pagination import cursor_response_payload, paginate_created_at_cursor
from .models import Comment
from .serializers import CommentSerializer


class CommentViewSet(viewsets.ModelViewSet):
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]

    def get_queryset(self):
        qs = Comment.objects.select_related("author", "content_type", "parent", "parent__author").prefetch_related(
            "mentions",
            "attachments",
        )
        ct = self.request.query_params.get("content_type")
        oid = self.request.query_params.get("object_id")
        if ct and oid:
            try:
                ct_model = ContentType.objects.get(model=ct)
                qs = qs.filter(content_type=ct_model, object_id=oid)
            except ContentType.DoesNotExist:
                qs = qs.none()
        return qs

    def list(self, request, *args, **kwargs):
        page = paginate_created_at_cursor(self.get_queryset(), request)
        serializer = self.get_serializer(page.results, many=True)
        return Response(cursor_response_payload(page, serializer.data))

    def perform_destroy(self, instance):
        if instance.author_id != self.request.user.id:
            raise PermissionDenied("You can only delete your own comments.")
        comment_id = instance.id
        content_type = instance.content_type.model
        object_id = instance.object_id
        actor_id = self.request.user.id
        instance.delete()
        transaction.on_commit(
            lambda: _broadcast_comment_deleted(comment_id, content_type, object_id, actor_id=actor_id)
        )


def _broadcast_comment_deleted(comment_id, content_type, object_id, *, actor_id):
    from apps.realtime.events import broadcast_comment_deleted

    broadcast_comment_deleted(comment_id, content_type, object_id, actor_id=actor_id)
