import logging

import redis
from django.contrib.contenttypes.models import ContentType
from rest_framework import permissions, status, views
from rest_framework.response import Response

from apps.accounts.permissions import IsAdmin
from apps.agentic.services.custom import (
    MAX_STREAM_MESSAGES,
    known_module_streams,
    list_module_definitions_with_health,
    list_playbook_definition_records,
    list_siem_definition_records,
    read_module_stream_message,
    read_module_stream_recent,
)
from apps.audit.models import AuditLog
from .models import RuntimeConfig


logger = logging.getLogger(__name__)


def _audit_refresh(section, request, result):
    instance = RuntimeConfig.get_current()
    AuditLog.objects.create(
        content_type=ContentType.objects.get_for_model(RuntimeConfig),
        object_id=str(instance.pk),
        action="refresh",
        actor=request.user if getattr(request.user, "is_authenticated", False) else None,
        metadata={
            "section": section,
            "success": result["success"],
            "counts": result["counts"],
        },
    )


class CustomDefinitionsModuleView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        return Response(list_module_definitions_with_health(), status=status.HTTP_200_OK)

    def post(self, request):
        result = list_module_definitions_with_health()
        _audit_refresh("modules", request, result)
        return Response(result, status=status.HTTP_200_OK)


class CustomDefinitionsPlaybookView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        return Response(list_playbook_definition_records(), status=status.HTTP_200_OK)

    def post(self, request):
        result = list_playbook_definition_records()
        _audit_refresh("playbooks", request, result)
        return Response(result, status=status.HTTP_200_OK)


class CustomDefinitionsSiemView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        return Response(list_siem_definition_records(), status=status.HTTP_200_OK)

    def post(self, request):
        result = list_siem_definition_records(reload=True)
        _audit_refresh("siem", request, result)
        return Response(result, status=status.HTTP_200_OK)


def _stream_name(request):
    stream_name = str(request.query_params.get("stream_name") or "").strip()
    if not stream_name:
        return None, Response({"stream_name": ["This query parameter is required."]}, status=status.HTTP_400_BAD_REQUEST)
    if stream_name not in known_module_streams():
        return None, Response({"detail": "Unknown module stream."}, status=status.HTTP_400_BAD_REQUEST)
    return stream_name, None


def _stream_limit(request):
    raw_limit = request.query_params.get("limit", 5)
    try:
        return max(1, min(int(raw_limit), MAX_STREAM_MESSAGES)), None
    except (TypeError, ValueError):
        return None, Response({"limit": ["Limit must be an integer."]}, status=status.HTTP_400_BAD_REQUEST)


def _redis_unavailable_response(action):
    logger.exception("Failed to %s", action)
    return Response({"detail": "Runtime stream service is unavailable."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class CustomModuleStreamMessagesView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        stream_name, error = _stream_name(request)
        if error is not None:
            return error
        limit, error = _stream_limit(request)
        if error is not None:
            return error
        try:
            result = read_module_stream_recent(stream_name, limit)
        except redis.RedisError:
            return _redis_unavailable_response("read module stream messages")
        return Response(result, status=status.HTTP_200_OK)


class CustomModuleStreamMessageView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        stream_name, error = _stream_name(request)
        if error is not None:
            return error
        message_id = str(request.query_params.get("message_id") or "").strip()
        if not message_id:
            return Response({"message_id": ["This query parameter is required."]}, status=status.HTTP_400_BAD_REQUEST)
        try:
            result = read_module_stream_message(stream_name, message_id)
        except redis.RedisError:
            return _redis_unavailable_response("read module stream message")
        return Response(result, status=status.HTTP_200_OK)
