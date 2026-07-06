from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, status, views, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response

from apps.accounts.permissions import IsAdmin
from apps.audit.models import AuditLog
from apps.common.advanced_filters import AdvancedFilterBackend
from apps.common.operation_timeout import OperationTimeoutError, run_with_operation_timeout
from .models import (
    LdapConfig,
    LLMProviderConfig,
    RuntimeConfig,
    SiemElkConfig,
    SiemSplunkConfig,
    ThreatIntelAlienVaultOTXConfig,
    ThreatIntelOpenCTIConfig,
)
from .runtime_config import invalidate
from .serializers import (
    LLMProviderConfigSerializer,
    LdapConfigSerializer,
    SiemElkConfigSerializer,
    SiemSplunkConfigSerializer,
    RuntimeConfigSerializer,
    ThreatIntelAlienVaultOTXConfigSerializer,
    ThreatIntelOpenCTIConfigSerializer,
)
from .services import test_alienvault_otx_config, test_elk_config, test_llm_provider, test_opencti_config, test_splunk_config

LLM_AUDIT_FIELDS = ("name", "base_url", "model", "proxy", "tags", "enabled", "priority", "api_key")
OTX_AUDIT_FIELDS = ("enabled", "api_key", "base_url", "proxy")
OPENCTI_AUDIT_FIELDS = ("enabled", "url", "token", "ssl_verify", "proxy")
SPLUNK_AUDIT_FIELDS = ("host", "port", "username", "password", "scheme", "verify")
ELK_AUDIT_FIELDS = (
    "host",
    "api_key",
    "verify_certs",
    "process_alert_from_index_enabled",
    "action_index",
    "action_poll_interval_seconds",
    "action_size",
)
LDAP_AUDIT_FIELDS = (
    "enabled",
    "server_uri",
    "domain",
    "bind_dn",
    "bind_password",
    "user_search_base_dn",
    "user_login_attr",
)
RUNTIME_AUDIT_FIELDS = (
    "prompt_language",
    "stream_maxlen",
)


def _snapshot(instance, fields):
    return {field: getattr(instance, field) for field in fields}


def _audit_changes(before, after, secret_fields):
    changes = {}
    for field in after.keys():
        old_value = before.get(field) if before else None
        new_value = after.get(field)
        if old_value == new_value:
            continue
        if field in secret_fields:
            changes[field] = {"changed": True}
        else:
            changes[field] = {"from": old_value, "to": new_value}
    return changes


def _write_audit(instance, action, actor, *, changes=None, metadata=None):
    AuditLog.objects.create(
        content_type=ContentType.objects.get_for_model(type(instance)),
        object_id=str(instance.pk),
        action=action,
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        changes=changes or {},
        metadata=metadata or {},
    )


def _run_config_test(operation, func, config):
    try:
        return run_with_operation_timeout(
            operation,
            func,
            config,
            timeout_seconds=settings.CONFIG_TEST_TIMEOUT_SECONDS,
        )
    except OperationTimeoutError as exc:
        return {"success": False, "detail": str(exc), "response_preview": ""}


def _config_from_instance(instance, values):
    config = _snapshot(instance, LLM_AUDIT_FIELDS) if instance else {}
    config.update(values)
    return config


class LLMProviderConfigViewSet(viewsets.ModelViewSet):
    queryset = LLMProviderConfig.objects.all()
    serializer_class = LLMProviderConfigSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    search_fields = ("name", "base_url", "model")
    ordering_fields = ("name", "base_url", "model", "enabled", "priority", "created_at", "updated_at")
    filterset_fields = ("enabled",)
    advanced_filter_fields = {
        "name": "text",
        "base_url": "text",
        "model": "text",
        "enabled": "select",
        "priority": "number",
    }

    def get_queryset(self):
        queryset = super().get_queryset()
        raw_tags = self.request.query_params.get("tags", "")
        tags = [tag.strip() for tag in raw_tags.split(",") if tag.strip()]
        if not tags:
            return queryset

        query = Q()
        for tag in tags:
            query |= Q(tags__contains=[tag])
        return queryset.filter(query).distinct()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["reveal_secrets"] = self.request.query_params.get("reveal_secrets") in {"1", "true", "yes"}
        return context

    @transaction.atomic
    def perform_create(self, serializer):
        instance = serializer.save()
        after = _snapshot(instance, LLM_AUDIT_FIELDS)
        _write_audit(instance, "create", self.request.user, changes=_audit_changes(None, after, {"api_key"}))
        transaction.on_commit(lambda: invalidate("llm"))

    @transaction.atomic
    def perform_update(self, serializer):
        instance = self.get_object()
        before = _snapshot(instance, LLM_AUDIT_FIELDS)
        instance = serializer.save()
        changes = _audit_changes(before, _snapshot(instance, LLM_AUDIT_FIELDS), {"api_key"})
        if changes:
            _write_audit(instance, "update", self.request.user, changes=changes)
        transaction.on_commit(lambda: invalidate("llm"))

    @transaction.atomic
    def perform_destroy(self, instance):
        before = _snapshot(instance, LLM_AUDIT_FIELDS)
        _write_audit(instance, "delete", self.request.user, changes=_audit_changes(before, {}, {"api_key"}))
        instance.delete()
        transaction.on_commit(lambda: invalidate("llm"))

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if self.get_serializer_context().get("reveal_secrets"):
            _write_audit(instance, "reveal", request.user, metadata={"fields": ["api_key"]})
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    @action(detail=False, methods=["post"], url_path="test")
    def test_unsaved(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = _run_config_test("settings.llm.test", test_llm_provider, serializer.validated_data)
        AuditLog.objects.create(
            content_type=ContentType.objects.get_for_model(LLMProviderConfig),
            object_id="unsaved",
            action="test",
            actor=request.user if getattr(request.user, "is_authenticated", False) else None,
            metadata={"success": result["success"], "provider": serializer.validated_data.get("name", "")},
        )
        return Response(result, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="test")
    def test_saved(self, request, pk=None):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data or {}, partial=True)
        serializer.is_valid(raise_exception=True)
        result = _run_config_test("settings.llm.test", test_llm_provider, _config_from_instance(instance, serializer.validated_data))
        _write_audit(instance, "test", request.user, metadata={"success": result["success"]})
        return Response(result, status=status.HTTP_200_OK)


def _otx_config_from_instance(instance, values):
    config = _snapshot(instance, OTX_AUDIT_FIELDS)
    config.update(values)
    return config


def _opencti_config_from_instance(instance, values):
    config = _snapshot(instance, OPENCTI_AUDIT_FIELDS)
    config.update(values)
    return config


def _invalidate_siem(group):
    invalidate(group)
    from integrations.siem.clients import reset_clients

    reset_clients()


class ThreatIntelAlienVaultOTXConfigView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get_serializer_context(self):
        return {
            "reveal_secrets": self.request.query_params.get("reveal_secrets") in {"1", "true", "yes"},
        }

    def get(self, request):
        instance = ThreatIntelAlienVaultOTXConfig.get_current()
        if self.get_serializer_context().get("reveal_secrets"):
            _write_audit(instance, "reveal", request.user, metadata={"fields": ["api_key"]})
        serializer = ThreatIntelAlienVaultOTXConfigSerializer(instance, context=self.get_serializer_context())
        return Response(serializer.data)

    @transaction.atomic
    def patch(self, request):
        instance = ThreatIntelAlienVaultOTXConfig.get_current()
        before = _snapshot(instance, OTX_AUDIT_FIELDS)
        serializer = ThreatIntelAlienVaultOTXConfigSerializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        changes = _audit_changes(before, _snapshot(instance, OTX_AUDIT_FIELDS), {"api_key"})
        if changes:
            _write_audit(instance, "update", request.user, changes=changes)
        transaction.on_commit(lambda: invalidate("otx"))
        return Response(ThreatIntelAlienVaultOTXConfigSerializer(instance).data)


class ThreatIntelAlienVaultOTXTestView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request):
        instance = ThreatIntelAlienVaultOTXConfig.get_current()
        serializer = ThreatIntelAlienVaultOTXConfigSerializer(instance, data=request.data or {}, partial=True)
        serializer.is_valid(raise_exception=True)
        result = _run_config_test(
            "settings.threat_intel.otx.test",
            test_alienvault_otx_config,
            _otx_config_from_instance(instance, serializer.validated_data),
        )
        _write_audit(instance, "test", request.user, metadata={"success": result["success"]})
        return Response(result, status=status.HTTP_200_OK)


class ThreatIntelOpenCTIConfigView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get_serializer_context(self):
        return {
            "reveal_secrets": self.request.query_params.get("reveal_secrets") in {"1", "true", "yes"},
        }

    def get(self, request):
        instance = ThreatIntelOpenCTIConfig.get_current()
        if self.get_serializer_context().get("reveal_secrets"):
            _write_audit(instance, "reveal", request.user, metadata={"fields": ["token"]})
        serializer = ThreatIntelOpenCTIConfigSerializer(instance, context=self.get_serializer_context())
        return Response(serializer.data)

    @transaction.atomic
    def patch(self, request):
        instance = ThreatIntelOpenCTIConfig.get_current()
        before = _snapshot(instance, OPENCTI_AUDIT_FIELDS)
        serializer = ThreatIntelOpenCTIConfigSerializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        changes = _audit_changes(before, _snapshot(instance, OPENCTI_AUDIT_FIELDS), {"token"})
        if changes:
            _write_audit(instance, "update", request.user, changes=changes)
        transaction.on_commit(lambda: invalidate("opencti"))
        return Response(ThreatIntelOpenCTIConfigSerializer(instance).data)


class ThreatIntelOpenCTITestView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request):
        instance = ThreatIntelOpenCTIConfig.get_current()
        serializer = ThreatIntelOpenCTIConfigSerializer(instance, data=request.data or {}, partial=True)
        serializer.is_valid(raise_exception=True)
        result = _run_config_test(
            "settings.threat_intel.opencti.test",
            test_opencti_config,
            _opencti_config_from_instance(instance, serializer.validated_data),
        )
        _write_audit(instance, "test", request.user, metadata={"success": result["success"]})
        return Response(result, status=status.HTTP_200_OK)


def _singleton_view_context(request):
    return {
        "reveal_secrets": request.query_params.get("reveal_secrets") in {"1", "true", "yes"},
    }


def _singleton_patch(instance, serializer_class, request, audit_fields, secret_fields, invalidate_group):
    before = _snapshot(instance, audit_fields)
    serializer = serializer_class(instance, data=request.data, partial=True)
    serializer.is_valid(raise_exception=True)
    instance = serializer.save()
    changes = _audit_changes(before, _snapshot(instance, audit_fields), secret_fields)
    if changes:
        _write_audit(instance, "update", request.user, changes=changes)
    transaction.on_commit(lambda: _invalidate_siem(invalidate_group))
    return Response(serializer_class(instance).data)


class SiemSplunkConfigView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        instance = SiemSplunkConfig.get_current()
        if _singleton_view_context(request)["reveal_secrets"]:
            _write_audit(instance, "reveal", request.user, metadata={"fields": ["password"]})
        serializer = SiemSplunkConfigSerializer(instance, context=_singleton_view_context(request))
        return Response(serializer.data)

    @transaction.atomic
    def patch(self, request):
        return _singleton_patch(
            SiemSplunkConfig.get_current(),
            SiemSplunkConfigSerializer,
            request,
            SPLUNK_AUDIT_FIELDS,
            {"password"},
            "splunk",
        )


class SiemSplunkTestView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request):
        instance = SiemSplunkConfig.get_current()
        serializer = SiemSplunkConfigSerializer(instance, data=request.data or {}, partial=True)
        serializer.is_valid(raise_exception=True)
        config = _snapshot(instance, SPLUNK_AUDIT_FIELDS)
        config.update(serializer.validated_data)
        result = _run_config_test("settings.siem.splunk.test", test_splunk_config, config)
        _write_audit(instance, "test", request.user, metadata={"success": result["success"]})
        return Response(result, status=status.HTTP_200_OK)


class SiemElkConfigView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        instance = SiemElkConfig.get_current()
        if _singleton_view_context(request)["reveal_secrets"]:
            _write_audit(instance, "reveal", request.user, metadata={"fields": ["api_key"]})
        serializer = SiemElkConfigSerializer(instance, context=_singleton_view_context(request))
        return Response(serializer.data)

    @transaction.atomic
    def patch(self, request):
        return _singleton_patch(
            SiemElkConfig.get_current(),
            SiemElkConfigSerializer,
            request,
            ELK_AUDIT_FIELDS,
            {"api_key"},
            "elk",
        )


class SiemElkTestView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request):
        instance = SiemElkConfig.get_current()
        serializer = SiemElkConfigSerializer(instance, data=request.data or {}, partial=True)
        serializer.is_valid(raise_exception=True)
        config = _snapshot(instance, ELK_AUDIT_FIELDS)
        config.update(serializer.validated_data)
        result = _run_config_test("settings.siem.elk.test", test_elk_config, config)
        _write_audit(instance, "test", request.user, metadata={"success": result["success"]})
        return Response(result, status=status.HTTP_200_OK)


class LdapConfigView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        instance = LdapConfig.get_current()
        if _singleton_view_context(request)["reveal_secrets"]:
            _write_audit(instance, "reveal", request.user, metadata={"fields": ["bind_password"]})
        serializer = LdapConfigSerializer(instance, context=_singleton_view_context(request))
        return Response(serializer.data)

    @transaction.atomic
    def patch(self, request):
        instance = LdapConfig.get_current()
        before = _snapshot(instance, LDAP_AUDIT_FIELDS)
        serializer = LdapConfigSerializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        changes = _audit_changes(before, _snapshot(instance, LDAP_AUDIT_FIELDS), {"bind_password"})
        if changes:
            _write_audit(instance, "update", request.user, changes=changes)
        transaction.on_commit(lambda: invalidate("ldap"))
        return Response(LdapConfigSerializer(instance).data)


class LdapTestView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request):
        from apps.accounts.ldap import test_ldap_config

        instance = LdapConfig.get_current()
        serializer = LdapConfigSerializer(instance, data=request.data or {}, partial=True)
        serializer.is_valid(raise_exception=True)
        config = _snapshot(instance, LDAP_AUDIT_FIELDS)
        config.update(serializer.validated_data)
        test_username = str(request.data.get("test_username") or "")
        test_password = str(request.data.get("test_password") or "")
        result = _run_config_test(
            "settings.ldap.test",
            lambda data: test_ldap_config(
                data,
                test_username=test_username,
                test_password=test_password,
            ),
            config,
        )
        _write_audit(instance, "test", request.user, metadata={"success": result["success"]})
        return Response(result, status=status.HTTP_200_OK)


class RuntimeConfigView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def get(self, request):
        instance = RuntimeConfig.get_current()
        return Response(RuntimeConfigSerializer(instance).data)

    @transaction.atomic
    def patch(self, request):
        instance = RuntimeConfig.get_current()
        before = _snapshot(instance, RUNTIME_AUDIT_FIELDS)
        serializer = RuntimeConfigSerializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        changes = _audit_changes(before, _snapshot(instance, RUNTIME_AUDIT_FIELDS), set())
        if changes:
            _write_audit(instance, "update", request.user, changes=changes)
        transaction.on_commit(lambda: invalidate("runtime"))
        return Response(RuntimeConfigSerializer(instance).data)
