from django.db.models import Count, DateTimeField, IntegerField, OuterRef, Subquery, Value
from django.db.models.functions import Coalesce
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from apps.alerts.models import Alert
from apps.audit.context import audit_actor
from apps.audit.mixins import AuditActorMixin
from apps.common.advanced_filters import AdvancedFilterBackend
from apps.enrichments.models import Enrichment
from apps.playbooks.models import Playbook
from .models import Case
from .serializers import CaseDetailSerializer, CaseListSerializer


class CaseViewSet(AuditActorMixin, viewsets.ModelViewSet):
    queryset = Case.objects.select_related("assignee").order_by("-created_at")
    serializer_class = CaseDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    lookup_field = "id"
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    search_fields = ("case_id", "title", "description", "summary", "correlation_uid")
    ordering_fields = (
        "created_at",
        "updated_at",
        "acknowledged_time",
        "closed_time",
        "severity",
        "severity_ai",
        "priority",
        "priority_ai",
        "status",
        "confidence",
        "confidence_ai",
        "impact",
        "impact_ai",
        "verdict",
        "verdict_ai",
    )
    filterset_fields = (
        "status",
        "severity",
        "priority",
        "category",
        "confidence",
        "impact",
        "verdict",
        "assignee",
    )
    advanced_filter_fields = {
        "case_id": "text",
        "title": "text",
        "status": "select",
        "category": "select",
        "severity": "select",
        "assignee": "user",
        "verdict": "select",
        "priority": "select",
        "confidence": "select",
        "impact": "select",
        "tags": "tag",
        "acknowledged_time": "date",
        "closed_time": "date",
        "created_at": "date",
        "updated_at": "date",
        "description": "text",
        "summary": "text",
        "correlation_uid": "text",
    }

    def annotate_list_metrics(self, queryset):
        alert_count = (
            Alert.objects
            .filter(case_id=OuterRef("pk"))
            .order_by()
            .values("case_id")
            .annotate(count=Count("id"))
            .values("count")[:1]
        )
        playbook_count = (
            Playbook.objects
            .filter(case_id=OuterRef("pk"))
            .order_by()
            .values("case_id")
            .annotate(count=Count("id"))
            .values("count")[:1]
        )
        first_alert_seen_time = (
            Alert.objects
            .filter(case_id=OuterRef("pk"), first_seen_time__isnull=False)
            .order_by("first_seen_time")
            .values("first_seen_time")[:1]
        )
        enrichment_count = (
            Enrichment.objects
            .filter(case_id=OuterRef("pk"))
            .order_by()
            .values("case_id")
            .annotate(count=Count("id"))
            .values("count")[:1]
        )
        return queryset.annotate(
            alert_count=Coalesce(Subquery(alert_count, output_field=IntegerField()), Value(0)),
            playbook_count=Coalesce(Subquery(playbook_count, output_field=IntegerField()), Value(0)),
            enrichment_count=Coalesce(Subquery(enrichment_count, output_field=IntegerField()), Value(0)),
            first_alert_seen_time=Subquery(first_alert_seen_time, output_field=DateTimeField()),
        )

    def annotate_detail_metrics(self, queryset):
        first_alert_seen_time = (
            Alert.objects
            .filter(case_id=OuterRef("pk"), first_seen_time__isnull=False)
            .order_by("first_seen_time")
            .values("first_seen_time")[:1]
        )
        return queryset.annotate(
            first_alert_seen_time=Subquery(first_alert_seen_time, output_field=DateTimeField()),
        )

    def get_queryset(self):
        if self.action == "list":
            return self.annotate_list_metrics(super().get_queryset()).defer("investigation_report_ai_json")
        if self.action in {"retrieve", "update", "partial_update"}:
            return self.annotate_detail_metrics(super().get_queryset()).defer("investigation_report_ai_json")
        return super().get_queryset()

    def get_serializer_class(self):
        if self.action == "list":
            return CaseListSerializer
        return CaseDetailSerializer

    @action(detail=True, methods=["get", "patch"], url_path="investigation")
    def investigation(self, request, *args, **kwargs):
        case = self.get_object()
        if request.method == "PATCH":
            value = request.data.get("investigation_report_ai_json", "")
            with audit_actor(request.user):
                case.investigation_report_ai_json = value
                case.save(update_fields=["investigation_report_ai_json", "updated_at"])
        return Response({
            "id": str(case.id),
            "case_id": case.case_id,
            "investigation_report_ai_json": case.investigation_report_ai_json,
        })
