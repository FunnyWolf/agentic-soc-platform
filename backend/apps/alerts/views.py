from django.db.models import Count, IntegerField, OuterRef, Subquery, Value
from django.db.models.functions import Coalesce
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions
from rest_framework.filters import OrderingFilter, SearchFilter

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from apps.audit.mixins import AuditActorMixin
from apps.common.advanced_filters import AdvancedFilterBackend
from apps.enrichments.models import Enrichment
from .models import Alert
from .serializers import AlertDetailSerializer, AlertListSerializer


class AlertViewSet(AuditActorMixin, viewsets.ModelViewSet):
    queryset = Alert.objects.select_related("case").order_by("-created_at")
    serializer_class = AlertDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    lookup_field = "id"
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    search_fields = (
        "alert_id",
        "title",
        "desc",
        "rule_id",
        "rule_name",
        "correlation_uid",
        "source_uid",
        "product_vendor",
        "product_name",
        "product_feature",
        "tactic",
        "technique",
        "status_detail",
        "remediation",
    )
    ordering_fields = (
        "created_at",
        "updated_at",
        "severity",
        "confidence",
        "impact",
        "status",
        "disposition",
        "action",
        "risk_level",
        "first_seen_time",
        "last_seen_time",
    )
    filterset_fields = (
        "status",
        "severity",
        "confidence",
        "impact",
        "disposition",
        "action",
        "product_category",
        "risk_level",
        "case__id",
        "artifacts__id",
    )
    advanced_filter_fields = {
        "alert_id": "text",
        "title": "text",
        "severity": "select",
        "confidence": "select",
        "impact": "select",
        "status": "select",
        "disposition": "select",
        "action": "select",
        "risk_level": "select",
        "product_category": "select",
        "product_vendor": "text",
        "product_name": "text",
        "rule_id": "text",
        "rule_name": "text",
        "correlation_uid": "text",
        "source_uid": "text",
        "labels": "tag",
        "first_seen_time": "date",
        "last_seen_time": "date",
        "created_at": "date",
    }

    def annotate_list_counts(self, queryset):
        artifact_count = (
            Alert.artifacts.through.objects
            .filter(alert_id=OuterRef("pk"))
            .order_by()
            .values("alert_id")
            .annotate(count=Count("artifact_id"))
            .values("count")[:1]
        )
        queryset = queryset.annotate(
            artifact_count=Coalesce(Subquery(artifact_count, output_field=IntegerField()), Value(0))
        )

        enrichment_count = (
            Enrichment.objects
            .filter(alert_id=OuterRef("pk"))
            .order_by()
            .values("alert_id")
            .annotate(count=Count("id"))
            .values("count")[:1]
        )
        return queryset.annotate(
            enrichment_count=Coalesce(Subquery(enrichment_count, output_field=IntegerField()), Value(0))
        )

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.action == "list":
            queryset = self.annotate_list_counts(queryset)
        artifact_id = self.request.query_params.get("artifacts")
        if artifact_id:
            queryset = queryset.filter(artifacts__id=artifact_id)
        return queryset

    def get_serializer_class(self):
        if self.action == "list":
            return AlertListSerializer
        return AlertDetailSerializer
