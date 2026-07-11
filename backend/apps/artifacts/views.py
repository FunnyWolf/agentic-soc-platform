from django.db.models import Count, IntegerField, OuterRef, Subquery, Value
from django.db.models.functions import Coalesce
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions
from rest_framework.filters import OrderingFilter, SearchFilter

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from apps.audit.mixins import AuditActorMixin
from apps.common.advanced_filters import AdvancedFilterBackend
from apps.enrichments.models import Enrichment
from .models import Artifact
from .serializers import ArtifactDetailSerializer, ArtifactListSerializer


class ArtifactViewSet(AuditActorMixin, viewsets.ModelViewSet):
    queryset = Artifact.objects.order_by("-created_at")
    serializer_class = ArtifactDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    lookup_field = "id"
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    search_fields = ("artifact_id", "value", "name", "type", "role")
    ordering_fields = ("created_at", "updated_at", "type", "role")
    filterset_fields = ("type", "role", "alerts__id")
    advanced_filter_fields = {
        "artifact_id": "text",
        "type": "select",
        "role": "select",
        "name": "text",
        "value": "text",
        "created_at": "date",
        "updated_at": "date",
    }

    def annotate_alert_count(self, queryset):
        alert_count = (
            Artifact.alerts.through.objects
            .filter(artifact_id=OuterRef("pk"))
            .order_by()
            .values("artifact_id")
            .annotate(count=Count("alert_id"))
            .values("count")[:1]
        )
        return queryset.annotate(
            alert_count=Coalesce(Subquery(alert_count, output_field=IntegerField()), Value(0))
        )

    def annotate_enrichment_count(self, queryset):
        enrichment_count = (
            Enrichment.objects
            .filter(artifact_id=OuterRef("pk"))
            .order_by()
            .values("artifact_id")
            .annotate(count=Count("id"))
            .values("count")[:1]
        )
        return queryset.annotate(
            enrichment_count=Coalesce(Subquery(enrichment_count, output_field=IntegerField()), Value(0))
        )

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.action == "list":
            queryset = self.annotate_enrichment_count(self.annotate_alert_count(queryset))
        alert_id = self.request.query_params.get("alerts")
        if alert_id:
            queryset = queryset.filter(alerts__id=alert_id)
        return queryset

    def get_serializer_class(self):
        if self.action == "list":
            return ArtifactListSerializer
        return ArtifactDetailSerializer
