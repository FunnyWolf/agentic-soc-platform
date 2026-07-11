from rest_framework import serializers

from .models import Alert


class AlertDetailSerializer(serializers.ModelSerializer):
    case_id = serializers.CharField(source="case.id", read_only=True)
    case_readable_id = serializers.CharField(source="case.case_id", read_only=True)
    case_title = serializers.CharField(source="case.title", read_only=True)
    case_status = serializers.CharField(source="case.status", read_only=True)
    case_category = serializers.CharField(source="case.category", read_only=True)

    class Meta:
        model = Alert
        fields = (
            "id",
            "alert_id",
            "case",
            "case_id",
            "case_readable_id",
            "case_title",
            "case_status",
            "case_category",
            "title",
            "severity",
            "confidence",
            "impact",
            "disposition",
            "action",
            "labels",
            "desc",
            "first_seen_time",
            "last_seen_time",
            "rule_id",
            "rule_name",
            "correlation_uid",
            "src_url",
            "source_uid",
            "data_sources",
            "analytic_name",
            "analytic_type",
            "analytic_state",
            "analytic_desc",
            "tactic",
            "technique",
            "sub_technique",
            "mitigation",
            "product_category",
            "product_vendor",
            "product_name",
            "product_feature",
            "policy_name",
            "policy_type",
            "policy_desc",
            "risk_level",
            "status",
            "status_detail",
            "remediation",
            "unmapped",
            "raw_data",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "alert_id", "created_at", "updated_at")


class AlertListSerializer(AlertDetailSerializer):
    artifact_count = serializers.IntegerField(read_only=True, default=0)
    enrichment_count = serializers.IntegerField(read_only=True, default=0)

    class Meta(AlertDetailSerializer.Meta):
        fields = (
            "id",
            "alert_id",
            "case",
            "case_id",
            "case_readable_id",
            "case_title",
            "case_status",
            "case_category",
            "title",
            "severity",
            "confidence",
            "impact",
            "disposition",
            "action",
            "labels",
            "desc",
            "first_seen_time",
            "last_seen_time",
            "rule_id",
            "rule_name",
            "correlation_uid",
            "src_url",
            "source_uid",
            "data_sources",
            "analytic_name",
            "analytic_type",
            "analytic_state",
            "analytic_desc",
            "tactic",
            "technique",
            "sub_technique",
            "mitigation",
            "product_category",
            "product_vendor",
            "product_name",
            "product_feature",
            "policy_name",
            "policy_type",
            "policy_desc",
            "risk_level",
            "status",
            "status_detail",
            "remediation",
            "artifact_count",
            "enrichment_count",
            "created_at",
            "updated_at",
        )
