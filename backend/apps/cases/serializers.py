from django.utils import timezone
from rest_framework import serializers

from apps.inbox.notifications import notify_case_assignment
from .models import Case, CaseStatus


class CaseDetailSerializer(serializers.ModelSerializer):
    assignee_name = serializers.SerializerMethodField()
    first_alert_seen_time = serializers.SerializerMethodField()
    detection_time_seconds = serializers.SerializerMethodField()
    acknowledgement_time_seconds = serializers.SerializerMethodField()
    response_time_seconds = serializers.SerializerMethodField()

    def _get_user_name(self, user):
        if not user:
            return ""
        return user.get_full_name() or user.username

    def get_assignee_name(self, obj):
        return self._get_user_name(obj.assignee)

    def _duration_seconds(self, start, end):
        if not start or not end:
            return None
        return int((end - start).total_seconds())

    def _first_alert_seen_time(self, obj):
        annotated_value = getattr(obj, "first_alert_seen_time", None)
        if annotated_value is not None:
            return annotated_value
        return obj.alerts.filter(first_seen_time__isnull=False).order_by("first_seen_time").values_list("first_seen_time", flat=True).first()

    def get_first_alert_seen_time(self, obj):
        value = self._first_alert_seen_time(obj)
        if value is None:
            return None
        return serializers.DateTimeField().to_representation(value)

    def get_detection_time_seconds(self, obj):
        return self._duration_seconds(self._first_alert_seen_time(obj), obj.created_at)

    def get_acknowledgement_time_seconds(self, obj):
        return self._duration_seconds(obj.created_at, obj.acknowledged_time)

    def get_response_time_seconds(self, obj):
        return self._duration_seconds(obj.acknowledged_time, obj.closed_time)

    def update(self, instance, validated_data):
        previous_assignee_id = instance.assignee_id
        previous_status = instance.status or ""
        next_status = validated_data.get("status", previous_status) or ""
        status_changed = next_status != previous_status
        now = timezone.now()

        if (
            status_changed
            and previous_status in ("", CaseStatus.NEW)
            and next_status != CaseStatus.NEW
            and not instance.acknowledged_time
            and "acknowledged_time" not in validated_data
        ):
            validated_data["acknowledged_time"] = now

        if (
            status_changed
            and next_status == CaseStatus.CLOSED
            and not instance.closed_time
            and "closed_time" not in validated_data
        ):
            validated_data["closed_time"] = now

        updated = super().update(instance, validated_data)
        request = self.context.get("request")
        actor = getattr(request, "user", None) if request else None
        notify_case_assignment(updated, previous_assignee_id=previous_assignee_id, actor=actor)
        return updated

    class Meta:
        model = Case
        fields = (
            "id",
            "case_id",
            "title",
            "severity",
            "impact",
            "priority",
            "confidence",
            "description",
            "category",
            "tags",
            "status",
            "verdict",
            "summary",
            "assignee",
            "assignee_name",
            "acknowledged_time",
            "closed_time",
            "correlation_uid",
            "severity_ai",
            "confidence_ai",
            "impact_ai",
            "priority_ai",
            "verdict_ai",
            "first_alert_seen_time",
            "detection_time_seconds",
            "acknowledgement_time_seconds",
            "response_time_seconds",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "case_id", "created_at", "updated_at")


class CaseListSerializer(CaseDetailSerializer):
    alert_count = serializers.IntegerField(read_only=True, default=0)
    playbook_count = serializers.IntegerField(read_only=True, default=0)
    enrichment_count = serializers.IntegerField(read_only=True, default=0)

    class Meta(CaseDetailSerializer.Meta):
        fields = (
            "id",
            "case_id",
            "title",
            "severity",
            "impact",
            "priority",
            "confidence",
            "description",
            "category",
            "tags",
            "status",
            "verdict",
            "summary",
            "assignee",
            "assignee_name",
            "acknowledged_time",
            "closed_time",
            "correlation_uid",
            "severity_ai",
            "confidence_ai",
            "impact_ai",
            "priority_ai",
            "verdict_ai",
            "alert_count",
            "playbook_count",
            "enrichment_count",
            "first_alert_seen_time",
            "detection_time_seconds",
            "acknowledgement_time_seconds",
            "response_time_seconds",
            "created_at",
            "updated_at",
        )
