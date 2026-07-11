from datetime import date, datetime
from uuid import UUID

from django.contrib.contenttypes.models import ContentType

from apps.audit.models import AuditLog
from apps.comments.models import Comment
from apps.enrichments.models import Enrichment

AI_SCHEMA_KEY = "ai"
AI_PROFILE_INVESTIGATION = "investigation"
AI_PROFILE_AGENT = "agent"
AI_PROFILE_VERSION = "2026-06-20"
AUDIT_LOG_LIMIT = 100
CASE_AI_AUDIT_FIELDS = {
    "severity_ai",
    "confidence_ai",
    "impact_ai",
    "priority_ai",
    "verdict_ai",
    "investigation_report_ai_json",
}

AI_FIELD_PROFILES = {
    "cases.Case": {
        AI_PROFILE_INVESTIGATION: [
            "created_at",
            "updated_at",
            "title",
            "severity",
            "impact",
            "priority",
            "confidence",
            "description",
            "category",
            "tags",
            "status",
            "acknowledged_time",
            "assignee",
            "closed_time",
            "verdict",
            "summary",
            "alerts",
            "enrichments",
            "comments",
            "audit_logs",
        ],
        AI_PROFILE_AGENT: [
            "id",
            "case_id",
            "created_at",
            "updated_at",
            "title",
            "severity",
            "impact",
            "priority",
            "confidence",
            "description",
            "category",
            "tags",
            "correlation_uid",
            "status",
            "assignee",
            "closed_time",
            "verdict",
            "summary",
            "alerts",
            "enrichments",
        ],
    },
    "alerts.Alert": {
        AI_PROFILE_INVESTIGATION: [
            "created_at",
            "updated_at",
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
            "analytic_name",
            "analytic_type",
            "analytic_state",
            "analytic_desc",
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
            "artifacts",
            "enrichments",
        ],
        AI_PROFILE_AGENT: [
            "id",
            "alert_id",
            "created_at",
            "updated_at",
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
            "artifacts",
            "enrichments",
        ],
    },
    "artifacts.Artifact": {
        AI_PROFILE_INVESTIGATION: [
            "created_at",
            "updated_at",
            "name",
            "type",
            "role",
            "value",
            "enrichments",
        ],
        AI_PROFILE_AGENT: [
            "id",
            "artifact_id",
            "created_at",
            "updated_at",
            "name",
            "type",
            "role",
            "value",
            "enrichments",
        ],
    },
    "enrichments.Enrichment": {
        AI_PROFILE_INVESTIGATION: [
            "created_at",
            "updated_at",
            "name",
            "type",
            "provider",
            "value",
            "desc",
        ],
        AI_PROFILE_AGENT: [
            "id",
            "enrichment_id",
            "created_at",
            "updated_at",
            "name",
            "type",
            "provider",
            "value",
            "desc",
        ],
    },
    "knowledge.Knowledge": {
        AI_PROFILE_AGENT: [
            "id",
            "knowledge_id",
            "created_at",
            "updated_at",
            "title",
            "body",
            "expires_at",
            "source",
            "tags",
        ],
    },
}


def get_profile_fields(model_label, profile):
    model_profiles = AI_FIELD_PROFILES[model_label]
    return tuple(model_profiles[profile])


def _model_label(obj):
    return obj._meta.label


def _serialize_scalar(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def _serialize_json_value(value):
    if isinstance(value, dict):
        return {str(key): _serialize_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize_json_value(item) for item in value]
    return _serialize_scalar(value)


def _serialize_user(user):
    if not user:
        return ""
    return user.get_full_name() or user.username


def _serialize_comment(comment):
    return {
        "created_at": _serialize_scalar(comment.created_at),
        "updated_at": _serialize_scalar(comment.updated_at),
        "author": _serialize_user(comment.author),
        "body": comment.body,
    }


def _serialize_audit_log(log):
    return {
        "created_at": _serialize_scalar(log.created_at),
        "action": log.action,
        "actor": _serialize_user(log.actor),
        "changes": _serialize_json_value(log.changes or {}),
        "metadata": _serialize_json_value(log.metadata or {}),
    }


def _enrichments_for(obj):
    model_name = obj._meta.model_name
    if model_name in {"case", "alert", "artifact"}:
        return Enrichment.objects.filter(**{model_name: obj}).order_by("created_at")
    return Enrichment.objects.none()


def _comments_for(obj):
    content_type = ContentType.objects.get_for_model(obj)
    return (
        Comment.objects.filter(content_type=content_type, object_id=obj.pk)
        .select_related("author")
        .order_by("created_at")
    )


def _audit_logs_for(obj):
    content_type = ContentType.objects.get_for_model(obj)
    logs = (
        AuditLog.objects.filter(content_type=content_type, object_id=str(obj.pk))
        .select_related("actor")
        .order_by("-created_at")[:AUDIT_LOG_LIMIT]
    )
    return reversed(list(logs))


def _serialize_case_alerts(case, profile):
    return [serialize_for_ai(alert, profile) for alert in case.alerts.all().order_by("created_at")]


def _serialize_artifacts(obj, profile):
    return [serialize_for_ai(artifact, profile) for artifact in obj.artifacts.all().order_by("created_at")]


def _serialize_enrichments(obj, profile):
    return [serialize_for_ai(enrichment, profile) for enrichment in _enrichments_for(obj)]


def _serialize_comments(obj, profile):
    return [_serialize_comment(comment) for comment in _comments_for(obj)]


def _serialize_audit_logs(obj, profile):
    return [_serialize_audit_log(log) for log in _audit_logs_for(obj)]


def _serialize_case_audit_log(log):
    data = _serialize_audit_log(log)
    data["changes"] = {
        field_name: change
        for field_name, change in data["changes"].items()
        if field_name not in CASE_AI_AUDIT_FIELDS
    }
    return data


def _serialize_case_audit_logs(obj, profile):
    audit_logs = []
    for log in _audit_logs_for(obj):
        serialized_log = _serialize_case_audit_log(log)
        if log.action == "update" and not serialized_log["changes"] and not serialized_log["metadata"]:
            continue
        audit_logs.append(serialized_log)
    return audit_logs


AI_RELATION_FIELD_SERIALIZERS = {
    ("cases.Case", "alerts"): _serialize_case_alerts,
    ("cases.Case", "enrichments"): _serialize_enrichments,
    ("cases.Case", "comments"): _serialize_comments,
    ("cases.Case", "audit_logs"): _serialize_case_audit_logs,
    ("alerts.Alert", "artifacts"): _serialize_artifacts,
    ("alerts.Alert", "enrichments"): _serialize_enrichments,
    ("artifacts.Artifact", "enrichments"): _serialize_enrichments,
}

AI_SCALAR_FIELD_SERIALIZERS = {
    "assignee": _serialize_user,
}


def _serialize_profile_field(obj, field_name, profile):
    model_label = _model_label(obj)
    if relation_serializer := AI_RELATION_FIELD_SERIALIZERS.get((model_label, field_name)):
        return relation_serializer(obj, profile)

    value = getattr(obj, field_name)
    if scalar_serializer := AI_SCALAR_FIELD_SERIALIZERS.get(field_name):
        return scalar_serializer(value)
    return _serialize_scalar(value)


def serialize_for_ai(obj, profile):
    fields = get_profile_fields(_model_label(obj), profile)
    return {field_name: _serialize_profile_field(obj, field_name, profile) for field_name in fields}


def serialize_case_for_investigation(case):
    return serialize_for_ai(case, AI_PROFILE_INVESTIGATION)
