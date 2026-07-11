import re
from collections import Counter
from datetime import timedelta

from django.db import connection
from django.db.models import Case as DbCase, Count, DateTimeField, FloatField, Min, Q, Sum, Value, When
from django.db.models.functions import Coalesce, TruncDay, TruncHour
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.alerts.models import Alert, AlertStatus, AlertTactic
from apps.artifacts.models import Artifact
from apps.cases.models import Case, CaseStatus
from apps.enrichments.models import Enrichment
from apps.knowledge.models import Knowledge, KnowledgeSource
from apps.playbooks.models import Playbook, PlaybookJobStatus


WINDOW_DELTAS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

OPEN_CASE_STATUSES = (CaseStatus.NEW, CaseStatus.IN_PROGRESS, CaseStatus.ON_HOLD)
ACTIVE_ALERT_STATUSES = (AlertStatus.NEW, AlertStatus.IN_PROGRESS)
ACTIVE_PLAYBOOK_STATUSES = (PlaybookJobStatus.RUNNING, PlaybookJobStatus.FAILED)
IMPORTANT_LEVELS = ("Critical", "High")

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational", "Info", "Unknown")
CASE_STATUS_ORDER = ("New", "In Progress", "On Hold", "Resolved", "Closed")
PLAYBOOK_STATUS_ORDER = ("Success", "Failed", "Pending", "Running")
SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 6,
    "Medium": 3,
    "Low": 1,
    "Informational": 0.5,
    "Info": 0.5,
}
KEYWORD_STOP_WORDS = {
    "and",
    "for",
    "from",
    "the",
    "with",
    "after",
    "before",
    "followed",
    "indicators",
    "pattern",
    "alert",
    "case",
    "mock",
    "unknown",
}
KEYWORD_AGGREGATION_LIMIT = 120


def iso_datetime(value):
    return value.isoformat() if value else None


def percentage(numerator, denominator):
    if denominator == 0:
        return None
    return round((numerator / denominator) * 100, 1)


def severity_weight(value):
    return SEVERITY_WEIGHTS.get(value or "", 0)


def mean_duration_result(row):
    seconds, sample_count = row or (None, 0)
    return {
        "seconds": int(seconds) if seconds is not None and sample_count else None,
        "sample_count": sample_count or 0,
    }


def alert_event_queryset(start):
    return Alert.objects.annotate(
        event_time=Coalesce(
            "last_seen_time",
            "first_seen_time",
            "created_at",
            output_field=DateTimeField(),
        )
    ).filter(event_time__gte=start)


def case_workload_queryset(start):
    return Case.objects.filter(
        Q(status__in=OPEN_CASE_STATUSES)
        | Q(created_at__gte=start)
        | Q(updated_at__gte=start)
        | Q(acknowledged_time__gte=start)
        | Q(closed_time__gte=start)
    ).distinct()


def ordered_distribution(queryset, field, labels):
    rows = queryset.order_by().values(field).annotate(value=Count("id"))
    counts = {
        row[field] or "Unknown": row["value"]
        for row in rows
    }
    return [{"label": label, "value": counts.get(label, 0)} for label in labels]


def top_distribution(queryset, field, limit=8):
    return [
        {"label": row[field], "value": row["value"]}
        for row in queryset.exclude(**{field: ""})
        .values(field)
        .annotate(value=Count("id"))
        .order_by("-value", field)[:limit]
    ]


def add_keyword(counter, value, weight=1, split=False):
    if value in (None, ""):
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            add_keyword(counter, item, weight=weight, split=split)
        return

    text = re.sub(r"\s+", " ", str(value).strip())
    if not text:
        return

    if split:
        for token in re.findall(r"[A-Za-z][A-Za-z0-9+._-]{2,}", text):
            normalized = token.strip("._-").lower()
            if len(normalized) >= 3 and normalized not in KEYWORD_STOP_WORDS:
                counter[normalized] += weight
        return

    normalized = text.lower()
    if len(normalized) >= 3 and normalized not in KEYWORD_STOP_WORDS:
        counter[text] += weight


def keyword_weight(value):
    return max(1, int(severity_weight(value) or 1))


def category_keyword_weight(value):
    return max(1, keyword_weight(value) // 2)


def weighted_severity_sum(queryset, multiplier=1):
    severity_score = DbCase(
        *[
            When(severity=severity, then=Value(float(weight) * multiplier))
            for severity, weight in SEVERITY_WEIGHTS.items()
        ],
        default=Value(0.0),
        output_field=FloatField(),
    )
    return queryset.aggregate(total=Sum(severity_score))["total"] or 0


def add_grouped_keywords(counter, queryset, field, weight_function):
    for row in queryset.exclude(**{field: ""}).values(field, "severity").annotate(count=Count("id")).order_by():
        add_keyword(counter, row[field], weight=row["count"] * weight_function(row["severity"]))


def add_title_tokens(counter, queryset, field):
    sql, params = queryset.order_by().values(field).query.sql_with_params()
    stop_words = list(KEYWORD_STOP_WORDS)
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT token, COUNT(*) AS value
            FROM (
                SELECT lower(trim(both '._-' FROM raw_token.value)) AS token
                FROM ({sql}) AS source
                CROSS JOIN LATERAL regexp_split_to_table(source.{field}, '[^A-Za-z0-9+._-]+') AS raw_token(value)
            ) AS tokens
            WHERE length(token) >= 3
              AND token ~ '^[a-z][a-z0-9+._-]*$'
              AND NOT (token = ANY(%s))
            GROUP BY token
            ORDER BY value DESC, token
            LIMIT %s
            """,
            [*params, stop_words, KEYWORD_AGGREGATION_LIMIT],
        )
        for token, value in cursor.fetchall():
            counter[token] += value


def add_json_array_keywords(counter, queryset, field):
    sql, params = queryset.order_by().values(field, "severity").query.sql_with_params()
    severity_cases = " ".join(
        "WHEN severity = %s THEN %s"
        for _severity, _weight in SEVERITY_WEIGHTS.items()
    )
    severity_params = [
        item
        for severity, weight in SEVERITY_WEIGHTS.items()
        for item in (severity, keyword_weight(severity))
    ]
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT value, SUM(weight) AS score
            FROM (
                SELECT
                    jsonb_array_elements_text(source.{field}) AS value,
                    CASE {severity_cases} ELSE 1 END AS weight
                FROM ({sql}) AS source
            ) AS tokens
            WHERE value <> ''
            GROUP BY value
            ORDER BY score DESC, value
            LIMIT %s
            """,
            [*severity_params, *params, KEYWORD_AGGREGATION_LIMIT],
        )
        for value, score in cursor.fetchall():
            add_keyword(counter, value, weight=score)


def build_threat_keywords(window_cases, window_alerts):
    counter = Counter()

    add_title_tokens(counter, window_alerts, "title")
    add_json_array_keywords(counter, window_alerts, "labels")
    add_grouped_keywords(counter, window_alerts, "tactic", keyword_weight)
    add_grouped_keywords(counter, window_alerts, "technique", keyword_weight)
    add_grouped_keywords(counter, window_alerts, "product_category", category_keyword_weight)
    add_grouped_keywords(counter, window_alerts, "product_name", lambda _severity: 1)

    add_title_tokens(counter, window_cases, "title")
    add_json_array_keywords(counter, window_cases, "tags")
    add_grouped_keywords(counter, window_cases, "category", category_keyword_weight)

    return [
        {"text": text, "value": value}
        for text, value in counter.most_common(36)
    ]


def build_mitre_severity_heatmap(window_alerts):
    tactics = [tactic.value for tactic in AlertTactic]
    severity_labels = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")

    rows = window_alerts.filter(tactic__in=tactics).order_by().values(
        "tactic",
        "severity",
    ).annotate(value=Count("id"))
    counts = {
        (row["tactic"], row["severity"] or "Unknown"): row["value"]
        for row in rows
    }

    return [
        {
            "tactic": tactic,
            "severity": severity,
            "value": counts.get((tactic, severity), 0),
        }
        for severity in severity_labels
        for tactic in tactics
    ]


def build_alert_trend(window, start, generated_at):
    trunc = TruncHour if window == "24h" else TruncDay
    event_queryset = alert_event_queryset(start)
    rows = event_queryset.annotate(
        bucket=trunc("event_time")
    ).values("bucket").annotate(value=Count("id")).order_by("bucket")

    if window == "24h":
        bucket_count = 24
        step = timedelta(hours=1)
        first_bucket = generated_at.replace(minute=0, second=0, microsecond=0) - step * (bucket_count - 1)
        label_format = "%H:%M"
    else:
        bucket_count = 7 if window == "7d" else 30
        step = timedelta(days=1)
        first_bucket = generated_at.replace(hour=0, minute=0, second=0, microsecond=0) - step * (bucket_count - 1)
        label_format = "%m-%d"

    counts = {row["bucket"].strftime(label_format): row["value"] for row in rows}
    trend = []
    for index in range(bucket_count):
        bucket = first_bucket + step * index
        label = bucket.strftime(label_format)
        trend.append({
            "time": iso_datetime(bucket),
            "label": label,
            "value": counts.get(label, 0),
        })
    return trend


def build_mean_times(start):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT ROUND(EXTRACT(EPOCH FROM AVG(created_at - first_alert_seen_time)))::int, COUNT(*)::int
            FROM (
                SELECT cases.id, cases.created_at, MIN(alerts.first_seen_time) AS first_alert_seen_time
                FROM cases
                LEFT JOIN alerts ON alerts.case_id = cases.id
                WHERE cases.created_at >= %s
                GROUP BY cases.id, cases.created_at
            ) AS detected_cases
            WHERE first_alert_seen_time IS NOT NULL
              AND created_at >= first_alert_seen_time
            """,
            [start],
        )
        mttd = mean_duration_result(cursor.fetchone())

        cursor.execute(
            """
            SELECT ROUND(EXTRACT(EPOCH FROM AVG(acknowledged_time - created_at)))::int, COUNT(*)::int
            FROM cases
            WHERE acknowledged_time >= %s
              AND acknowledged_time IS NOT NULL
              AND acknowledged_time >= created_at
            """,
            [start],
        )
        mtta = mean_duration_result(cursor.fetchone())

        cursor.execute(
            """
            SELECT ROUND(EXTRACT(EPOCH FROM AVG(closed_time - acknowledged_time)))::int, COUNT(*)::int
            FROM cases
            WHERE closed_time >= %s
              AND closed_time IS NOT NULL
              AND acknowledged_time IS NOT NULL
              AND closed_time >= acknowledged_time
            """,
            [start],
        )
        mttr = mean_duration_result(cursor.fetchone())

    return {
        "mttd": mttd,
        "mtta": mtta,
        "mttr": mttr,
    }


def build_active_risk_index(window_cases, window_alerts, window_playbooks):
    case_score = weighted_severity_sum(window_cases.filter(status__in=OPEN_CASE_STATUSES), multiplier=2)
    alert_score = weighted_severity_sum(window_alerts.filter(status__in=ACTIVE_ALERT_STATUSES))
    playbook_score = (
        window_playbooks.filter(job_status=PlaybookJobStatus.FAILED).count() * 4
        + window_playbooks.filter(job_status=PlaybookJobStatus.RUNNING).count()
    )
    return min(100, round(case_score + alert_score + playbook_score))


def build_top_risk_artifacts(window_alerts):
    severity_score = DbCase(
        *[
            When(alert__severity=severity, then=Value(float(weight)))
            for severity, weight in SEVERITY_WEIGHTS.items()
        ],
        default=Value(0.0),
        output_field=FloatField(),
    )
    rows = (
        Alert.artifacts.through.objects
        .filter(alert_id__in=window_alerts.order_by().values("id"))
        .values(
            "artifact_id",
            "artifact__name",
            "artifact__type",
            "artifact__role",
            "artifact__value",
        )
        .annotate(
            risk_score=Sum(severity_score),
            alert_count=Count("alert_id"),
        )
        .order_by("-risk_score", "-alert_count", "-artifact__value")[:8]
    )
    return [
        {
            "id": str(row["artifact_id"]),
            "name": row["artifact__name"],
            "type": row["artifact__type"],
            "role": row["artifact__role"],
            "value": row["artifact__value"],
            "risk_score": round(row["risk_score"] or 0, 1),
            "alert_count": row["alert_count"],
        }
        for row in rows
    ]


def build_recent_highlights(window_cases, window_alerts):
    highlights = []
    for case in window_cases.filter(
        Q(severity__in=IMPORTANT_LEVELS) | Q(priority__in=IMPORTANT_LEVELS)
    ).order_by("-created_at")[:8]:
        highlights.append({
            "id": str(case.id),
            "kind": "case",
            "readable_id": case.case_id,
            "title": case.title,
            "severity": case.severity,
            "status": case.status,
            "timestamp": case.created_at,
            "subtitle": case.category or "Case",
        })

    for alert in window_alerts.filter(
        Q(severity__in=IMPORTANT_LEVELS) | Q(risk_level__in=IMPORTANT_LEVELS)
    ).order_by("-event_time")[:8]:
        highlights.append({
            "id": str(alert.id),
            "kind": "alert",
            "readable_id": alert.alert_id,
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "timestamp": alert.event_time,
            "subtitle": alert.tactic or alert.product_category or alert.product_name or "Alert",
        })

    highlights.sort(key=lambda item: item["timestamp"], reverse=True)
    return [
        {
            **item,
            "timestamp": iso_datetime(item["timestamp"]),
        }
        for item in highlights[:8]
    ]


def build_dashboard_overview(window):
    generated_at = timezone.now()
    start = generated_at - WINDOW_DELTAS[window]

    window_cases = Case.objects.filter(created_at__gte=start)
    workload_cases = case_workload_queryset(start)
    open_cases = Case.objects.filter(status__in=OPEN_CASE_STATUSES)
    window_alerts = alert_event_queryset(start)
    window_playbooks = Playbook.objects.filter(created_at__gte=start)

    playbook_status_counts = {
        row["job_status"] or "Unknown": row["value"]
        for row in window_playbooks.values("job_status").annotate(value=Count("id"))
    }
    successful_playbooks = playbook_status_counts.get(PlaybookJobStatus.SUCCESS, 0)
    failed_playbooks = playbook_status_counts.get(PlaybookJobStatus.FAILED, 0)
    completed_playbooks = successful_playbooks + failed_playbooks

    total_cases = window_cases.count()
    cases_with_enrichments = window_cases.filter(enrichments__isnull=False).distinct().count()
    cases_with_playbooks = window_cases.filter(playbooks__isnull=False).distinct().count()

    summary = {
        "active_risk_index": build_active_risk_index(open_cases, window_alerts, window_playbooks),
        "total_cases": total_cases,
        "total_alerts": window_alerts.count(),
        "total_artifacts": Artifact.objects.filter(alerts__in=window_alerts).distinct().count(),
        "total_enrichments": Enrichment.objects.filter(created_at__gte=start).count(),
        "total_knowledge": Knowledge.objects.filter(created_at__gte=start).count(),
        "open_cases": open_cases.count(),
        "open_critical_cases": open_cases.filter(severity="Critical").count(),
        "critical_high_alerts": window_alerts.filter(severity__in=IMPORTANT_LEVELS).count(),
        "running_playbooks": playbook_status_counts.get(PlaybookJobStatus.RUNNING, 0),
        "failed_playbooks": failed_playbooks,
        "automation_success_rate": percentage(successful_playbooks, completed_playbooks),
    }

    coverage = {
        "enrichment_coverage": percentage(cases_with_enrichments, total_cases),
        "playbook_coverage": percentage(cases_with_playbooks, total_cases),
        "knowledge_records": Knowledge.objects.filter(created_at__gte=start, source=KnowledgeSource.CASE).count(),
        "artifact_records": summary["total_artifacts"],
        "enrichment_records": summary["total_enrichments"],
    }

    automation = [
        {"label": label, "value": playbook_status_counts.get(label, 0)}
        for label in PLAYBOOK_STATUS_ORDER
    ]

    return {
        "window": window,
        "window_start": iso_datetime(start),
        "generated_at": iso_datetime(generated_at),
        "summary": summary,
        "mean_times": build_mean_times(start),
        "alert_trend": build_alert_trend(window, start, generated_at),
        "severity_distribution": ordered_distribution(window_alerts, "severity", SEVERITY_ORDER),
        "case_status_mix": ordered_distribution(workload_cases, "status", CASE_STATUS_ORDER),
        "product_category_distribution": top_distribution(window_alerts, "product_category"),
        "mitre_tactics": top_distribution(window_alerts, "tactic"),
        "mitre_severity_heatmap": build_mitre_severity_heatmap(window_alerts),
        "threat_keywords": build_threat_keywords(workload_cases, window_alerts),
        "automation": automation,
        "coverage": coverage,
        "top_risk_artifacts": build_top_risk_artifacts(window_alerts),
        "recent_highlights": build_recent_highlights(workload_cases, window_alerts),
    }


class DashboardOverviewView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        window = request.query_params.get("window", "7d")
        if window not in WINDOW_DELTAS:
            return Response(
                {"window": [f"Unsupported window. Use one of: {', '.join(WINDOW_DELTAS)}."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(build_dashboard_overview(window))
