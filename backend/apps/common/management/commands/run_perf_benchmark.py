import json
import math
import re
import time
from pathlib import Path
from types import SimpleNamespace

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, reset_queries
from django.db.models import CharField, Count, DateTimeField, IntegerField, OuterRef, Q, Subquery, Value
from django.db.models.functions import Cast, Coalesce, Concat
from django.utils import timezone

from apps.alerts.models import Alert
from apps.artifacts.models import Artifact
from apps.audit.models import AuditLog
from apps.cases.models import Case
from apps.common.cursor_pagination import paginate_created_at_cursor
from apps.dashboard.views import build_dashboard_overview
from apps.playbooks.models import Playbook


HOT_SEARCH_TOKEN = "perf-hot-auth"
MID_SEARCH_TOKEN = "perf-mid-cloud"
RARE_SEARCH_TOKEN = "perf-rare-000001"


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil((pct / 100) * len(ordered)) - 1))
    return ordered[index]


def duration_stats(values):
    if not values:
        return {"min_ms": None, "avg_ms": None, "p95_ms": None, "max_ms": None}
    return {
        "min_ms": round(min(values), 2),
        "avg_ms": round(sum(values) / len(values), 2),
        "p95_ms": round(percentile(values, 95), 2),
        "max_ms": round(max(values), 2),
    }


def database_label():
    config = connection.settings_dict
    return {
        "engine": config.get("ENGINE"),
        "host": config.get("HOST") or "default",
        "port": config.get("PORT") or "default",
        "name": str(config.get("NAME")),
        "user": str(config.get("USER")),
    }


class Command(BaseCommand):
    help = "Run ORM-level smoke benchmarks against database read paths."

    def add_arguments(self, parser):
        parser.add_argument("--iterations", type=int, default=3)
        parser.add_argument("--warmup", type=int, default=1)
        parser.add_argument("--page-size", type=int, default=100)
        parser.add_argument("--deep-offset", type=int, default=10_000)
        parser.add_argument("--run-id", default="")
        parser.add_argument("--output-dir", default="")

    def handle(self, *args, **options):
        if options["iterations"] < 1:
            raise CommandError("--iterations must be greater than zero.")
        if options["warmup"] < 0:
            raise CommandError("--warmup cannot be negative.")
        if options["page_size"] < 1:
            raise CommandError("--page-size must be greater than zero.")
        if options["deep_offset"] < 0:
            raise CommandError("--deep-offset cannot be negative.")

        started_at = timezone.now()
        scenarios = self.scenarios(page_size=options["page_size"], deep_offset=options["deep_offset"])
        results = []

        self.stdout.write(f"Database: {database_label()}")
        self.stdout.write(f"Running {len(scenarios)} scenarios, iterations={options['iterations']}, warmup={options['warmup']}")

        for name, func in scenarios:
            result = self.measure(
                name,
                func,
                iterations=options["iterations"],
                warmup=options["warmup"],
            )
            results.append(result)
            if result.get("error"):
                self.stdout.write(self.style.ERROR(f"{name}: ERROR {result['error']}"))
            else:
                stats = result["duration"]
                self.stdout.write(
                    f"{name}: avg={stats['avg_ms']}ms p95={stats['p95_ms']}ms "
                    f"queries={result['query_count_avg']} rows={result['result_count']}"
                )

        payload = {
            "run_id": options["run_id"] or "",
            "started_at": started_at.isoformat(),
            "finished_at": timezone.now().isoformat(),
            "database": database_label(),
            "options": {
                "iterations": options["iterations"],
                "warmup": options["warmup"],
                "page_size": options["page_size"],
                "deep_offset": options["deep_offset"],
            },
            "results": results,
        }
        output_path = self.write_results(payload, output_dir=options["output_dir"], run_id=options["run_id"])
        self.stdout.write(self.style.SUCCESS(f"Wrote benchmark results to {output_path}"))

    def measure(self, name, func, *, iterations, warmup):
        try:
            for _ in range(warmup):
                func()

            durations = []
            query_counts = []
            result_count = None
            old_force_debug = connection.force_debug_cursor
            connection.force_debug_cursor = True
            try:
                for _ in range(iterations):
                    reset_queries()
                    started = time.perf_counter()
                    result_count = func()
                    durations.append((time.perf_counter() - started) * 1000)
                    query_counts.append(len(connection.queries))
            finally:
                connection.force_debug_cursor = old_force_debug
                reset_queries()

            return {
                "name": name,
                "duration": duration_stats(durations),
                "query_count_min": min(query_counts) if query_counts else None,
                "query_count_avg": round(sum(query_counts) / len(query_counts), 2) if query_counts else None,
                "query_count_max": max(query_counts) if query_counts else None,
                "result_count": result_count,
                "error": "",
            }
        except Exception as exc:  # noqa: BLE001 - benchmark records scenario failures and continues.
            return {
                "name": name,
                "duration": duration_stats([]),
                "query_count_min": None,
                "query_count_avg": None,
                "query_count_max": None,
                "result_count": None,
                "error": f"{type(exc).__name__}: {exc}",
            }

    def scenarios(self, *, page_size, deep_offset):
        def case_queryset():
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
            return Case.objects.select_related("assignee").annotate(
                alert_count=Coalesce(Subquery(alert_count, output_field=IntegerField()), Value(0)),
                playbook_count=Coalesce(Subquery(playbook_count, output_field=IntegerField()), Value(0)),
                first_alert_seen_time=Subquery(first_alert_seen_time, output_field=DateTimeField()),
            ).order_by("-created_at")

        def alert_queryset():
            return Alert.objects.select_related("case").prefetch_related("artifacts").order_by("-created_at")

        def artifact_queryset():
            alert_count = (
                Artifact.alerts.through.objects
                .filter(artifact_id=OuterRef("pk"))
                .order_by()
                .values("artifact_id")
                .annotate(count=Count("alert_id"))
                .values("count")[:1]
            )
            return Artifact.objects.annotate(
                alert_count=Coalesce(Subquery(alert_count, output_field=IntegerField()), Value(0))
            ).order_by("-created_at")

        def admin_audit_queryset():
            return AuditLog.objects.select_related("actor", "content_type").annotate(
                changes_text=Cast("changes", output_field=CharField()),
                metadata_text=Cast("metadata", output_field=CharField()),
                actor_display=Concat(
                    Coalesce("actor__first_name", Value("")),
                    Value(" "),
                    Coalesce("actor__last_name", Value("")),
                    output_field=CharField(),
                ),
            ).order_by("-created_at", "-id")

        def list_count(queryset):
            return len(list(queryset[:page_size]))

        def cursor_count(queryset):
            request = SimpleNamespace(query_params={"page_size": str(min(page_size, 100))})
            page = paginate_created_at_cursor(queryset, request)
            return len(page.results)

        return [
            ("cases.default_page", lambda: list_count(case_queryset())),
            ("cases.deep_page", lambda: list_count(case_queryset()[deep_offset:deep_offset + page_size])),
            ("cases.filter_status_severity", lambda: list_count(case_queryset().filter(status__in=["New", "In Progress"], severity__in=["High", "Critical"]))),
            ("cases.search_hot", lambda: list_count(case_queryset().filter(Q(case_id__icontains=HOT_SEARCH_TOKEN) | Q(title__icontains=HOT_SEARCH_TOKEN) | Q(description__icontains=HOT_SEARCH_TOKEN) | Q(summary__icontains=HOT_SEARCH_TOKEN) | Q(correlation_uid__icontains=HOT_SEARCH_TOKEN)))),
            ("cases.search_rare", lambda: list_count(case_queryset().filter(Q(title__icontains=RARE_SEARCH_TOKEN) | Q(description__icontains=RARE_SEARCH_TOKEN)))),
            ("alerts.default_page", lambda: list_count(alert_queryset())),
            ("alerts.filter_status_severity", lambda: list_count(alert_queryset().filter(status__in=["New", "In Progress"], severity__in=["High", "Critical"]))),
            ("alerts.filter_product_risk", lambda: list_count(alert_queryset().filter(product_category="IAM", risk_level__in=["High", "Critical"]))),
            ("alerts.order_first_seen", lambda: list_count(alert_queryset().order_by("-first_seen_time", "-id"))),
            ("alerts.search_hot", lambda: list_count(alert_queryset().filter(Q(alert_id__icontains=HOT_SEARCH_TOKEN) | Q(title__icontains=HOT_SEARCH_TOKEN) | Q(desc__icontains=HOT_SEARCH_TOKEN) | Q(rule_name__icontains=HOT_SEARCH_TOKEN) | Q(source_uid__icontains=HOT_SEARCH_TOKEN)))),
            ("alerts.search_rare", lambda: list_count(alert_queryset().filter(Q(title__icontains=RARE_SEARCH_TOKEN) | Q(rule_name__icontains=RARE_SEARCH_TOKEN)))),
            ("artifacts.default_page", lambda: list_count(artifact_queryset())),
            ("artifacts.filter_type_role", lambda: list_count(artifact_queryset().filter(type="Hostname", role__in=["Actor", "Target"]))),
            ("artifacts.search_hot", lambda: list_count(artifact_queryset().filter(Q(artifact_id__icontains=HOT_SEARCH_TOKEN) | Q(value__icontains=HOT_SEARCH_TOKEN) | Q(name__icontains=HOT_SEARCH_TOKEN) | Q(type__icontains=HOT_SEARCH_TOKEN) | Q(role__icontains=HOT_SEARCH_TOKEN)))),
            ("artifacts.search_rare", lambda: list_count(artifact_queryset().filter(value__icontains=RARE_SEARCH_TOKEN))),
            ("dashboard.24h", lambda: len(build_dashboard_overview("24h"))),
            ("dashboard.7d", lambda: len(build_dashboard_overview("7d"))),
            ("dashboard.30d", lambda: len(build_dashboard_overview("30d"))),
            ("audit.default_page", lambda: list_count(admin_audit_queryset())),
            ("audit.filter_action_actor", lambda: list_count(admin_audit_queryset().filter(action="update", actor__isnull=False))),
            ("audit.search_hot", lambda: list_count(admin_audit_queryset().filter(Q(action__icontains=HOT_SEARCH_TOKEN) | Q(object_id__icontains=HOT_SEARCH_TOKEN) | Q(content_type__model__icontains=HOT_SEARCH_TOKEN) | Q(actor__username__icontains=HOT_SEARCH_TOKEN) | Q(changes_text__icontains=HOT_SEARCH_TOKEN) | Q(metadata_text__icontains=HOT_SEARCH_TOKEN)))),
            ("cursor.cases", lambda: cursor_count(Case.objects.all())),
            ("cursor.alerts", lambda: cursor_count(Alert.objects.select_related("case"))),
            ("cursor.artifacts", lambda: cursor_count(Artifact.objects.all())),
        ]

    def write_results(self, payload, *, output_dir, run_id):
        base_dir = Path(output_dir) if output_dir else Path(settings.BASE_DIR) / "perf-results"
        base_dir.mkdir(parents=True, exist_ok=True)
        timestamp = timezone.now().strftime("%Y%m%d%H%M%S")
        run_part = re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id).strip("-") if run_id else "benchmark"
        path = base_dir / f"{timestamp}-{run_part}.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path
