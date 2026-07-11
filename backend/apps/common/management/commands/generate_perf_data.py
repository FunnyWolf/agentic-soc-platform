import hashlib
import json
import random
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone

from apps.alerts.models import (
    Alert,
    AlertAction,
    AlertAnalyticState,
    AlertAnalyticType,
    AlertPolicyType,
    AlertRiskLevel,
    AlertStatus,
    AlertTactic,
    Confidence,
    Disposition,
    Impact,
    ProductCategory,
    Severity,
)
from apps.artifacts.models import Artifact, ArtifactName, ArtifactRole, ArtifactType
from apps.audit.models import AuditLog
from apps.cases.models import (
    Case,
    CaseCategory,
    CaseConfidence,
    CaseImpact,
    CasePriority,
    CaseSeverity,
    CaseStatus,
    CaseVerdict,
)
from apps.common.readable_ids import sync_readable_id_sequence
from apps.enrichments.models import Enrichment, EnrichmentProvider, EnrichmentType
from apps.knowledge.models import Knowledge, KnowledgeSource
from apps.playbooks.models import Playbook, PlaybookJobStatus


@dataclass(frozen=True)
class Scale:
    cases: int
    alerts: int
    artifacts: int
    alert_artifact_links: int
    enrichments: int
    playbooks: int
    knowledge: int
    audit_logs: int


SCALES = {
    "tiny": Scale(
        cases=20,
        alerts=200,
        artifacts=100,
        alert_artifact_links=600,
        enrichments=80,
        playbooks=40,
        knowledge=8,
        audit_logs=200,
    ),
    "medium": Scale(
        cases=10_000,
        alerts=100_000,
        artifacts=50_000,
        alert_artifact_links=300_000,
        enrichments=30_000,
        playbooks=10_000,
        knowledge=2_000,
        audit_logs=100_000,
    ),
    "large": Scale(
        cases=100_000,
        alerts=1_000_000,
        artifacts=500_000,
        alert_artifact_links=3_000_000,
        enrichments=250_000,
        playbooks=100_000,
        knowledge=20_000,
        audit_logs=1_000_000,
    ),
    "extreme": Scale(
        cases=1_000_000,
        alerts=10_000_000,
        artifacts=5_000_000,
        alert_artifact_links=30_000_000,
        enrichments=2_500_000,
        playbooks=1_000_000,
        knowledge=200_000,
        audit_logs=10_000_000,
    ),
}

HOT_SEARCH_TOKEN = "perf-hot-auth"
MID_SEARCH_TOKEN = "perf-mid-cloud"
RARE_SEARCH_TOKEN = "perf-rare-000001"
PERF_USER_COUNT = 20


def stable_seed(value):
    return int(hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16], 16)


def run_slug(run_id):
    value = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
    return value[:40] or "perf"


def weighted_choice(rng, choices):
    total = sum(weight for _, weight in choices)
    marker = rng.uniform(0, total)
    upto = 0
    for value, weight in choices:
        upto += weight
        if upto >= marker:
            return value
    return choices[-1][0]


def batched(iterable, size):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def format_readable_id(prefix, number):
    return f"{prefix}_{number:06d}"


def readable_start(model, field_name, prefix):
    marker = f"{prefix}_"
    max_number = 0
    for value in model.objects.exclude(**{field_name: ""}).values_list(field_name, flat=True).iterator(chunk_size=10_000):
        if not value or not value.startswith(marker):
            continue
        suffix = value[len(marker):]
        if suffix.isdigit():
            max_number = max(max_number, int(suffix))
    return max_number + 1


def database_label():
    config = connection.settings_dict
    return (
        f"{config.get('ENGINE')} "
        f"host={config.get('HOST') or 'default'} "
        f"port={config.get('PORT') or 'default'} "
        f"name={config.get('NAME')} "
        f"user={config.get('USER')}"
    )


def random_time_in_last_90_days(rng, now):
    marker = rng.random()
    if marker < 0.05:
        seconds = rng.randint(0, 24 * 60 * 60)
    elif marker < 0.20:
        seconds = rng.randint(24 * 60 * 60, 7 * 24 * 60 * 60)
    elif marker < 0.60:
        seconds = rng.randint(7 * 24 * 60 * 60, 30 * 24 * 60 * 60)
    else:
        seconds = rng.randint(30 * 24 * 60 * 60, 90 * 24 * 60 * 60)
    return now - timedelta(seconds=seconds)


def token_for_index(index):
    if index == 0:
        return RARE_SEARCH_TOKEN
    if index % 17 == 0:
        return MID_SEARCH_TOKEN
    if index % 3 == 0:
        return HOT_SEARCH_TOKEN
    return "perf-normal"


class Command(BaseCommand):
    help = "Generate large deterministic performance-test data for local dedicated PostgreSQL databases."

    def add_arguments(self, parser):
        parser.add_argument("--scale", choices=sorted(SCALES), default="tiny")
        parser.add_argument("--seed", default="20260710")
        parser.add_argument("--run-id", default="")
        parser.add_argument("--batch-size", type=int, default=5_000)
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--reset-perf-data", action="store_true")
        parser.add_argument("--confirm-reset", action="store_true")
        parser.add_argument("--delete-run", default="")

    def handle(self, *args, **options):
        batch_size = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be greater than zero.")

        scale = SCALES[options["scale"]]
        run_id = options["run_id"] or timezone.now().strftime("perf-%Y%m%d%H%M%S")
        rng = random.Random(stable_seed(options["seed"]))

        self.stdout.write(f"Database: {database_label()}")
        self.stdout.write(f"Scale: {options['scale']} {scale}")
        self.stdout.write(f"Run ID: {run_id}")

        if options["delete_run"]:
            self.delete_run(options["delete_run"], dry_run=options["dry_run"])
            return

        if options["reset_perf_data"]:
            if not options["confirm_reset"]:
                raise CommandError("--reset-perf-data requires --confirm-reset.")
            self.reset_perf_data(dry_run=options["dry_run"])

        if options["dry_run"]:
            self.stdout.write(self.style.WARNING("Dry run only. No performance data generated."))
            return

        self.generate(scale=scale, rng=rng, run_id=run_id, batch_size=batch_size)

    def reset_perf_data(self, *, dry_run):
        tables = [
            "audit_logs",
            "enrichments",
            "playbooks",
            "knowledge",
            "alerts",
            "artifacts",
            "cases",
        ]
        statement = f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE"
        if dry_run:
            self.stdout.write(f"Would execute: {statement}")
            return
        with connection.cursor() as cursor:
            cursor.execute(statement)
        self.stdout.write(self.style.WARNING("Reset performance data tables with TRUNCATE ... CASCADE."))

    def delete_run(self, run_id, *, dry_run):
        slug = run_slug(run_id)
        run_tag = f"perf-run:{run_id}"
        artifact_value_pattern = f"%perf-{slug}-%"
        alert_filter = "labels @> %s::jsonb"
        artifact_filter = "value LIKE %s"
        statements = [
            ("audit_logs", "DELETE FROM audit_logs WHERE metadata ->> 'run_id' = %s", [run_id]),
            ("enrichments", "DELETE FROM enrichments WHERE data ->> 'run_id' = %s", [run_id]),
            ("playbooks", "DELETE FROM playbooks WHERE job_id LIKE %s", [f"perf-{slug}-%"]),
            ("knowledge", "DELETE FROM knowledge WHERE tags @> %s::jsonb", [json.dumps([run_tag])]),
            (
                "alerts_artifacts",
                (
                    "DELETE FROM alerts_artifacts WHERE alert_id IN "
                    f"(SELECT id FROM alerts WHERE {alert_filter}) "
                    "OR artifact_id IN "
                    f"(SELECT id FROM artifacts WHERE {artifact_filter})"
                ),
                [json.dumps([run_tag]), artifact_value_pattern],
            ),
            ("alerts", "DELETE FROM alerts WHERE labels @> %s::jsonb", [json.dumps([run_tag])]),
            ("cases", "DELETE FROM cases WHERE tags @> %s::jsonb", [json.dumps([run_tag])]),
            ("artifacts", "DELETE FROM artifacts WHERE value LIKE %s", [artifact_value_pattern]),
        ]
        if dry_run:
            for name, statement, params in statements:
                self.stdout.write(f"Would delete from {name}: {statement} {params}")
            return

        with connection.cursor() as cursor, transaction.atomic():
            for name, statement, params in statements:
                cursor.execute(statement, params)
                self.stdout.write(f"Deleted {cursor.rowcount} rows from {name}.")

    def generate(self, *, scale, rng, run_id, batch_size):
        now = timezone.now()
        slug = run_slug(run_id)
        run_tag = f"perf-run:{run_id}"
        users = self.ensure_perf_users(now)
        user_ids = [user.id for user in users]

        readable_offsets = {
            "case": readable_start(Case, "case_id", "case"),
            "alert": readable_start(Alert, "alert_id", "alert"),
            "artifact": readable_start(Artifact, "artifact_id", "artifact"),
            "enrichment": readable_start(Enrichment, "enrichment_id", "enrichment"),
            "knowledge": readable_start(Knowledge, "knowledge_id", "knowledge"),
            "playbook": readable_start(Playbook, "playbook_id", "playbook"),
        }

        case_ids, case_times = self.create_cases(
            scale=scale,
            rng=rng,
            now=now,
            run_id=run_id,
            run_tag=run_tag,
            readable_offset=readable_offsets["case"],
            user_ids=user_ids,
            batch_size=batch_size,
        )
        artifact_ids = self.create_artifacts(
            scale=scale,
            slug=slug,
            run_tag=run_tag,
            readable_offset=readable_offsets["artifact"],
            batch_size=batch_size,
        )
        alert_ids = self.create_alerts(
            scale=scale,
            rng=rng,
            now=now,
            run_id=run_id,
            run_tag=run_tag,
            case_ids=case_ids,
            case_times=case_times,
            readable_offset=readable_offsets["alert"],
            batch_size=batch_size,
        )
        self.create_alert_artifact_links(
            scale=scale,
            rng=rng,
            alert_ids=alert_ids,
            artifact_ids=artifact_ids,
            batch_size=batch_size,
        )
        self.create_enrichments(
            scale=scale,
            rng=rng,
            now=now,
            run_id=run_id,
            case_ids=case_ids,
            alert_ids=alert_ids,
            artifact_ids=artifact_ids,
            readable_offset=readable_offsets["enrichment"],
            batch_size=batch_size,
        )
        self.create_playbooks(
            scale=scale,
            rng=rng,
            now=now,
            slug=slug,
            case_ids=case_ids,
            user_ids=user_ids,
            readable_offset=readable_offsets["playbook"],
            batch_size=batch_size,
        )
        self.create_knowledge(
            scale=scale,
            now=now,
            run_id=run_id,
            run_tag=run_tag,
            case_ids=case_ids,
            readable_offset=readable_offsets["knowledge"],
            batch_size=batch_size,
        )
        self.create_audit_logs(
            scale=scale,
            rng=rng,
            now=now,
            run_id=run_id,
            case_ids=case_ids,
            alert_ids=alert_ids,
            artifact_ids=artifact_ids,
            user_ids=user_ids,
            batch_size=batch_size,
        )
        self.sync_readable_id_sequences(readable_offsets, scale)

        self.stdout.write(self.style.SUCCESS(f"Generated performance data for run {run_id}."))

    def sync_readable_id_sequences(self, readable_offsets, scale):
        sequence_targets = {
            "case": scale.cases,
            "alert": scale.alerts,
            "artifact": scale.artifacts,
            "enrichment": scale.enrichments,
            "knowledge": min(scale.knowledge, scale.cases),
            "playbook": scale.playbooks,
        }
        for prefix, count in sequence_targets.items():
            if count <= 0:
                continue
            sync_readable_id_sequence(prefix, readable_offsets[prefix] + count - 1)
        self.stdout.write("Synchronized readable ID sequences.")

    def ensure_perf_users(self, now):
        User = get_user_model()
        users = []
        for index in range(PERF_USER_COUNT):
            username = f"perf_user_{index + 1:03d}"
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": f"{username}@perf.local",
                    "first_name": "Perf",
                    "last_name": f"User {index + 1:03d}",
                    "is_active": True,
                    "date_joined": now,
                    "password": "!",
                },
            )
            if created:
                self.stdout.write(f"Created reusable user {username}.")
            users.append(user)
        return users

    def bulk_create(self, model, objects, *, batch_size, label):
        total = 0
        for batch in batched(objects, batch_size):
            model.objects.bulk_create(batch, batch_size=batch_size)
            total += len(batch)
        self.stdout.write(f"Created {total} {label}.")

    def create_cases(self, *, scale, rng, now, run_id, run_tag, readable_offset, user_ids, batch_size):
        case_ids = [uuid.uuid4() for _ in range(scale.cases)]
        case_times = [random_time_in_last_90_days(rng, now) for _ in range(scale.cases)]
        statuses = [
            (CaseStatus.NEW, 30),
            (CaseStatus.IN_PROGRESS, 28),
            (CaseStatus.ON_HOLD, 10),
            (CaseStatus.RESOLVED, 20),
            (CaseStatus.CLOSED, 12),
        ]
        severities = [
            (CaseSeverity.CRITICAL, 4),
            (CaseSeverity.HIGH, 16),
            (CaseSeverity.MEDIUM, 45),
            (CaseSeverity.LOW, 25),
            (CaseSeverity.INFORMATIONAL, 8),
            (CaseSeverity.UNKNOWN, 2),
        ]
        categories = [
            CaseCategory.IAM,
            CaseCategory.EDR,
            CaseCategory.NDR,
            CaseCategory.CLOUD,
            CaseCategory.EMAIL,
            CaseCategory.WAF,
            CaseCategory.DLP,
            CaseCategory.SIEM,
        ]

        def objects():
            for index, case_id in enumerate(case_ids):
                created_at = case_times[index]
                status = weighted_choice(rng, statuses)
                acknowledged_time = None
                closed_time = None
                if status not in {CaseStatus.NEW}:
                    acknowledged_time = created_at + timedelta(minutes=rng.randint(5, 240))
                if status in {CaseStatus.RESOLVED, CaseStatus.CLOSED}:
                    closed_time = (acknowledged_time or created_at) + timedelta(hours=rng.randint(1, 72))
                severity = weighted_choice(rng, severities)
                token = token_for_index(index)
                category = categories[index % len(categories)]
                yield Case(
                    id=case_id,
                    case_id=format_readable_id("case", readable_offset + index),
                    title=f"{token} performance case {index:08d}",
                    severity=severity,
                    impact=weighted_choice(rng, [(CaseImpact.CRITICAL, 5), (CaseImpact.HIGH, 20), (CaseImpact.MEDIUM, 45), (CaseImpact.LOW, 25), (CaseImpact.UNKNOWN, 5)]),
                    priority=weighted_choice(rng, [(CasePriority.CRITICAL, 5), (CasePriority.HIGH, 20), (CasePriority.MEDIUM, 45), (CasePriority.LOW, 25), (CasePriority.UNKNOWN, 5)]),
                    confidence=weighted_choice(rng, [(CaseConfidence.HIGH, 30), (CaseConfidence.MEDIUM, 50), (CaseConfidence.LOW, 15), (CaseConfidence.UNKNOWN, 5)]),
                    description=f"{token} generated database performance case for {run_id}. Scenario {category}.",
                    category=category,
                    tags=[run_tag, token, category.lower()],
                    status=status,
                    verdict=weighted_choice(rng, [(CaseVerdict.UNKNOWN, 35), (CaseVerdict.TRUE_POSITIVE, 30), (CaseVerdict.SUSPICIOUS, 20), (CaseVerdict.FALSE_POSITIVE, 10), (CaseVerdict.SECURITY_RISK, 5)]),
                    summary=f"Performance baseline summary {index:08d}",
                    assignee_id=user_ids[index % len(user_ids)] if user_ids else None,
                    acknowledged_time=acknowledged_time,
                    closed_time=closed_time,
                    correlation_uid=f"perf-corr-{run_id}-{index:08d}",
                    severity_ai=severity,
                    confidence_ai=CaseConfidence.HIGH if index % 4 == 0 else CaseConfidence.MEDIUM,
                    impact_ai=CaseImpact.HIGH if severity in {CaseSeverity.CRITICAL, CaseSeverity.HIGH} else CaseImpact.MEDIUM,
                    priority_ai=CasePriority.HIGH if severity in {CaseSeverity.CRITICAL, CaseSeverity.HIGH} else CasePriority.MEDIUM,
                    verdict_ai=CaseVerdict.SUSPICIOUS if index % 5 == 0 else CaseVerdict.UNKNOWN,
                    investigation_report_ai_json=json.dumps({"run_id": run_id, "index": index, "token": token}),
                    created_at=created_at,
                    updated_at=created_at + timedelta(minutes=rng.randint(0, 120)),
                )

        self.bulk_create(Case, objects(), batch_size=batch_size, label="cases")
        return case_ids, case_times

    def create_artifacts(self, *, scale, slug, run_tag, readable_offset, batch_size):
        artifact_ids = [uuid.uuid4() for _ in range(scale.artifacts)]
        artifact_types = [
            ArtifactType.HOSTNAME,
            ArtifactType.USER_NAME,
            ArtifactType.EMAIL_ADDRESS,
            ArtifactType.URL_STRING,
            ArtifactType.HASH,
            ArtifactType.PROCESS_NAME,
            ArtifactType.RESOURCE_UID,
        ]
        artifact_names = [
            ArtifactName.SOURCE,
            ArtifactName.DESTINATION,
            ArtifactName.ACTOR,
            ArtifactName.TARGET,
            ArtifactName.AFFECTED,
            ArtifactName.RELATED,
        ]
        artifact_roles = [ArtifactRole.ACTOR, ArtifactRole.TARGET, ArtifactRole.AFFECTED, ArtifactRole.RELATED]
        now = timezone.now()

        def value_for(index, type_):
            token = token_for_index(index)
            prefix = f"perf-{slug}-{token}-{index:08d}"
            if type_ == ArtifactType.HOSTNAME:
                return f"{prefix}.corp.local"
            if type_ == ArtifactType.USER_NAME:
                return f"{prefix}-user"
            if type_ == ArtifactType.EMAIL_ADDRESS:
                return f"{prefix}@example.local"
            if type_ == ArtifactType.URL_STRING:
                return f"https://{prefix}.example.local/path"
            if type_ == ArtifactType.HASH:
                return f"{prefix}-{hashlib.sha256(prefix.encode('utf-8')).hexdigest()}"
            if type_ == ArtifactType.PROCESS_NAME:
                return f"{prefix}.exe"
            return f"{prefix}-resource"

        def objects():
            for index, artifact_id in enumerate(artifact_ids):
                type_ = artifact_types[index % len(artifact_types)]
                yield Artifact(
                    id=artifact_id,
                    artifact_id=format_readable_id("artifact", readable_offset + index),
                    name=artifact_names[index % len(artifact_names)],
                    type=type_,
                    role=artifact_roles[index % len(artifact_roles)],
                    value=value_for(index, type_),
                    created_at=now - timedelta(minutes=index % 100_000),
                    updated_at=now - timedelta(minutes=index % 50_000),
                )

        self.bulk_create(Artifact, objects(), batch_size=batch_size, label=f"artifacts tagged {run_tag}")
        return artifact_ids

    def create_alerts(self, *, scale, rng, now, run_id, run_tag, case_ids, case_times, readable_offset, batch_size):
        alert_ids = [uuid.uuid4() for _ in range(scale.alerts)]
        hot_case_count = max(1, scale.cases // 1_000)
        statuses = [
            (AlertStatus.NEW, 35),
            (AlertStatus.IN_PROGRESS, 25),
            (AlertStatus.RESOLVED, 25),
            (AlertStatus.SUPPRESSED, 8),
            (AlertStatus.ARCHIVED, 7),
        ]
        severities = [
            (Severity.CRITICAL, 3),
            (Severity.HIGH, 17),
            (Severity.MEDIUM, 45),
            (Severity.LOW, 27),
            (Severity.INFORMATIONAL, 6),
            (Severity.UNKNOWN, 2),
        ]
        categories = list(ProductCategory)
        tactics = list(AlertTactic)

        def objects():
            for index, alert_id in enumerate(alert_ids):
                if rng.random() < 0.15:
                    case_index = rng.randrange(hot_case_count)
                else:
                    case_index = rng.randrange(scale.cases)
                case_created_at = case_times[case_index]
                first_seen = case_created_at - timedelta(minutes=rng.randint(1, 360))
                last_seen = first_seen + timedelta(minutes=rng.randint(0, 240))
                created_at = case_created_at + timedelta(minutes=rng.randint(0, 30))
                severity = weighted_choice(rng, severities)
                category = categories[index % len(categories)]
                tactic = tactics[index % len(tactics)]
                token = token_for_index(index)
                yield Alert(
                    id=alert_id,
                    alert_id=format_readable_id("alert", readable_offset + index),
                    case_id=case_ids[case_index],
                    title=f"{token} generated alert {index:08d}",
                    severity=severity,
                    confidence=weighted_choice(rng, [(Confidence.HIGH, 30), (Confidence.MEDIUM, 50), (Confidence.LOW, 15), (Confidence.UNKNOWN, 5)]),
                    impact=Impact.HIGH if severity in {Severity.CRITICAL, Severity.HIGH} else Impact.MEDIUM,
                    disposition=weighted_choice(rng, [(Disposition.DETECTED, 40), (Disposition.BLOCKED, 25), (Disposition.ALLOWED, 20), (Disposition.QUARANTINED, 10), (Disposition.UNKNOWN, 5)]),
                    action=weighted_choice(rng, [(AlertAction.OBSERVED, 45), (AlertAction.DENIED, 25), (AlertAction.ALLOWED, 20), (AlertAction.MODIFIED, 5), (AlertAction.UNKNOWN, 5)]),
                    labels=[run_tag, token, category.lower(), tactic.lower().replace(" ", "-")],
                    desc=f"{token} alert description for database read baseline run {run_id}.",
                    first_seen_time=first_seen,
                    last_seen_time=last_seen,
                    rule_id=f"perf-rule-{index % 2_000:04d}",
                    rule_name=f"{token} detection rule {index % 2_000:04d}",
                    correlation_uid=f"perf-corr-{run_id}-{case_index:08d}",
                    src_url=f"https://siem.local/alerts/{alert_id}",
                    source_uid=f"perf-source-{run_id}-{index:08d}",
                    data_sources=[category.lower(), "perf.telemetry"],
                    analytic_name=f"perf analytic {index % 500:03d}",
                    analytic_type=AlertAnalyticType.RULE,
                    analytic_state=AlertAnalyticState.ACTIVE,
                    analytic_desc=f"{token} analytic generated for performance test.",
                    tactic=tactic,
                    technique=f"T{1000 + (index % 500):04d}",
                    sub_technique=f"T{1000 + (index % 500):04d}.{index % 10:03d}",
                    mitigation="Generated mitigation guidance for performance testing.",
                    product_category=category,
                    product_vendor="PerfVendor",
                    product_name=f"PerfProduct-{index % 12}",
                    product_feature=f"Feature-{index % 20}",
                    policy_name=f"Perf policy {index % 100}",
                    policy_type=AlertPolicyType.ACCESS_CONTROL_POLICY,
                    policy_desc="Generated policy text for database performance testing.",
                    risk_level=AlertRiskLevel.CRITICAL if severity == Severity.CRITICAL else AlertRiskLevel.HIGH if severity == Severity.HIGH else AlertRiskLevel.MEDIUM,
                    status=weighted_choice(rng, statuses),
                    status_detail=f"{token} status detail",
                    remediation="Review generated alert and close after benchmark.",
                    unmapped={"run_id": run_id, "token": token, "case_index": case_index, "index": index},
                    raw_data={
                        "run_id": run_id,
                        "event": {"id": str(alert_id), "index": index, "token": token},
                        "network": {"src": f"10.{index % 255}.{(index // 255) % 255}.{index % 254 + 1}", "dst": f"172.16.{index % 255}.{index % 254 + 1}"},
                        "process": {"name": f"perf-process-{index % 200}.exe", "pid": index % 65535},
                        "message": f"{token} generated raw payload for database read performance baseline.",
                    },
                    created_at=created_at,
                    updated_at=created_at + timedelta(minutes=rng.randint(0, 180)),
                )

        self.bulk_create(Alert, objects(), batch_size=batch_size, label="alerts")
        return alert_ids

    def create_alert_artifact_links(self, *, scale, rng, alert_ids, artifact_ids, batch_size):
        through = Alert.artifacts.through
        hot_artifact_count = max(1, scale.artifacts // 5_000)

        def objects():
            for alert_index, alert_id in enumerate(alert_ids):
                link_count = 1 + (alert_index % 5)
                used = set()
                for link_index in range(link_count):
                    if rng.random() < 0.20:
                        artifact_index = rng.randrange(hot_artifact_count)
                    else:
                        artifact_index = rng.randrange(scale.artifacts)
                    while artifact_index in used:
                        artifact_index = (artifact_index + 1) % scale.artifacts
                    used.add(artifact_index)
                    yield through(alert_id=alert_id, artifact_id=artifact_ids[artifact_index])

        self.bulk_create(through, objects(), batch_size=batch_size, label="alert-artifact links")

    def create_enrichments(self, *, scale, rng, now, run_id, case_ids, alert_ids, artifact_ids, readable_offset, batch_size):
        enrichment_types = [
            EnrichmentType.THREAT_INTELLIGENCE,
            EnrichmentType.CMDB,
            EnrichmentType.REPUTATION,
            EnrichmentType.IDENTITY,
            EnrichmentType.BEHAVIOR,
        ]
        providers = [
            EnrichmentProvider.MOCK,
            EnrichmentProvider.INTERNAL_CMDB,
            EnrichmentProvider.ASP,
            EnrichmentProvider.SPLUNK,
            EnrichmentProvider.ELASTIC,
        ]

        def objects():
            for index in range(scale.enrichments):
                target_type = index % 3
                case_id = case_ids[rng.randrange(scale.cases)] if target_type == 0 else None
                alert_id = alert_ids[rng.randrange(scale.alerts)] if target_type == 1 else None
                artifact_id = artifact_ids[rng.randrange(scale.artifacts)] if target_type == 2 else None
                token = token_for_index(index)
                created_at = random_time_in_last_90_days(rng, now)
                yield Enrichment(
                    id=uuid.uuid4(),
                    enrichment_id=format_readable_id("enrichment", readable_offset + index),
                    name=f"{token} enrichment {index:08d}",
                    type=enrichment_types[index % len(enrichment_types)],
                    provider=providers[index % len(providers)],
                    uid=f"perf:{run_id}:{index:08d}",
                    value=f"{token}:value:{index:08d}",
                    desc=f"{token} generated enrichment for performance benchmark.",
                    data={"run_id": run_id, "token": token, "score": index % 100, "source": "perf-generator"},
                    case_id=case_id,
                    alert_id=alert_id,
                    artifact_id=artifact_id,
                    created_at=created_at,
                    updated_at=created_at + timedelta(minutes=index % 240),
                )

        self.bulk_create(Enrichment, objects(), batch_size=batch_size, label="enrichments")

    def create_playbooks(self, *, scale, rng, now, slug, case_ids, user_ids, readable_offset, batch_size):
        names = ["Investigation", "Knowledge Extraction", "Threat Intelligence Enrichment", "CMDB Enrichment"]
        statuses = [
            (PlaybookJobStatus.SUCCESS, 55),
            (PlaybookJobStatus.FAILED, 10),
            (PlaybookJobStatus.PENDING, 20),
            (PlaybookJobStatus.RUNNING, 15),
        ]

        def objects():
            for index in range(scale.playbooks):
                created_at = random_time_in_last_90_days(rng, now)
                token = token_for_index(index)
                yield Playbook(
                    id=uuid.uuid4(),
                    playbook_id=format_readable_id("playbook", readable_offset + index),
                    case_id=case_ids[rng.randrange(scale.cases)],
                    name=names[index % len(names)],
                    user_input=f"{token} generated playbook input",
                    user_id=user_ids[index % len(user_ids)] if user_ids else None,
                    job_status=weighted_choice(rng, statuses),
                    job_id=f"perf-{slug}-{index:08d}",
                    remark=f"{token} generated playbook remark",
                    created_at=created_at,
                    updated_at=created_at + timedelta(minutes=index % 180),
                )

        self.bulk_create(Playbook, objects(), batch_size=batch_size, label="playbooks")

    def create_knowledge(self, *, scale, now, run_id, run_tag, case_ids, readable_offset, batch_size):
        linked_count = min(scale.knowledge, len(case_ids))

        def objects():
            for index in range(linked_count):
                created_at = now - timedelta(hours=index % (90 * 24))
                token = token_for_index(index)
                yield Knowledge(
                    id=uuid.uuid4(),
                    knowledge_id=format_readable_id("knowledge", readable_offset + index),
                    title=f"{token} knowledge {index:08d}",
                    body=f"{token} generated knowledge body for database performance run {run_id}.",
                    expires_at=None if index % 5 else now + timedelta(days=30),
                    source=KnowledgeSource.CASE,
                    tags=[run_tag, token, "perf-knowledge"],
                    case_id=case_ids[index],
                    created_at=created_at,
                    updated_at=created_at + timedelta(minutes=index % 120),
                )

        self.bulk_create(Knowledge, objects(), batch_size=batch_size, label="knowledge records")

    def create_audit_logs(self, *, scale, rng, now, run_id, case_ids, alert_ids, artifact_ids, user_ids, batch_size):
        content_types = {
            "case": ContentType.objects.get_for_model(Case).id,
            "alert": ContentType.objects.get_for_model(Alert).id,
            "artifact": ContentType.objects.get_for_model(Artifact).id,
        }
        resources = [
            ("case", case_ids),
            ("alert", alert_ids),
            ("artifact", artifact_ids),
        ]
        actions = [("create", 50), ("update", 40), ("delete", 10)]

        def objects():
            for index in range(scale.audit_logs):
                resource_name, resource_ids = resources[index % len(resources)]
                object_id = resource_ids[rng.randrange(len(resource_ids))]
                token = token_for_index(index)
                created_at = random_time_in_last_90_days(rng, now)
                yield AuditLog(
                    content_type_id=content_types[resource_name],
                    object_id=str(object_id),
                    action=weighted_choice(rng, actions),
                    actor_id=user_ids[index % len(user_ids)] if user_ids and index % 7 else None,
                    changes={"status": {"from": "New", "to": "In Progress"}, "token": token},
                    metadata={"run_id": run_id, "perf": True, "resource": resource_name, "token": token},
                    created_at=created_at,
                )

        self.bulk_create(AuditLog, objects(), batch_size=batch_size, label="audit logs")
