import hashlib

from django.db import connection, transaction
from django.utils import timezone

from apps.agentic.models import AgenticJobStatus, CaseAnalysisJob

CASE_ANALYSIS_RESULT_FIELDS = [
    "verdict_ai",
    "severity_ai",
    "impact_ai",
    "priority_ai",
    "confidence_ai",
    "investigation_report_ai_json",
]


def _case_analysis_lock_id(case_pk):
    raw_key = str(case_pk)
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=False) & ((1 << 63) - 1)


def _lock_case_analysis(case):
    lock_id = _case_analysis_lock_id(case.pk)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [lock_id])


@transaction.atomic
def request_case_analysis(*, case, trigger, scheduled_at=None):
    _lock_case_analysis(case)
    existing = (
        CaseAnalysisJob.objects.select_for_update()
        .filter(case=case, status=AgenticJobStatus.PENDING)
        .order_by("scheduled_at", "created_at")
        .first()
    )
    if existing:
        return existing

    return CaseAnalysisJob.objects.create(
        case=case,
        trigger=trigger,
        scheduled_at=scheduled_at or timezone.now(),
    )


@transaction.atomic
def start_case_analysis_job(job):
    locked = CaseAnalysisJob.objects.select_for_update().get(pk=job.pk)
    if locked.status != AgenticJobStatus.PENDING:
        raise ValueError(f"CaseAnalysisJob must be Pending before start, got {locked.status}")
    locked.status = AgenticJobStatus.RUNNING
    locked.started_at = timezone.now()
    locked.error = ""
    locked.save(update_fields=["status", "started_at", "error", "updated_at"])
    return locked


@transaction.atomic
def save_case_analysis_record(*, case, record):
    """Persist the full AnalysisRecord and its denormalized Case AI fields."""
    locked_case = case.__class__.objects.select_for_update().get(pk=case.pk)
    report = record.report
    locked_case.verdict_ai = report.verdict
    locked_case.severity_ai = report.severity
    locked_case.impact_ai = report.impact
    locked_case.priority_ai = report.priority
    locked_case.confidence_ai = report.confidence
    locked_case.investigation_report_ai_json = record.model_dump_json()
    locked_case.full_clean()
    locked_case.save(update_fields=[*CASE_ANALYSIS_RESULT_FIELDS, "updated_at"])
    return locked_case


@transaction.atomic
def complete_case_analysis_job(job, *, result_json):
    locked = CaseAnalysisJob.objects.select_for_update().get(pk=job.pk)
    if locked.status != AgenticJobStatus.RUNNING:
        raise ValueError(f"CaseAnalysisJob must be Running before complete, got {locked.status}")

    locked.status = AgenticJobStatus.SUCCESS
    locked.completed_at = timezone.now()
    locked.result_json = result_json
    locked.error = ""
    locked.save(update_fields=["status", "completed_at", "result_json", "error", "updated_at"])
    return locked


@transaction.atomic
def fail_case_analysis_job(job, error):
    locked = CaseAnalysisJob.objects.select_for_update().get(pk=job.pk)
    if locked.status == AgenticJobStatus.SUCCESS:
        raise ValueError("CaseAnalysisJob cannot be failed after success")
    if locked.status != job.status:
        raise ValueError(f"CaseAnalysisJob status changed from {job.status} to {locked.status}")
    locked.status = AgenticJobStatus.FAILED
    locked.completed_at = timezone.now()
    locked.error = str(error)
    locked.save(update_fields=["status", "completed_at", "error", "updated_at"])
    return locked
