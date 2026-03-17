from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from PLUGINS.SIEM.models import KeywordSearchInput
from PLUGINS.SIEM.tools import SIEMToolKit
from PLUGINS.SIRP.nocolymodel import Group, Condition, Operator
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpmodel import CaseModel, Severity, CaseStatus, CaseVerdict, Confidence, AttackStage


def get_case(
    case_id: Annotated[str, "Case ID, e.g. case_000005"]
) -> Annotated[Optional[str], "Case as AI-friendly JSON, or None if not found"]:
    """Get one case by ID."""
    model = Case.get_by_id(case_id)
    if not model:
        return None
    result = model.model_dump_json_for_ai()
    return result


def list_cases(
    status: Annotated[Optional[list[CaseStatus]], "Case status filter"] = None,
    severity: Annotated[Optional[list[Severity]], "Case severity filter"] = None,
    confidence: Annotated[Optional[list[Confidence]], "Case confidence filter"] = None,
    limit: Annotated[int, "Max cases to return"] = 10
) -> Annotated[list[str], "Matching cases as AI-friendly JSON list"]:
    """List cases with optional filters."""
    conditions = []

    if status:
        conditions.append(Condition(field="status", operator=Operator.IN, value=status))
    if severity:
        conditions.append(Condition(field="severity", operator=Operator.IN, value=severity))
    if confidence:
        conditions.append(Condition(field="confidence", operator=Operator.IN, value=confidence))

    filter_model = Group(logic="AND", children=conditions) if conditions else Group(logic="AND", children=[])

    models = Case.list(filter_model, lazy_load=True)
    result = []
    for model in models[:limit]:
        result.append(model.model_dump_json_for_ai())
    return result


def update_case(
        case_id: Annotated[str, "Case ID to update"],
        severity: Annotated[Optional[Severity], "Updated analyst severity"] = None,
        status: Annotated[Optional[CaseStatus], "Updated case status"] = None,
        verdict: Annotated[Optional[CaseVerdict], "Updated final verdict"] = None,
        severity_ai: Annotated[Optional[Severity], "Updated AI-assessed severity"] = None,
        confidence_ai: Annotated[Optional[Confidence], "Updated AI-assessed confidence"] = None,
        attack_stage_ai: Annotated[Optional[AttackStage], "Updated AI-assessed attack stage"] = None,
        comment_ai: Annotated[Optional[
            str], "Updated AI comment. Markdown supported"] = None,
        summary_ai: Annotated[Optional[
            str], "Updated AI summary. Markdown supported"] = None
) -> Annotated[Optional[str], "Updated case row ID, or None if not found"]:
    """Update selected fields on a case."""
    case_old = Case.get_by_id(case_id, lazy_load=True)
    if not case_old:
        return None

    case_new = CaseModel()
    case_new.rowid = case_old.rowid
    if severity:
        case_new.severity = severity
    if status:
        case_new.status = status
    if verdict:
        case_new.verdict = verdict
    if severity_ai:
        case_new.severity_ai = severity_ai
    if confidence_ai:
        case_new.confidence_ai = confidence_ai
    if attack_stage_ai:
        case_new.attack_stage_ai = attack_stage_ai
    if comment_ai:
        case_new.comment_ai = comment_ai
    if summary_ai:
        case_new.summary_ai = summary_ai

    return Case.update(case_new)


def siem_keyword_search(
    keyword: Annotated[str | list[str], "Keyword or keyword list; list uses AND matching"],
    time_range_start: Annotated[str, "UTC start time in ISO8601, e.g. 2026-02-04T06:00:00Z"],
    time_range_end: Annotated[str, "UTC end time in ISO8601, e.g. 2026-02-04T07:00:00Z"],
    time_field: Annotated[str, "Time field used for range filtering"] = "@timestamp",
    index_name: Annotated[Optional[str], "Target SIEM index or source; None means all"] = None
) -> Annotated[list[str], "Search hits as JSON strings"]:
    """Search SIEM events by keyword and time range."""
    input_data = KeywordSearchInput(
        keyword=keyword,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        time_field=time_field,
        index_name=index_name
    )
    results = SIEMToolKit.keyword_search(input_data)
    return [item.model_dump_json() for item in results]


def get_current_time(
        time_format: Annotated[
            Optional[str], "Optional Python strftime format. If omitted, returns ISO8601 time with timezone"] = None
) -> Annotated[str, "Current local time string with timezone"]:
    """Get current system time."""
    current_time = datetime.now().astimezone()
    if time_format:
        return current_time.strftime(time_format)
    return current_time.isoformat(timespec="seconds")


if __name__ == "__main__":
    import os

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    import django

    django.setup()
    print(get_current_time())
    time_range_end = datetime.now(timezone.utc)
    time_range_start = time_range_end - timedelta(minutes=10)
    siem_results = siem_keyword_search(
        keyword=["227.174.159.18", "CreateAccessKey"],
        time_range_start=time_range_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        time_range_end=time_range_end.strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    print(siem_results)
    cases = list_cases(limit=1)
    print(cases)
    if cases:
        case = Case.list(Group(logic="AND", children=[]), lazy_load=True)[0]
        result = update_case(
            case_id=case.id,
            status=CaseStatus.IN_PROGRESS,
            verdict=CaseVerdict.SUSPICIOUS,
            severity_ai=Severity.HIGH,
            confidence_ai=Confidence.MEDIUM,
            comment_ai="#### AI Comment\n\nAdditional investigation notes.",
            summary_ai="#### AI Summary\n\nUpdated case summary."
        )
    else:
        result = None
    print(result)
