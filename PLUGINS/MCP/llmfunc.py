import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from Lib.playbookloader import PlaybookLoader
from PLUGINS.SIEM.models import AdaptiveQueryInput, KeywordSearchInput, SchemaExplorerInput
from PLUGINS.SIEM.tools import SIEMToolKit
from PLUGINS.SIRP.nocolymodel import Group, Condition, Operator
from PLUGINS.SIRP.sirpapi import Alert, Artifact, Case, Enrichment, Knowledge, Playbook, Ticket
from PLUGINS.SIRP.sirpmodel import ArtifactModel, ArtifactReputationScore, ArtifactRole, ArtifactType, AlertStatus, EnrichmentModel, Severity, \
    CaseStatus, CaseVerdict, Confidence, \
    AttackStage, KnowledgeAction, KnowledgeSource, PlaybookJobStatus, PlaybookType, TicketStatus, TicketType, TicketModel


def _build_filter_group(conditions: list[Condition]) -> Group:
    return Group(logic="AND", children=conditions or [])


def _dump_models_for_ai(models, limit: int) -> list[str]:
    return [model.model_dump_json_for_ai() for model in models[:limit]]


# Case
def list_cases(
    case_id: Annotated[Optional[str], "Case ID, e.g. case_000005"] = None,
        status: Annotated[Optional[list[CaseStatus]], "Case status filter"] = None,
        severity: Annotated[Optional[list[Severity]], "Case severity filter"] = None,
        confidence: Annotated[Optional[list[Confidence]], "Case confidence filter"] = None,
        verdict: Annotated[Optional[list[CaseVerdict]], "Case verdict filter"] = None,
        correlation_uid: Annotated[Optional[str], "Case correlation UID filter"] = None,
        title: Annotated[Optional[str], "Fuzzy case title filter"] = None,
        tags: Annotated[Optional[list[str]], "Case tag filter"] = None,
        limit: Annotated[int, "Max cases to return"] = 10
) -> Annotated[list[str], "Matching cases as AI-friendly JSON list"]:
    """List cases with optional filters."""
    conditions = []
    if case_id:
        conditions.append(Condition(field="id", operator=Operator.EQ, value=case_id))
    if status:
        conditions.append(Condition(field="status", operator=Operator.IN, value=status))
    if severity:
        conditions.append(Condition(field="severity", operator=Operator.IN, value=severity))
    if confidence:
        conditions.append(Condition(field="confidence", operator=Operator.IN, value=confidence))
    if verdict:
        conditions.append(Condition(field="verdict", operator=Operator.IN, value=verdict))
    if correlation_uid:
        conditions.append(Condition(field="correlation_uid", operator=Operator.EQ, value=correlation_uid))
    if title:
        conditions.append(Condition(field="title", operator=Operator.CONTAINS, value=title))
    if tags:
        conditions.append(Condition(field="tags", operator=Operator.CONTAINS, value=tags))

    filter_model = _build_filter_group(conditions)
    models = Case.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def get_case_discussions(
        case_id: Annotated[str, "Case ID, e.g. case_000005"]
) -> Annotated[Optional[list[str]], "Case discussions as JSON list, or None if case not found"]:
    """Get case discussions by case ID."""
    discussions = Case.get_discussions(case_id)
    if discussions is None:
        return None
    return [json.dumps(item, ensure_ascii=False) for item in discussions]


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
    return Case.update_by_id(
        case_id=case_id,
        severity=severity,
        status=status,
        verdict=verdict,
        severity_ai=severity_ai,
        confidence_ai=confidence_ai,
        attack_stage_ai=attack_stage_ai,
        comment_ai=comment_ai,
        summary_ai=summary_ai
    )


# Alert
def list_alerts(
    alert_id: Annotated[Optional[str], "Alert ID, e.g. alert_000001"] = None,
        status: Annotated[Optional[list[AlertStatus]], "Alert status filter"] = None,
        severity: Annotated[Optional[list[Severity]], "Alert severity filter"] = None,
        confidence: Annotated[Optional[list[Confidence]], "Alert confidence filter"] = None,
        correlation_uid: Annotated[Optional[str], "Alert correlation UID filter"] = None,
        limit: Annotated[int, "Max alerts to return"] = 10
) -> Annotated[list[str], "Matching alerts as AI-friendly JSON list"]:
    """List alerts with optional filters."""
    conditions = []

    if alert_id:
        conditions.append(Condition(field="id", operator=Operator.EQ, value=alert_id))
    if status:
        conditions.append(Condition(field="status", operator=Operator.IN, value=status))
    if severity:
        conditions.append(Condition(field="severity", operator=Operator.IN, value=severity))
    if confidence:
        conditions.append(Condition(field="confidence", operator=Operator.IN, value=confidence))
    if correlation_uid:
        conditions.append(Condition(field="correlation_uid", operator=Operator.EQ, value=correlation_uid))

    filter_model = _build_filter_group(conditions)
    models = Alert.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def get_alert_discussions(
        alert_id: Annotated[str, "Alert ID, e.g. alert_000001"]
) -> Annotated[Optional[list[str]], "Alert discussions as JSON list, or None if alert not found"]:
    """Get alert discussions by alert ID."""
    discussions = Alert.get_discussions(alert_id)
    if discussions is None:
        return None
    return [json.dumps(item, ensure_ascii=False) for item in discussions]


def update_alert(
        alert_id: Annotated[str, "Alert ID to update"],
        severity_ai: Annotated[Optional[Severity], "Updated AI-assessed severity"] = None,
        confidence_ai: Annotated[Optional[Confidence], "Updated AI-assessed confidence"] = None,
        comment_ai: Annotated[Optional[str], "Updated AI comment. Markdown supported"] = None
) -> Annotated[Optional[str], "Updated alert row ID, or None if not found"]:
    """Update selected AI fields on an alert."""
    return Alert.update_by_id(
        alert_id=alert_id,
        severity_ai=severity_ai,
        confidence_ai=confidence_ai,
        comment_ai=comment_ai
    )


# Artifact

def create_artifact(
        name: Annotated[str, "Artifact name"] = "",
        type: Annotated[Optional[ArtifactType], "Artifact type"] = None,
        role: Annotated[Optional[ArtifactRole], "Artifact role"] = None,
        owner: Annotated[str, "Artifact owner"] = "",
        value: Annotated[str, "Artifact value"] = "",
        reputation_provider: Annotated[str, "Threat intel provider"] = "",
        reputation_score: Annotated[Optional[ArtifactReputationScore], "Artifact reputation score"] = None
) -> Annotated[str, "Created artifact record row ID"]:
    """Create one artifact record."""
    model = ArtifactModel()
    model.name = name
    model.type = type
    model.role = role
    model.owner = owner
    model.value = value
    model.reputation_provider = reputation_provider
    model.reputation_score = reputation_score
    return Artifact.create(model)


def attach_artifact_to_alert(
    alert_id: Annotated[str, "Target alert ID to receive the existing artifact"],
    artifact_rowid: Annotated[str, "Artifact record row ID returned by create_artifact"]
) -> Annotated[Optional[str], "Attached artifact record row ID, or None if alert not found"]:
    """Attach one existing artifact record to an existing alert."""
    return Alert.attach_artifact(
        alert_id=alert_id,
        artifact_rowid=artifact_rowid
    )


def list_artifacts(
    artifact_id: Annotated[Optional[str], "Artifact ID, e.g. artifact_000001"] = None,
        type: Annotated[Optional[list[ArtifactType]], "Artifact type filter"] = None,
        role: Annotated[Optional[list[ArtifactRole]], "Artifact role filter"] = None,
        reputation_score: Annotated[Optional[list[ArtifactReputationScore]], "Artifact reputation filter"] = None,
        owner: Annotated[Optional[str], "Artifact owner filter"] = None,
        value: Annotated[Optional[str], "Exact artifact value filter"] = None,
        limit: Annotated[int, "Max artifacts to return"] = 10
) -> Annotated[list[str], "Matching artifacts as AI-friendly JSON list"]:
    """List artifacts with optional filters."""
    conditions = []
    if artifact_id:
        conditions.append(Condition(field="id", operator=Operator.EQ, value=artifact_id))
    if type:
        conditions.append(Condition(field="type", operator=Operator.IN, value=type))
    if role:
        conditions.append(Condition(field="role", operator=Operator.IN, value=role))
    if reputation_score:
        conditions.append(Condition(field="reputation_score", operator=Operator.IN, value=reputation_score))
    if owner:
        conditions.append(Condition(field="owner", operator=Operator.EQ, value=owner))
    if value:
        conditions.append(Condition(field="value", operator=Operator.EQ, value=value))

    filter_model = _build_filter_group(conditions)
    models = Artifact.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


# Enrichment
def create_enrichment(
        name: Annotated[str, "Enrichment name"] = "",
        type: Annotated[str, "Enrichment type"] = "Other",
        provider: Annotated[str, "Enrichment provider"] = "Other",
        value: Annotated[str, "Enrichment value"] = "",
        src_url: Annotated[str, "Enrichment source URL"] = "",
        desc: Annotated[str, "Enrichment summary"] = "",
        data: Annotated[str, "Detailed enrichment JSON string"] = ""
) -> Annotated[str, "Created enrichment record row ID"]:
    """Create one enrichment record."""
    model = EnrichmentModel()
    model.name = name
    model.type = type
    model.provider = provider
    model.value = value
    model.src_url = src_url
    model.desc = desc
    model.data = data
    return Enrichment.create(model)


def attach_enrichment_to_target(
    target_type: Annotated[str, "Target object type: case, alert, or artifact"],
    target_id: Annotated[str, "Target object ID to receive the existing enrichment"],
    enrichment_rowid: Annotated[str, "Enrichment record row ID returned by create_enrichment"]
) -> Annotated[Optional[str], "Attached enrichment record row ID, or None if target not found"]:
    """Attach one existing enrichment record to an existing case, alert, or artifact."""
    normalized_target_type = target_type.strip().lower()

    if normalized_target_type == "case":
        return Case.attach_enrichment(
            case_id=target_id,
            enrichment_rowid=enrichment_rowid
        )

    if normalized_target_type == "alert":
        return Alert.attach_enrichment(
            alert_id=target_id,
            enrichment_rowid=enrichment_rowid
        )

    if normalized_target_type == "artifact":
        return Artifact.attach_enrichment(
            artifact_id=target_id,
            enrichment_rowid=enrichment_rowid
        )

    raise ValueError("target_type must be one of: case, alert, artifact")


# Ticket
def create_ticket(
        uid: Annotated[str, "External ticket ID to sync into SIRP"],
        title: Annotated[str, "Ticket title"] = "",
        status: Annotated[Optional[TicketStatus], "External ticket status"] = None,
        type: Annotated[Optional[TicketType], "External ticket type"] = None,
        src_url: Annotated[str, "External ticket URL"] = ""
) -> Annotated[str, "Created ticket record row ID"]:
    """Create one synced external ticket record in SIRP."""
    model = TicketModel()
    model.uid = uid
    model.title = title
    model.status = status
    model.type = type
    model.src_url = src_url
    return Ticket.create(model)


def attach_ticket_to_case(
    case_id: Annotated[str, "Target case ID to receive the existing ticket"],
    ticket_rowid: Annotated[str, "Ticket record row ID returned by create_ticket"]
) -> Annotated[Optional[str], "Attached ticket record row ID, or None if case not found"]:
    """Attach one existing ticket record to an existing case."""
    return Case.attach_ticket(
        case_id=case_id,
        ticket_rowid=ticket_rowid
    )


def list_tickets(
        status: Annotated[Optional[list[TicketStatus]], "Ticket status filter"] = None,
        type: Annotated[Optional[list[TicketType]], "Ticket type filter"] = None,
        uid: Annotated[Optional[str], "Exact external ticket ID filter"] = None,
        limit: Annotated[int, "Max tickets to return"] = 10
) -> Annotated[list[str], "Matching tickets as AI-friendly JSON list"]:
    """List synced external tickets with optional filters."""
    conditions = []

    if status:
        conditions.append(Condition(field="status", operator=Operator.IN, value=status))
    if type:
        conditions.append(Condition(field="type", operator=Operator.IN, value=type))
    if uid:
        conditions.append(Condition(field="uid", operator=Operator.EQ, value=uid))

    filter_model = _build_filter_group(conditions)
    models = Ticket.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def update_ticket(
        ticket_id: Annotated[str, "Ticket ID to update"],
        uid: Annotated[Optional[str], "Updated external ticket ID"] = None,
        title: Annotated[Optional[str], "Updated ticket title"] = None,
        status: Annotated[Optional[TicketStatus], "Updated external ticket status"] = None,
        type: Annotated[Optional[TicketType], "Updated external ticket type"] = None,
        src_url: Annotated[Optional[str], "Updated external ticket URL"] = None
) -> Annotated[Optional[str], "Updated ticket row ID, or None if not found"]:
    """Update one synced external ticket record in SIRP."""
    return Ticket.update_by_id(
        ticket_id=ticket_id,
        uid=uid,
        title=title,
        status=status,
        type=type,
        src_url=src_url
    )


# Playbook
def list_available_playbook_definitions(
) -> Annotated[str, "Runnable playbook definitions as JSON string, not playbook run records"]:
    """List all runnable built-in playbook definitions, not playbook run records."""
    result = PlaybookLoader.list_playbook_config()
    return json.dumps(result, ensure_ascii=False)


def list_playbook_runs(
        playbook_id: Annotated[Optional[str], "Playbook run ID, e.g. playbook_000001"] = None,
        job_status: Annotated[Optional[list[PlaybookJobStatus]], "Playbook job status filter"] = None,
        type: Annotated[Optional[list[PlaybookType]], "Playbook type filter"] = None,
        source_id: Annotated[Optional[str], "Playbook target record ID filter, e.g. case_000001, alert_000001, artifact_000001"] = None,
        limit: Annotated[int, "Max playbook runs to return"] = 10
) -> Annotated[list[str], "Matching playbook run records as AI-friendly JSON list"]:
    """List playbook run records with optional filters."""
    conditions = []

    if playbook_id:
        conditions.append(Condition(field="id", operator=Operator.EQ, value=playbook_id))
    if source_id:
        conditions.append(Condition(field="source_id", operator=Operator.EQ, value=source_id))
    if job_status:
        conditions.append(Condition(field="job_status", operator=Operator.IN, value=job_status))
    if type:
        conditions.append(Condition(field="type", operator=Operator.IN, value=type))

    filter_model = _build_filter_group(conditions)
    models = Playbook.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def execute_playbook(
        type: Annotated[PlaybookType, "Target object type for the created playbook run: CASE, ALERT, or ARTIFACT"],
        name: Annotated[str, "Runnable playbook definition name from list_available_playbook_definitions, not a playbook run ID"],
        record_id: Annotated[str, "Target record ID, e.g. case_000001, alert_000001, artifact_000001"],
        user_input: Annotated[Optional[str], "Optional extra natural-language input for this playbook run"] = None
) -> Annotated[str, "Created pending playbook run record as AI-friendly JSON string"]:
    """Create one pending playbook run record from a runnable playbook definition."""
    result = Playbook.add_pending_playbook(
        type=type,
        name=name,
        user_input=user_input,
        record_id=record_id
    )
    return result.model_dump_json_for_ai()


def list_knowledge(
        action: Annotated[Optional[list[KnowledgeAction]], "Knowledge action filter"] = None,
        source: Annotated[Optional[list[KnowledgeSource]], "Knowledge source filter"] = None,
        using: Annotated[Optional[bool], "Knowledge using flag filter"] = None,
        title: Annotated[Optional[str], "Fuzzy knowledge title filter"] = None,
        body: Annotated[Optional[str], "Fuzzy knowledge body filter"] = None,
        tags: Annotated[Optional[list[str]], "Knowledge tag filter"] = None,
        limit: Annotated[int, "Max knowledge records to return"] = 10
) -> Annotated[list[str], "Matching knowledge records as AI-friendly JSON list"]:
    """List knowledge records with optional filters."""
    conditions = []

    if action:
        conditions.append(Condition(field="action", operator=Operator.IN, value=action))
    if source:
        conditions.append(Condition(field="source", operator=Operator.IN, value=source))
    if using is not None:
        conditions.append(Condition(field="using", operator=Operator.EQ, value=using))
    if title:
        conditions.append(Condition(field="title", operator=Operator.CONTAINS, value=title))
    if body:
        conditions.append(Condition(field="body", operator=Operator.CONTAINS, value=body))
    if tags:
        conditions.append(Condition(field="tags", operator=Operator.CONTAINS, value=tags))

    filter_model = _build_filter_group(conditions)
    models = Knowledge.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def update_knowledge(
        knowledge_id: Annotated[str, "Knowledge ID to update"],
        title: Annotated[Optional[str], "Updated knowledge title"] = None,
        body: Annotated[Optional[str], "Updated knowledge body"] = None,
        using: Annotated[Optional[bool], "Updated knowledge using flag"] = None,
        action: Annotated[Optional[KnowledgeAction], "Updated knowledge action"] = None,
        source: Annotated[Optional[KnowledgeSource], "Updated knowledge source"] = None,
        tags: Annotated[Optional[list[str]], "Updated knowledge tags; pass [] to clear"] = None
) -> Annotated[Optional[str], "Updated knowledge row ID, or None if not found"]:
    """Update one knowledge record in SIRP."""
    return Knowledge.update_by_id(
        knowledge_id=knowledge_id,
        title=title,
        body=body,
        using=using,
        action=action,
        source=source,
        tags=tags
    )


def siem_explore_schema(
        target_index: Annotated[Optional[str], "Target SIEM index; omit to list all available indices"] = None
) -> Annotated[str, "Schema exploration result as JSON string"]:
    """Explore available SIEM indices or inspect one index schema."""
    input_data = SchemaExplorerInput(target_index=target_index)
    result = SIEMToolKit.explore_schema(input_data)
    return json.dumps(result, ensure_ascii=False)


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


def siem_adaptive_query(
        index_name: Annotated[str, "Target SIEM index or source name"],
        time_range_start: Annotated[str, "UTC start time in ISO8601, e.g. 2026-02-04T06:00:00Z"],
        time_range_end: Annotated[str, "UTC end time in ISO8601, e.g. 2026-02-04T07:00:00Z"],
        time_field: Annotated[str, "Time field used for range filtering"] = "@timestamp",
        filters: Annotated[Optional[dict[str, str | list[str]]], "Exact-match filters; values can be a string or string list"] = None,
        aggregation_fields: Annotated[Optional[list[str]], "Fields used for top-N statistics; omit to use defaults"] = None
) -> Annotated[str, "Adaptive query result as JSON string"]:
    """Query SIEM data with exact-match filters and optional aggregations."""
    input_data = AdaptiveQueryInput(
        index_name=index_name,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        time_field=time_field,
        filters=filters or {},
        aggregation_fields=aggregation_fields or []
    )
    result = SIEMToolKit.execute_adaptive_query(input_data)
    return result.model_dump_json()


def get_current_time(
        time_format: Annotated[
            Optional[str], "Optional Python strftime format. If omitted, returns ISO8601 time with timezone"] = None
) -> Annotated[str, "Current local time string with timezone"]:
    """Get current system time."""
    current_time = datetime.now().astimezone()
    if time_format:
        return current_time.strftime(time_format)
    return current_time.isoformat(timespec="seconds")



