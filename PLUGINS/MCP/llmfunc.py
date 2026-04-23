import json
from datetime import datetime
from typing import Annotated, Optional, Union, List

from pydantic import Field

from Lib.playbookloader import PlaybookLoader
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI
from PLUGINS.SIEM.models import AdaptiveQueryInput, KeywordSearchInput, SchemaExplorerInput, KeywordSearchOutput, IndexInfo, SchemaIndexSummary
from PLUGINS.SIEM.tools import SIEMToolKit
from PLUGINS.SIRP.nocolymodel import Group, Condition, Operator
from PLUGINS.SIRP.sirpapi import Alert, Artifact, Case, Enrichment, Knowledge, Playbook, Ticket
from PLUGINS.SIRP.sirpcoremodel import TicketStatus, TicketType, ArtifactType, ArtifactRole, ArtifactReputationScore, Severity, AttackStage, Confidence, \
    AlertStatus, CaseStatus, CaseVerdict, EnrichmentModel, TicketModel, ArtifactModel
from PLUGINS.SIRP.sirpextramodel import PlaybookType, KnowledgeSource, PlaybookJobStatus, KnowledgeAction


def _dump_models_for_ai(models, limit: int) -> list[dict]:
    return [model.model_dump_for_ai() for model in models[:limit]]


# redis stream

def read_stream_message_by_id(
        stream_name: Annotated[str, Field(
            description="Stream name, usually the module name, e.g. 'Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy' (Stream 名称,通常为 Module 名称)")],
        message_id: Annotated[str, Field(description="Message ID (Entry ID), e.g. '1776309110392-0' (消息 ID)")],
) -> Annotated[dict, Field(
    description="Message read from Redis stream by message ID, or empty dict if not found (通过消息 ID 从 Redis Stream 精确读取的消息 dict,不存在时返回空 dict)")]:
    """Read one message from a Redis stream by its exact message ID (non-blocking). (按消息 ID 从 Redis Stream 精确读取一条消息,非阻塞)"""
    redis_stream_api = RedisStreamAPI()
    message = redis_stream_api.read_stream_message_by_id(stream_name, message_id, timeout=1)
    return message


def read_stream_head(
        stream_name: Annotated[str, Field(
            description="Stream name, usually the module name, e.g. 'Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy' (Stream 名称,通常为 Module 名称)")],
        n: Annotated[int, Field(description="Number of messages to read from the head (从头读取的消息数量)")] = 3) -> Annotated[
    list[dict], Field(description="First n messages from Redis stream as list of dict (前 n 条消息列表)")]:
    """Read the first n messages from a Redis stream (non-blocking). Useful for inspecting stream contents or understanding message structure. (从 Redis Stream 头部读取前 n 条消息,非阻塞。常用于查看 Stream 内容或了解消息结构)"""
    redis_stream_api = RedisStreamAPI()
    messages = redis_stream_api.read_stream_head(stream_name, n, timeout=1)
    return messages


# Case
def list_cases(
        row_id: Annotated[Optional[str], Field(description="Case row ID filter, e.g. 03c26478-b213-44c8-b651-3cc88abaac01 (Case 行 ID 过滤)")] = None,
        case_id: Annotated[Optional[str], Field(description="Case ID filter, e.g. case_000005 (Case ID 过滤)")] = None,
        status: Annotated[Optional[list[CaseStatus]], Field(description="Case status filter (Case 状态过滤)")] = None,
        severity: Annotated[Optional[list[Severity]], Field(description="Case severity filter (Case 严重程度过滤)")] = None,
        confidence: Annotated[Optional[list[Confidence]], Field(description="Case confidence filter (Case 置信度过滤)")] = None,
        verdict: Annotated[Optional[list[CaseVerdict]], Field(description="Case verdict filter (Case 判定结果过滤)")] = None,
        correlation_uid: Annotated[Optional[str], Field(description="Case correlation UID filter (Case 关联 UID 过滤)")] = None,
        title: Annotated[Optional[str], Field(description="Fuzzy case title filter (Case 标题模糊过滤)")] = None,
        tags: Annotated[Optional[list[str]], Field(description="Case tag filter (Case 标签过滤)")] = None,
        lazy_load: Annotated[bool, Field(description="True means do not load attached related data (True 表示不加载关联数据)")] = True,
        limit: Annotated[int, Field(description="Max cases to return (最多返回条数)")] = 10
) -> Annotated[list[dict], Field(description="Matching cases as AI-friendly JSON list (匹配的 Case 列表)")]:
    """List cases with optional filters. (列出 Case,支持多条件过滤)"""
    conditions = []
    if row_id:
        conditions.append(Condition(field="rowId", operator=Operator.EQ, value=row_id))
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

    filter_model = Group(logic="AND", children=conditions or [])
    models = Case.list(filter_model, lazy_load=lazy_load)
    return _dump_models_for_ai(models, limit)


def get_case_discussions(
        case_id: Annotated[str, Field(description="Case ID, e.g. case_000005 (Case ID)")]
) -> Annotated[Optional[list[str]], Field(
    description="Case discussions as JSON string list, or None if case not found (Case 讨论记录 JSON 字符串列表,Case 不存在时返回 None)")]:
    """Get case discussions by case ID. (通过 Case ID 获取讨论记录)"""
    discussions = Case.get_discussions(case_id)
    if discussions is None:
        return None
    return [json.dumps(item, ensure_ascii=False) for item in discussions]


def update_case(
        case_id: Annotated[str, Field(description="Case ID to update (待更新的 Case ID)")],
        severity_ai: Annotated[Optional[Severity], Field(description="Updated AI-assessed severity (更新 AI 评估严重程度)")] = None,
        confidence_ai: Annotated[Optional[Confidence], Field(description="Updated AI-assessed confidence (更新 AI 评估置信度)")] = None,
        attack_stage_ai: Annotated[Optional[AttackStage], Field(description="Updated AI-assessed attack stage (更新 AI 评估攻击阶段)")] = None,
        comment_ai: Annotated[Optional[str], Field(description="Updated AI comment, Markdown supported (更新 AI 注释,支持 Markdown)")] = None,
        verdict_ai: Annotated[Optional[CaseVerdict], Field(description="Updated AI-assessed verdict (更新 AI 评估判定结果)")] = None,
        summary_ai: Annotated[Optional[str], Field(description="Updated AI closure summary, Markdown supported (更新 AI 结案摘要,支持 Markdown)")] = None
) -> Annotated[Optional[str], Field(description="Updated case row ID, or None if not found (更新后的 Case 行 ID,不存在时返回 None)")]:
    """Update AI-assessed fields on a case. (更新 Case 的 AI 评估字段)"""
    return Case.update_by_id(
        case_id=case_id,
        severity_ai=severity_ai,
        confidence_ai=confidence_ai,
        attack_stage_ai=attack_stage_ai,
        comment_ai=comment_ai,
        verdict_ai=verdict_ai,
        summary_ai=summary_ai
    )


# Alert
def list_alerts(
        row_id: Annotated[Optional[str], Field(description="Alert row ID filter, e.g. 03c26478-b213-44c8-b651-3cc88abaac01 (Alert 行 ID 过滤)")] = None,
        alert_id: Annotated[Optional[str], Field(description="Alert ID filter, e.g. alert_000001 (Alert ID 过滤)")] = None,
        status: Annotated[Optional[list[AlertStatus]], Field(description="Alert status filter (Alert 状态过滤)")] = None,
        severity: Annotated[Optional[list[Severity]], Field(description="Alert severity filter (Alert 严重程度过滤)")] = None,
        confidence: Annotated[Optional[list[Confidence]], Field(description="Alert confidence filter (Alert 置信度过滤)")] = None,
        correlation_uid: Annotated[Optional[str], Field(description="Alert correlation UID filter (Alert 关联 UID 过滤)")] = None,
        lazy_load: Annotated[bool, Field(description="True means do not load attached related data (True 表示不加载关联数据)")] = True,
        limit: Annotated[int, Field(description="Max alerts to return (最多返回条数)")] = 10
) -> Annotated[list[dict], Field(description="Matching alerts as AI-friendly JSON list (匹配的 Alert 列表)")]:
    """List alerts with optional filters. (列出 Alert,支持多条件过滤)"""
    conditions = []

    if row_id:
        conditions.append(Condition(field="rowId", operator=Operator.EQ, value=row_id))
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

    filter_model = Group(logic="AND", children=conditions or [])
    models = Alert.list(filter_model, lazy_load=lazy_load)
    return _dump_models_for_ai(models, limit)


def get_alert_discussions(
        alert_id: Annotated[str, Field(description="Alert ID, e.g. alert_000001 (Alert ID)")]
) -> Annotated[Optional[list[str]], Field(
    description="Alert discussions as JSON string list, or None if alert not found (Alert 讨论记录 JSON 字符串列表,Alert 不存在时返回 None)")]:
    """Get alert discussions by alert ID. (通过 Alert ID 获取讨论记录)"""
    discussions = Alert.get_discussions(alert_id)
    if discussions is None:
        return None
    return [json.dumps(item, ensure_ascii=False) for item in discussions]


def update_alert(
        alert_id: Annotated[str, Field(description="Alert ID to update (待更新的 Alert ID)")],
        severity_ai: Annotated[Severity, Field(description="Updated AI-assessed severity (更新 AI 评估严重程度)")] = None,
        confidence_ai: Annotated[Optional[Confidence], Field(description="Updated AI-assessed confidence (更新 AI 评估置信度)")] = None,
        comment_ai: Annotated[Optional[str], Field(description="Updated AI comment, Markdown supported (更新 AI 注释,支持 Markdown)")] = None
) -> Annotated[Optional[str], Field(description="Updated alert row ID, or None if not found (更新后的 Alert 行 ID,不存在时返回 None)")]:
    """Update AI-assessed fields on an alert. (更新 Alert 的 AI 评估字段)"""
    return Alert.update_by_id(
        alert_id=alert_id,
        severity_ai=severity_ai,
        confidence_ai=confidence_ai,
        comment_ai=comment_ai
    )


# Artifact
# Do not open to mcp , because we think artifact is add only by automation, not human
def create_artifact(
        name: Annotated[str, Field(description="Artifact name (实体名称)")] = "",
        type: Annotated[Optional[ArtifactType], Field(description="Artifact type (实体类型)")] = None,
        role: Annotated[Optional[ArtifactRole], Field(description="Artifact role in event (实体在事件中的角色)")] = None,
        owner: Annotated[str, Field(description="Owning system or user (所属系统或用户)")] = "",
        value: Annotated[str, Field(description="Artifact value (实体值)")] = "",
        reputation_provider: Annotated[str, Field(description="Threat intel provider (威胁情报提供商)")] = "",
        reputation_score: Annotated[Optional[ArtifactReputationScore], Field(description="Artifact reputation score (实体信誉评分)")] = None
) -> Annotated[str, Field(description="Created artifact record row ID (创建的 Artifact 行 ID)")]:
    """Create one artifact record. (创建一条 Artifact 记录)"""
    model = ArtifactModel()
    model.name = name
    model.type = type
    model.role = role
    model.owner = owner
    model.value = value
    model.reputation_provider = reputation_provider
    model.reputation_score = reputation_score
    return Artifact.create(model)


# Do not open to mcp , because we think artifact is add only by automation, not human
def attach_artifact_to_alert(
        alert_id: Annotated[str, Field(description="Target alert ID to receive the existing artifact (接收 Artifact 的目标 Alert ID)")],
        artifact_row_id: Annotated[str, Field(description="Artifact record row ID returned by create_artifact (由 create_artifact 返回的 Artifact 行 ID)")]
) -> Annotated[
    Optional[str], Field(description="Attached artifact record row ID, or None if alert not found (挂载后的 Artifact 行 ID,Alert 不存在时返回 None)")]:
    """Attach one existing artifact record to an existing alert. (将已有 Artifact 挂载到已有 Alert)"""
    return Alert.attach_artifact(
        alert_id=alert_id,
        artifact_row_id=artifact_row_id
    )


def list_artifacts(
        row_id: Annotated[Optional[str], Field(description="Artifact row ID filter, e.g. 03c26478-b213-44c8-b651-3cc88abaac01 (Artifact 行 ID 过滤)")] = None,
        artifact_id: Annotated[Optional[str], Field(description="Artifact ID filter, e.g. artifact_000001 (Artifact ID 过滤)")] = None,
        type: Annotated[Optional[list[ArtifactType]], Field(description="Artifact type filter (实体类型过滤)")] = None,
        role: Annotated[Optional[list[ArtifactRole]], Field(description="Artifact role filter (实体角色过滤)")] = None,
        reputation_score: Annotated[Optional[list[ArtifactReputationScore]], Field(description="Artifact reputation filter (实体信誉过滤)")] = None,
        owner: Annotated[Optional[str], Field(description="Artifact owner filter, exact match (实体所有者过滤,精确匹配)")] = None,
        value: Annotated[Optional[str], Field(description="Artifact value filter, exact match (实体值过滤,精确匹配)")] = None,
        lazy_load: Annotated[bool, Field(description="True means do not load attached related data (True 表示不加载关联数据)")] = True,
        limit: Annotated[int, Field(description="Max artifacts to return (最多返回条数)")] = 10
) -> Annotated[list[dict], Field(description="Matching artifacts as AI-friendly JSON list (匹配的 Artifact 列表)")]:
    """List artifacts with optional filters. (列出 Artifact,支持多条件过滤)"""
    conditions = []
    if row_id:
        conditions.append(Condition(field="rowId", operator=Operator.EQ, value=row_id))
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

    filter_model = Group(logic="AND", children=conditions or [])
    models = Artifact.list(filter_model, lazy_load=lazy_load)
    return _dump_models_for_ai(models, limit)


# Enrichment
def create_enrichment(
        name: Annotated[str, Field(description="Enrichment name (富化名称)")] = "",
        type: Annotated[str, Field(description="Enrichment type (富化类型)")] = "Other",
        provider: Annotated[str, Field(description="Enrichment provider (富化提供商)")] = "Other",
        value: Annotated[str, Field(description="Enrichment value (富化值)")] = "",
        src_url: Annotated[str, Field(description="Enrichment source URL (富化来源 URL)")] = "",
        desc: Annotated[str, Field(description="Enrichment summary (富化摘要)")] = "",
        data: Annotated[str, Field(description="Detailed enrichment JSON string (详细富化 JSON 字符串)")] = ""
) -> Annotated[str, Field(description="Created enrichment record row ID (创建的 Enrichment 行 ID)")]:
    """Create one enrichment record. (创建一条富化记录)"""
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
        target_id: Annotated[str, Field(
            description="Target object ID to receive the enrichment; must start with case_, alert_, or artifact_ (接收富化的目标对象 ID,须以 case_、alert_ 或 artifact_ 开头)")],
        enrichment_row_id: Annotated[
            str, Field(description="Enrichment record row ID returned by create_enrichment (由 create_enrichment 返回的 Enrichment 行 ID)")]
) -> Annotated[
    Optional[str], Field(description="Attached enrichment record row ID, or None if target not found (挂载后的 Enrichment 行 ID,目标不存在时返回 None)")]:
    """Attach one existing enrichment record to an existing case, alert, or artifact. (将已有富化记录挂载到 Case、Alert 或 Artifact)"""
    normalized_target_id = target_id.strip().lower()

    if normalized_target_id.startswith("case_"):
        return Case.attach_enrichment(
            case_id=target_id,
            enrichment_row_id=enrichment_row_id
        )

    if normalized_target_id.startswith("alert_"):
        return Alert.attach_enrichment(
            alert_id=target_id,
            enrichment_row_id=enrichment_row_id
        )

    if normalized_target_id.startswith("artifact_"):
        return Artifact.attach_enrichment(
            artifact_id=target_id,
            enrichment_row_id=enrichment_row_id
        )

    raise ValueError("target_id must start with one of: case_, alert_, artifact_")


# Ticket
def create_ticket(
        uid: Annotated[str, Field(description="External ticket ID to sync into SIRP (同步到 SIRP 的外部工单 ID)")],
        title: Annotated[str, Field(description="Ticket title (工单标题)")] = "",
        status: Annotated[Optional[TicketStatus], Field(description="External ticket status (外部工单状态)")] = None,
        type: Annotated[Optional[TicketType], Field(description="External ticket type (外部工单类型)")] = None,
        src_url: Annotated[str, Field(description="External ticket URL (外部工单 URL)")] = ""
) -> Annotated[str, Field(description="Created ticket record row ID (创建的 Ticket 行 ID)")]:
    """Create one synced external ticket record in SIRP. (在 SIRP 中创建一条同步的外部工单记录)"""
    model = TicketModel()
    model.uid = uid
    model.title = title
    model.status = status
    model.type = type
    model.src_url = src_url
    return Ticket.create(model)


def attach_ticket_to_case(
        case_id: Annotated[str, Field(description="Target case ID to receive the existing ticket (接收 Ticket 的目标 Case ID)")],
        ticket_row_id: Annotated[str, Field(description="Ticket record row ID returned by create_ticket (由 create_ticket 返回的 Ticket 行 ID)")]
) -> Annotated[Optional[str], Field(description="Attached ticket record row ID, or None if case not found (挂载后的 Ticket 行 ID,Case 不存在时返回 None)")]:
    """Attach one existing ticket record to an existing case. (将已有 Ticket 挂载到已有 Case)"""
    return Case.attach_ticket(
        case_id=case_id,
        ticket_row_id=ticket_row_id
    )


def list_tickets(
        row_id: Annotated[Optional[str], Field(description="Ticket row ID filter, e.g. 03c26478-b213-44c8-b651-3cc88abaac01 (Ticket 行 ID 过滤)")] = None,
        status: Annotated[Optional[list[TicketStatus]], Field(description="Ticket status filter (工单状态过滤)")] = None,
        type: Annotated[Optional[list[TicketType]], Field(description="Ticket type filter (工单类型过滤)")] = None,
        uid: Annotated[Optional[str], Field(description="External ticket ID filter, exact match (外部工单 ID 过滤,精确匹配)")] = None,
        limit: Annotated[int, Field(description="Max tickets to return (最多返回条数)")] = 10
) -> Annotated[list[dict], Field(description="Matching tickets as AI-friendly JSON list (匹配的 Ticket 列表)")]:
    """List synced external tickets with optional filters. (列出同步的外部工单,支持多条件过滤)"""
    conditions = []

    if row_id:
        conditions.append(Condition(field="rowId", operator=Operator.EQ, value=row_id))
    if status:
        conditions.append(Condition(field="status", operator=Operator.IN, value=status))
    if type:
        conditions.append(Condition(field="type", operator=Operator.IN, value=type))
    if uid:
        conditions.append(Condition(field="uid", operator=Operator.EQ, value=uid))

    filter_model = Group(logic="AND", children=conditions or [])
    models = Ticket.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def update_ticket(
        ticket_id: Annotated[str, Field(description="Ticket ID to update (待更新的 Ticket ID)")],
        uid: Annotated[Optional[str], Field(description="Updated external ticket ID (更新外部工单 ID)")] = None,
        title: Annotated[Optional[str], Field(description="Updated ticket title (更新工单标题)")] = None,
        status: Annotated[Optional[TicketStatus], Field(description="Updated external ticket status (更新外部工单状态)")] = None,
        type: Annotated[Optional[TicketType], Field(description="Updated external ticket type (更新外部工单类型)")] = None,
        src_url: Annotated[Optional[str], Field(description="Updated external ticket URL (更新外部工单 URL)")] = None
) -> Annotated[Optional[str], Field(description="Updated ticket row ID, or None if not found (更新后的 Ticket 行 ID,不存在时返回 None)")]:
    """Update one synced external ticket record in SIRP. (更新 SIRP 中一条同步的外部工单记录)"""
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
) -> Annotated[str, Field(
    description="Runnable playbook definitions as JSON string, not playbook run records (可执行的 Playbook 定义列表 JSON 字符串,非 Playbook 执行记录)")]:
    """List all runnable built-in playbook definitions, not playbook run records. (列出所有可执行的内置 Playbook 定义,非 Playbook 执行记录)"""
    result = PlaybookLoader.list_playbook_config()
    return json.dumps(result, ensure_ascii=False)


def list_playbook_runs(
        row_id: Annotated[
            Optional[str], Field(description="Playbook run row ID filter, e.g. 03c26478-b213-44c8-b651-3cc88abaac01 (Playbook 执行记录行 ID 过滤)")] = None,
        playbook_id: Annotated[Optional[str], Field(description="Playbook run ID filter, e.g. playbook_000001 (Playbook 执行记录 ID 过滤)")] = None,
        job_status: Annotated[Optional[list[PlaybookJobStatus]], Field(description="Playbook job status filter (Playbook 任务状态过滤)")] = None,
        type: Annotated[Optional[list[PlaybookType]], Field(description="Playbook type filter (Playbook 类型过滤)")] = None,
        source_id: Annotated[Optional[str], Field(
            description="Playbook target record ID filter, e.g. case_000001, alert_000001, artifact_000001 (Playbook 目标记录 ID 过滤)")] = None,
        limit: Annotated[int, Field(description="Max playbook runs to return (最多返回条数)")] = 10
) -> Annotated[list[dict], Field(description="Matching playbook run records as AI-friendly JSON list (匹配的 Playbook 执行记录列表)")]:
    """List playbook run records with optional filters. (列出 Playbook 执行记录,支持多条件过滤)"""
    conditions = []

    if row_id:
        conditions.append(Condition(field="rowId", operator=Operator.EQ, value=row_id))
    if playbook_id:
        conditions.append(Condition(field="id", operator=Operator.EQ, value=playbook_id))
    if source_id:
        conditions.append(Condition(field="source_id", operator=Operator.EQ, value=source_id))
    if job_status:
        conditions.append(Condition(field="job_status", operator=Operator.IN, value=job_status))
    if type:
        conditions.append(Condition(field="type", operator=Operator.IN, value=type))

    filter_model = Group(logic="AND", children=conditions or [])
    models = Playbook.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def execute_playbook(
        type: Annotated[PlaybookType, Field(description="Target object type for the playbook run (Playbook 执行的目标对象类型)")],
        name: Annotated[str, Field(
            description="Runnable playbook definition name from list_available_playbook_definitions, not a playbook run ID (来自 list_available_playbook_definitions 的 Playbook 定义名称,非执行记录 ID)")],
        record_id: Annotated[str, Field(description="Target record ID, e.g. case_000001, alert_000001, artifact_000001 (目标记录 ID)")],
        user_input: Annotated[
            Optional[str], Field(description="Optional extra natural-language input for this playbook run (本次执行的可选补充自然语言输入)")] = None
) -> Annotated[str, Field(description="Created pending playbook run record as AI-friendly JSON string (创建的待执行 Playbook 记录 JSON 字符串)")]:
    """Create one pending playbook run record from a runnable playbook definition. (根据 Playbook 定义创建一条待执行记录)"""
    result = Playbook.add_pending_playbook(
        type=type,
        name=name,
        user_input=user_input,
        record_id=record_id
    )
    return result.model_dump_json_for_ai()


def list_knowledge(
        row_id: Annotated[Optional[str], Field(description="Knowledge row ID filter, e.g. 03c26478-b213-44c8-b651-3cc88abaac01 (知识条目行 ID 过滤)")] = None,
        action: Annotated[Optional[list[KnowledgeAction]], Field(description="Knowledge action filter (知识操作过滤)")] = None,
        source: Annotated[Optional[list[KnowledgeSource]], Field(description="Knowledge source filter (知识来源过滤)")] = None,
        using: Annotated[Optional[bool], Field(description="Knowledge using flag filter (知识使用中标志过滤)")] = None,
        title: Annotated[Optional[str], Field(description="Fuzzy knowledge title filter (知识标题模糊过滤)")] = None,
        body: Annotated[Optional[str], Field(description="Fuzzy knowledge body filter (知识内容模糊过滤)")] = None,
        tags: Annotated[Optional[list[str]], Field(description="Knowledge tag filter (知识标签过滤)")] = None,
        limit: Annotated[int, Field(description="Max knowledge records to return (最多返回条数)")] = 10
) -> Annotated[list[dict], Field(description="Matching knowledge records as AI-friendly JSON list (匹配的知识条目列表)")]:
    """List knowledge records with optional filters. (列出知识条目,支持多条件过滤)"""
    conditions = []

    if row_id:
        conditions.append(Condition(field="rowId", operator=Operator.EQ, value=row_id))
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

    filter_model = Group(logic="AND", children=conditions or [])
    models = Knowledge.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def update_knowledge(
        knowledge_id: Annotated[str, Field(description="Knowledge ID to update (待更新的知识条目 ID)")],
        title: Annotated[Optional[str], Field(description="Updated knowledge title (更新知识标题)")] = None,
        body: Annotated[Optional[str], Field(description="Updated knowledge body (更新知识内容)")] = None,
        action: Annotated[Optional[KnowledgeAction], Field(description="Updated knowledge action (更新知识操作)")] = None,
        tags: Annotated[Optional[list[str]], Field(description="Updated knowledge tags; pass [] to clear (更新知识标签,传 [] 可清空)")] = None
) -> Annotated[Optional[str], Field(description="Updated knowledge row ID, or None if not found (更新后的知识条目行 ID,不存在时返回 None)")]:
    """Update one knowledge record in SIRP. (更新 SIRP 中一条知识条目)"""
    return Knowledge.update_by_id(
        knowledge_id=knowledge_id,
        title=title,
        body=body,
        action=action,
        tags=tags
    )


def search_knowledge(
        query: Annotated[str, Field(description="The search query (搜索关键词或问题)")]
) -> Annotated[str, Field(description="Relevant knowledge entries, policies, and special handling instructions (相关知识条目、策略及特殊处理说明)")]:
    """Search the internal knowledge base for specific entities, business-specific logic, SOPs, or historical context. (在内部知识库中搜索实体、业务逻辑、SOP 或历史上下文)"""
    results = Knowledge.search(query)
    return results


def siem_explore_schema(
        target_index: Annotated[Optional[str], Field(
            description="Target SIEM index to inspect; omit to list all available indices (目标 SIEM 索引名称,不填则列出所有可用索引)")] = None
) -> Annotated[Union[IndexInfo, List[SchemaIndexSummary]], Field(description="Schema exploration result(索引 Schema 探查结果)")]:
    """Explore available SIEM indices or inspect one index schema. (探查可用的 SIEM 索引列表或指定索引的 Schema)"""
    input_data = SchemaExplorerInput(target_index=target_index)
    result = SIEMToolKit.explore_schema(input_data)
    return result


def siem_keyword_search(
        keyword: Annotated[str | list[str], Field(description="Keyword or keyword list; list uses AND matching (关键词或关键词列表,列表时使用 AND 匹配)")],
        time_range_start: Annotated[str, Field(description="UTC start time in ISO8601, e.g. 2026-02-04T06:00:00Z (UTC 开始时间,ISO8601 格式)")],
        time_range_end: Annotated[str, Field(description="UTC end time in ISO8601, e.g. 2026-02-04T07:00:00Z (UTC 结束时间,ISO8601 格式)")],
        time_field: Annotated[str, Field(description="Time field used for range filtering (用于时间范围过滤的字段名)")] = "@timestamp",
        index_name: Annotated[
            Optional[str], Field(description="Target SIEM index or source; None means all indices (目标 SIEM 索引或数据源,None 表示全部索引)")] = None
) -> Annotated[list[KeywordSearchOutput], Field(description="Search hits as JSON strings (命中的事件列表,每条为 JSON 字符串)")]:
    """Search SIEM events by keyword and time range. (按关键词和时间范围搜索 SIEM 事件)"""
    input_data = KeywordSearchInput(
        keyword=keyword,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        time_field=time_field,
        index_name=index_name
    )
    results = SIEMToolKit.keyword_search(input_data)
    # return [item.model_dump_json() for item in results]
    return results


def siem_adaptive_query(
        index_name: Annotated[str, Field(description="Target SIEM index or source name (目标 SIEM 索引或数据源名称)")],
        time_range_start: Annotated[str, Field(description="UTC start time in ISO8601, e.g. 2026-02-04T06:00:00Z (UTC 开始时间,ISO8601 格式)")],
        time_range_end: Annotated[str, Field(description="UTC end time in ISO8601, e.g. 2026-02-04T07:00:00Z (UTC 结束时间,ISO8601 格式)")],
        time_field: Annotated[str, Field(description="Time field used for range filtering (用于时间范围过滤的字段名)")] = "@timestamp",
        filters: Annotated[Optional[dict[str, str | list[str]]], Field(
            description="Exact-match filters; values can be a string or string list (精确匹配过滤条件,值可以是字符串或字符串列表)")] = None,
        aggregation_fields: Annotated[Optional[list[str]], Field(
            description="Fields used for top-N aggregation statistics; omit to use defaults (用于 Top-N 聚合统计的字段列表,不填使用默认值)")] = None
) -> Annotated[str, Field(description="Adaptive query result as JSON string (自适应查询结果 JSON 字符串)")]:
    """Query SIEM data with exact-match filters and optional aggregations. (对 SIEM 数据执行精确匹配过滤和可选聚合查询)"""
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
            Optional[str], Field(
                description="Optional Python strftime format string; if omitted, returns ISO8601 with timezone (可选的 Python strftime 格式字符串,不填则返回带时区的 ISO8601 时间)")] = None
) -> Annotated[str, Field(description="Current local time string with timezone (带时区的当前本地时间字符串)")]:
    """Get current system time. (获取当前系统时间)"""
    current_time = datetime.now().astimezone()
    if time_format:
        return current_time.strftime(time_format)
    return current_time.isoformat(timespec="seconds")


REGISTERED_MCP_TOOLS = [

    # case
    list_cases,
    get_case_discussions,
    update_case,

    # alert
    list_alerts,
    get_alert_discussions,
    update_alert,

    # artifact
    list_artifacts,

    # enrichment
    create_enrichment,
    attach_enrichment_to_target,

    # playbook
    list_available_playbook_definitions,
    execute_playbook,
    list_playbook_runs,

    # knowledge
    list_knowledge,
    update_knowledge,
    search_knowledge,

    # ticket
    list_tickets,
    create_ticket,
    update_ticket,
    attach_ticket_to_case,

    # SIEM
    get_current_time,
    siem_explore_schema,
    siem_adaptive_query,
    siem_keyword_search,

    # redis stream
    read_stream_head,
    read_stream_message_by_id,
]
