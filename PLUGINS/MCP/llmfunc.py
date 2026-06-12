import json
from datetime import datetime, timezone
from typing import Annotated, Optional, Union, List, Literal

from pydantic import Field

from Lib.playbookloader import PlaybookLoader
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI
from PLUGINS.SIEM.models import AdaptiveQueryInput, ESQLQueryInput, KeywordSearchInput, SchemaExplorerInput, QueryOutput, IndexInfo, SchemaIndexSummary, \
    DiscoverIndexFieldsInput, DiscoverIndexFieldsOutput, SPLQueryInput
from PLUGINS.SIEM.tools import SIEMToolKit
from PLUGINS.SIRP.nocolymodel import Group, Condition, Operator
from PLUGINS.SIRP.sirpapi import Alert, Artifact, Case, Enrichment, Knowledge, Playbook
from PLUGINS.SIRP.sirpbasemodel import AI_PROFILE_MCP
from PLUGINS.SIRP.sirpcoremodel import ArtifactType, ArtifactRole, Severity, Confidence, \
    AlertStatus, CaseStatus, CaseVerdict, EnrichmentModel, EnrichmentType, EnrichmentProvider
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus
from PLUGINS.ThreatIntelligence.models import TIQueryOutput
from PLUGINS.ThreatIntelligence.tools import TIToolKit


def _dump_models_for_ai(models, limit: int) -> list[dict]:
    return [model.model_dump_for_ai(profile=AI_PROFILE_MCP) for model in models[:limit]]


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
        include_discussions: Annotated[bool, Field(description="Include case discussions in the result (返回结果中包含讨论记录)")] = True,
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
    results = _dump_models_for_ai(models, limit)

    if include_discussions:
        for item in results:
            row_id_val = item.get("row_id")
            if row_id_val:
                discussions = Case.get_discussions_by_row_id(row_id_val) or []
                item["discussions"] = discussions

    return results


def update_case(
        case_id: Annotated[str, Field(description="Case ID to update (待更新的 Case ID)")],
        severity_ai: Annotated[Optional[Severity], Field(description="Updated AI-assessed severity (更新 AI 评估严重程度)")] = None,
        confidence_ai: Annotated[Optional[Confidence], Field(description="Updated AI-assessed confidence (更新 AI 评估置信度)")] = None,
        verdict_ai: Annotated[Optional[CaseVerdict], Field(description="Updated AI-assessed verdict (更新 AI 评估判定结果)")] = None,
        comment: Annotated[Optional[str], Field(description="Analyst comment, Markdown supported (分析师注释,支持 Markdown)")] = None,
        summary: Annotated[Optional[str], Field(description="Closure summary, Markdown supported (结案摘要,支持 Markdown)")] = None,
) -> Annotated[Optional[str], Field(description="Updated case row ID, or None if not found (更新后的 Case 行 ID,不存在时返回 None)")]:
    """Update case fields including AI-assessed fields, analyst comment, and closure summary. (更新 Case 字段,包括 AI 评估字段、分析师注释和结案摘要)"""
    return Case.update_by_id(
        case_id=case_id,
        severity_ai=severity_ai,
        confidence_ai=confidence_ai,
        verdict_ai=verdict_ai,
        comment=comment,
        summary=summary,
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
    if owner:
        conditions.append(Condition(field="owner", operator=Operator.EQ, value=owner))
    if value:
        conditions.append(Condition(field="value", operator=Operator.EQ, value=value))

    filter_model = Group(logic="AND", children=conditions or [])
    models = Artifact.list(filter_model, lazy_load=lazy_load)
    return _dump_models_for_ai(models, limit)


# Enrichment
def create_enrichment(
        target_id: Annotated[str, Field(
            description="Target object ID to attach the enrichment to; must start with case_, alert_, or artifact_ (挂载富化的目标对象 ID,须以 case_、alert_ 或 artifact_ 开头)")],
        name: Annotated[str, Field(description="Enrichment name (富化名称)")] = "",
        type: Annotated[EnrichmentType, Field(description="Enrichment type (富化类型)")] = EnrichmentType.OTHER,
        value: Annotated[str, Field(description="Enrichment value (富化值)")] = "",
        uid: Annotated[str, Field(description="Externally computed stable identifier for deduplication (外部计算的稳定唯一标识,用于去重)")] = "",
        desc: Annotated[str, Field(description="Enrichment summary (富化摘要)")] = "",
        data: Annotated[str, Field(description="Detailed enrichment JSON string (详细富化 JSON 字符串)")] = ""
) -> Annotated[str, Field(description="Created enrichment record row ID (创建的 Enrichment 行 ID)")]:
    """Create one enrichment record and attach it to a target case, alert, or artifact. (创建一条富化记录并挂载到目标 Case、Alert 或 Artifact)"""
    model = EnrichmentModel()
    model.name = name
    model.type = type
    model.provider = EnrichmentProvider.MCP
    model.value = value
    model.uid = uid
    model.desc = desc
    model.data = data
    enrichment_row_id = Enrichment.create(model)

    normalized_target_id = target_id.strip().lower()
    if normalized_target_id.startswith("case_"):
        Case.attach_enrichment(case_id=target_id, enrichment_row_id=enrichment_row_id)
    elif normalized_target_id.startswith("alert_"):
        Alert.attach_enrichment(alert_id=target_id, enrichment_row_id=enrichment_row_id)
    elif normalized_target_id.startswith("artifact_"):
        Artifact.attach_enrichment(artifact_id=target_id, enrichment_row_id=enrichment_row_id)
    else:
        raise ValueError("target_id must start with one of: case_, alert_, artifact_")

    return enrichment_row_id


# Playbook
def list_playbook_definitions(
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
        case_id: Annotated[Optional[str], Field(
            description="Target case ID filter, e.g. case_000001 (目标 Case ID 过滤)")] = None,
        limit: Annotated[int, Field(description="Max playbook runs to return (最多返回条数)")] = 10
) -> Annotated[list[dict], Field(description="Matching playbook run records as AI-friendly JSON list (匹配的 Playbook 执行记录列表)")]:
    """List playbook run records with optional filters. (列出 Playbook 执行记录,支持多条件过滤)"""
    conditions = []

    if row_id:
        conditions.append(Condition(field="rowId", operator=Operator.EQ, value=row_id))
    if playbook_id:
        conditions.append(Condition(field="id", operator=Operator.EQ, value=playbook_id))
    if case_id:
        conditions.append(Condition(field="case_id", operator=Operator.EQ, value=case_id))
    if job_status:
        conditions.append(Condition(field="job_status", operator=Operator.IN, value=job_status))

    filter_model = Group(logic="AND", children=conditions or [])
    models = Playbook.list(filter_model, lazy_load=True)
    return _dump_models_for_ai(models, limit)


def execute_playbook(
        name: Annotated[str, Field(
            description="Runnable playbook definition name from list_playbook_definitions, not a playbook run ID (来自 list_playbook_definitions 的 Playbook 定义名称,非执行记录 ID)")],
        case_id: Annotated[str, Field(description="Target case ID, e.g. case_000001 (目标 Case ID)")],
        user_input: Annotated[
            Optional[str], Field(description="Optional extra natural-language input for this playbook run (本次执行的可选补充自然语言输入)")] = None
) -> Annotated[str, Field(description="Created pending playbook run record as AI-friendly JSON string (创建的待执行 Playbook 记录 JSON 字符串)")]:
    """Create one pending playbook run record from a runnable playbook definition. (根据 Playbook 定义创建一条待执行记录)"""
    result = Playbook.add_pending_playbook(
        name=name,
        user_input=user_input,
        case_id=case_id
    )
    return result.model_dump_json_for_ai(profile=AI_PROFILE_MCP)


def update_knowledge(
        knowledge_id: Annotated[str, Field(description="Knowledge ID to update (待更新的知识条目 ID)")],
        title: Annotated[Optional[str], Field(description="Updated knowledge title (更新知识标题)")] = None,
        body: Annotated[Optional[str], Field(description="Updated knowledge body (更新知识内容)")] = None,
        expires_at: Annotated[Optional[str], Field(
            description="Updated expiration time; omit or keep empty for permanently valid knowledge (更新过期时间，不填写表示永久有效)")] = None,
        tags: Annotated[Optional[list[str]], Field(description="Updated knowledge tags; pass [] to clear (更新知识标签,传 [] 可清空)")] = None
) -> Annotated[Optional[str], Field(description="Updated knowledge row ID, or None if not found (更新后的知识条目行 ID,不存在时返回 None)")]:
    """Update one knowledge record in SIRP. (更新 SIRP 中一条知识条目)"""
    return Knowledge.update_by_id(
        knowledge_id=knowledge_id,
        title=title,
        body=body,
        expires_at=expires_at,
        tags=tags
    )


def search_knowledge(
        keyword: Annotated[Union[str, list[str]], Field(
            description="Search keyword or keyword list; when a list is provided, records matching at least one item are returned (搜索关键词或关键词列表；传入列表时返回匹配至少一个列表项的记录)")],
        limit: Annotated[int, Field(description="Maximum number of knowledge records to return (最多返回的知识记录数量)")] = 10
) -> Annotated[str, Field(
    description="Relevant knowledge entries, policies, and special handling instructions as a JSON list string (JSON 列表字符串形式的相关知识条目、策略及特殊处理说明)")]:
    """Search the internal knowledge base by keyword. (按关键词搜索内部知识库)"""
    results = Knowledge.search(keyword, limit=limit)
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
) -> Annotated[list[QueryOutput], Field(description="Search hits as JSON strings (命中的事件列表,每条为 JSON 字符串)")]:
    """Search SIEM events by keyword and time range. (按关键词和时间范围搜索 SIEM 事件)"""
    input_data = KeywordSearchInput(
        keyword=keyword,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        time_field=time_field,
        index_name=index_name
    )
    results = SIEMToolKit.keyword_search(input_data)
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


def siem_discover_index_fields(
        index_name: Annotated[
            str, Field(description="Target SIEM index/source name to discover fields from the live backend (目标 SIEM 索引名称,从实时后端发现字段)")],
        backend: Annotated[Literal["ELK", "Splunk"], Field(description="Backend type: 'ELK' or 'Splunk' (后端类型: 'ELK' 或 'Splunk')")],
        time_range_start: Annotated[Optional[str], Field(description="Optional UTC start time for sampling in ISO8601 (可选的采样起始时间,ISO8601 格式)")] = None,
        time_range_end: Annotated[Optional[str], Field(description="Optional UTC end time for sampling in ISO8601 (可选的采样结束时间,ISO8601 格式)")] = None,
        doc_limit: Annotated[int, Field(description="Number of documents to scan, default 10000 (扫描的日志条数,默认 10000)")] = 10000,
        max_samples_per_field: Annotated[int, Field(description="Max sample values per field, default 20 (每个字段最大样例值数量,默认 20)")] = 20,
) -> Annotated[DiscoverIndexFieldsOutput, Field(description="Discovered fields with types and sample values (发现的字段信息,包含类型和样本值)")]:
    """Discover all fields of a live SIEM index, returning field names, types, and sample values. Useful for generating index YAML configs. (从实时 SIEM 索引发现所有字段,返回字段名、类型和样本值,用于生成索引 YAML 配置)"""
    input_data = DiscoverIndexFieldsInput(
        index_name=index_name, backend=backend,
        time_range_start=time_range_start, time_range_end=time_range_end,
        doc_limit=doc_limit, max_samples_per_field=max_samples_per_field,
    )
    return SIEMToolKit.discover_index_fields(input_data)


def siem_execute_spl(
        query: Annotated[str, Field(description="Raw Splunk SPL query string (原始 Splunk SPL 查询语句)")],
        limit: Annotated[int, Field(description="Maximum number of records to return, default 100 (最大返回记录数,默认 100)")] = 100,
        time_range_start: Annotated[Optional[str], Field(description="Optional UTC start time in ISO8601 (可选的 UTC 开始时间,ISO8601 格式)")] = None,
        time_range_end: Annotated[Optional[str], Field(description="Optional UTC end time in ISO8601 (可选的 UTC 结束时间,ISO8601 格式)")] = None,
        time_field: Annotated[str, Field(description="Time field for range filtering (时间范围过滤字段名)")] = "@timestamp",
        index_name: Annotated[Optional[str], Field(description="Index name for output labeling; omit if specified in SPL (用于输出标记的索引名,SPL 中已指定时可不填)")] = None,
) -> Annotated[str, Field(description="Raw SPL query result as JSON string (原始 SPL 查询结果 JSON 字符串)")]:
    """Execute a raw Splunk SPL query and return results. (执行原始 Splunk SPL 查询并返回结果)"""
    input_data = SPLQueryInput(
        query=query, limit=limit,
        time_range_start=time_range_start, time_range_end=time_range_end,
        time_field=time_field, index_name=index_name,
    )
    result = SIEMToolKit.execute_spl(input_data)
    return result.model_dump_json()


def siem_execute_esql(
        query: Annotated[str, Field(description="Raw ELK ES|QL query string (原始 ELK ES|QL 查询语句)")],
        limit: Annotated[int, Field(description="Maximum number of records to return, default 100 (最大返回记录数,默认 100)")] = 100,
        time_range_start: Annotated[Optional[str], Field(description="Optional UTC start time in ISO8601 (可选的 UTC 开始时间,ISO8601 格式)")] = None,
        time_range_end: Annotated[Optional[str], Field(description="Optional UTC end time in ISO8601 (可选的 UTC 结束时间,ISO8601 格式)")] = None,
        time_field: Annotated[str, Field(description="Time field for range filtering (时间范围过滤字段名)")] = "@timestamp",
        index_name: Annotated[Optional[str], Field(description="Index name for output labeling; omit if specified in ES|QL (用于输出标记的索引名,ES|QL 中已指定时可不填)")] = None,
) -> Annotated[str, Field(description="Raw ES|QL query result as JSON string (原始 ES|QL 查询结果 JSON 字符串)")]:
    """Execute a raw ELK ES|QL query and return results. (执行原始 ELK ES|QL 查询并返回结果)"""
    input_data = ESQLQueryInput(
        query=query, limit=limit,
        time_range_start=time_range_start, time_range_end=time_range_end,
        time_field=time_field, index_name=index_name,
    )
    result = SIEMToolKit.execute_esql(input_data)
    return result.model_dump_json()


def get_current_time() -> Annotated[str, Field(description="Current local time string with UTC (当前本地时间UTC字符串)")]:
    """Get current system UTC time. (获取当前系统 UTC 时间)"""
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


# ThreatIntelligence

def ti_query(
        indicator: Annotated[str, Field(
            description="Indicator to look up: IP address, file hash, URL, or domain (待查询的指标: IP地址、文件哈希、URL 或域名)")],
        provider: Annotated[Optional[str], Field(
            description="Specific ThreatIntelligence provider name, e.g. 'AlienVault OTX'; None queries all providers (指定 ThreatIntelligence 提供商名称,None 表示查询所有提供商)")] = None,
) -> Annotated[TIQueryOutput, Field(
    description="Aggregated threat intelligence results from one or more providers (来自一个或多个提供商的聚合威胁情报结果)")]:
    """Query threat intelligence providers for an indicator and return aggregated results. (查询指标的威胁情报,返回聚合结果)"""
    return TIToolKit.query(indicator=indicator, provider=provider)


REGISTERED_MCP_TOOLS = [

    # case
    list_cases,
    update_case,

    # alert
    list_alerts,

    # artifact
    list_artifacts,

    # enrichment
    create_enrichment,

    # playbook
    list_playbook_definitions,
    execute_playbook,
    list_playbook_runs,

    # knowledge
    update_knowledge,
    search_knowledge,

    # SIEM
    get_current_time,
    siem_explore_schema,
    siem_adaptive_query,
    siem_keyword_search,
    siem_discover_index_fields,
    siem_execute_spl,
    siem_execute_esql,

    # ThreatIntelligence
    ti_query,

    # redis stream
    read_stream_head,
    read_stream_message_by_id,
]
