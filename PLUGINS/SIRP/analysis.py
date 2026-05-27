from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Any, Optional

from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, ConfigDict, Field

from Lib.configs import DATA_DIR
from Lib.log import logger
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case, Knowledge
from PLUGINS.SIRP.sirpbasemodel import AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP
from PLUGINS.SIRP.sirpcoremodel import AttackStage, CaseModel, CasePriority, CaseVerdict, Confidence, Impact, Severity

PROMPT_PATH = Path(DATA_DIR) / "SYSTEM" / "ANALYSIS" / "System_EN.md"
KNOWLEDGE_KEYWORDS_PROMPT_PATH = Path(DATA_DIR) / "SYSTEM" / "ANALYSIS" / "KnowledgeKeywords_EN.md"
KNOWLEDGE_EXTRACTION_PROMPT_PATH = Path(DATA_DIR) / "SYSTEM" / "KNOWLEDGE_EXTRACTION" / "System_EN.md"
MAX_KNOWLEDGE_KEYWORDS = 8
MAX_KNOWLEDGE_RECORDS = 10


class AffectedAsset(BaseModel):
    asset_type: str = Field(description="Type of asset, e.g. Host, IP, User, Mailbox, File, Cloud Resource. 资产类型。")
    asset_value: str = Field(description="Specific identifier, e.g. hostname, IP, username, email, file path. 资产具体标识。")


class EvidenceFinding(BaseModel):
    title: str = Field(description="Short title of the finding. 发现标题。")
    finding_type: str = Field(description="Category, e.g. Identity, Host, Process, Network, Email, Cloud, Policy. 发现类型。")
    subject: str = Field(description="Core subject, e.g. account, host, IP, URL, policy name. 发现主体。")
    evidence: str = Field(description="Core evidence summary; include traceable fields or objects. 核心证据摘要。")
    conclusion: str = Field(description="What this finding means for the case judgment. 对案件判断的意义。")


class AttackChainStep(BaseModel):
    attack_stage: AttackStage = Field(description="MITRE ATT&CK stage. 攻击阶段。")
    description: str = Field(
        description="What happened, how it was achieved, and supporting evidence. 阶段描述与证据。")


class TimelineEvent(BaseModel):
    timestamp: str = Field(description="Time of event; relative or approximate if exact time unavailable. 事件时间。")
    attack_behavior: str = Field(description="Key behavior or detection at this time point. 关键行为或检测现象。")
    evidence_field: str = Field(description="Key log field, raw excerpt, or correlated evidence. 关键日志字段或原文片段。")


class IndicatorOfCompromise(BaseModel):
    indicator_type: str = Field(description="IOC type. IOC 类型。")
    value: str = Field(description="The IOC value. IOC 具体值。")
    context: str = Field(description="Role in this case, e.g. download URL, C2, dropped file. 本案中的作用。")


class Remediation(BaseModel):
    action_type: str = Field(description="Action type, e.g. Isolate host, Disable account, Block URL. 处置动作类型。")
    description: str = Field(description="Specific, directly actionable recommendation. 具体可执行的建议。")
    priority: CasePriority = Field(description="Execution priority of this action. 执行优先级。")


class InvestigationReport(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    verdict: CaseVerdict = Field(description="Final case determination, e.g. True Positive, Suspicious, False Positive. 案件最终性质判定。")
    severity: Severity = Field(description="Incident severity. 事件严重程度。")
    impact: Impact = Field(description="Incident impact scope. 事件影响范围。")
    priority: CasePriority = Field(description="Response priority. 响应优先级。")
    confidence: Confidence = Field(description="Assessment confidence. 评估置信度。")
    digest: str = Field(description="Conclusive summary of the case. 案件综合摘要。")
    affected_assets: List[AffectedAsset] = Field(description="Directly affected or operated assets. 受影响资产列表。")
    evidence_findings: List[EvidenceFinding] = Field(description="Key findings supporting the conclusion. 关键证据发现列表。")
    attack_chain: List[AttackChainStep] = Field(description="Confirmed behavioral chain. 已确认的行为链。")
    attack_timeline: List[TimelineEvent] = Field(description="Key events in chronological order. 关键事件时间线。")
    ioc_indicators: List[IndicatorOfCompromise] = Field(description="IOCs for investigation or monitoring. 可用于排查或监控的 IOC 列表。")
    remediations: List[Remediation] = Field(description="Remediation recommendations. 处置与加固建议。")
    unknowns: List[str] = Field(description="Unconfirmed items requiring additional evidence. 需要补证的不确定点。")


class KnowledgeSearchKeywords(BaseModel):
    keywords: List[str] = Field(default_factory=list, description="Knowledge search keywords generated from the Case.")


class AnalysisRecord(BaseModel):
    """调度元数据 + AI 调查报告的完整存储单元。"""
    trigger: str | None = Field(default=None, description="触发本次分析的来源标识。")
    analysis_queue_message_id: str | None = Field(default=None, description="触发本次分析的队列消息 ID。")
    analysis_next_run_at: str | None = Field(default=None, description="下一次分析执行时间（ISO 8601）。")
    analysis_last_started_at: str | None = Field(default=None, description="本次分析实际开始时间（ISO 8601）。")
    analysis_last_completed_at: str | None = Field(default=None, description="本次分析完成时间（ISO 8601）。")
    knowledge_keywords: List[str] = Field(default_factory=list, description="本次分析用于检索 Knowledge 的关键词。")
    knowledge_records: List[dict[str, Any]] = Field(default_factory=list, description="本次分析使用的 Knowledge 记录。")
    report: InvestigationReport


def normalize_knowledge_keywords(keywords: List[str]) -> List[str]:
    normalized_keywords = []
    seen_keywords = set()
    for keyword in keywords or []:
        if not isinstance(keyword, str):
            continue
        keyword = " ".join(keyword.strip().split())
        if not keyword:
            continue
        if len(keyword) > 80:
            keyword = keyword[:80]
        keyword_key = keyword.casefold()
        if keyword_key in seen_keywords:
            continue
        normalized_keywords.append(keyword)
        seen_keywords.add(keyword_key)
        if len(normalized_keywords) >= MAX_KNOWLEDGE_KEYWORDS:
            break
    return normalized_keywords


def extract_knowledge_keywords(case_json: str) -> List[str]:
    try:
        system_prompt = KNOWLEDGE_KEYWORDS_PROMPT_PATH.read_text(encoding="utf-8")
        llm = LLMAPI().get_model(tag="structured_output").with_structured_output(KnowledgeSearchKeywords)
        result = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=case_json),
        ])
        if isinstance(result, KnowledgeSearchKeywords):
            raw_keywords = result.keywords
        elif isinstance(result, list):
            raw_keywords = result
        else:
            logger.warning(f"Unexpected keywords result type: {type(result)}")
            return []
        knowledge_keywords = normalize_knowledge_keywords(raw_keywords)
        return knowledge_keywords
    except Exception as e:
        logger.exception(e)
        return []


def search_knowledge_records(keywords: List[str]) -> List[dict[str, Any]]:
    if not keywords:
        return []
    try:
        records = Knowledge.search_models(keywords, limit=MAX_KNOWLEDGE_RECORDS)
        knowledge_records = [record.model_dump_for_ai(profile=AI_PROFILE_MCP) for record in records]
        return knowledge_records
    except Exception as e:
        logger.exception(e)
        return []


def build_analysis_input_json(case_json: str, knowledge_keywords: List[str], knowledge_records: List[dict[str, Any]],
                              discussions: List[dict[str, Any]] | None = None) -> str:
    try:
        case_data = json.loads(case_json)
    except json.JSONDecodeError:
        case_data = case_json

    payload = {
        "knowledge": {
            "records": knowledge_records,
            "keywords": knowledge_keywords,
        },
        "case": case_data,
        "discussions": discussions or [],
    }
    analysis_input_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    estimated_tokens = len(analysis_input_json) // 3
    logger.info(
        f"Analysis input built. chars={len(analysis_input_json)}, estimated_tokens≈{estimated_tokens}, knowledge={len(knowledge_records)}, discussions={len(discussions or [])}")
    return analysis_input_json


def generate_investigation_report(analysis_input_json: str) -> InvestigationReport:
    system_prompt = PROMPT_PATH.read_text(encoding="utf-8")
    llm = LLMAPI().get_model(tag="structured_output").with_structured_output(InvestigationReport)
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=analysis_input_json),
    ]
    report: InvestigationReport = llm.invoke(messages)
    return report


def build_analysis_record(
        trigger: str,
        queue_message_id: str | None,
        next_run_at: str | None,
        case: CaseModel,
        knowledge_keywords: List[str],
        knowledge_records: List[dict[str, Any]],
        report: InvestigationReport,
) -> AnalysisRecord:
    analysis_record = AnalysisRecord(
        trigger=trigger,
        analysis_queue_message_id=queue_message_id,
        analysis_next_run_at=next_run_at,
        analysis_last_started_at=(
            case.analysis_last_started_at.isoformat() if case.analysis_last_started_at else None
        ),
        analysis_last_completed_at=datetime.now().astimezone().isoformat(),
        knowledge_keywords=knowledge_keywords,
        knowledge_records=knowledge_records,
        report=report,
    )
    return analysis_record


def build_case_analysis_patch(
        case_row_id: str,
        report: InvestigationReport,
        analysis_record: AnalysisRecord,
) -> CaseModel:
    case_patch = CaseModel(
        row_id=case_row_id,
        verdict_ai=report.verdict,
        severity_ai=report.severity,
        impact_ai=report.impact,
        priority_ai=report.priority,
        confidence_ai=report.confidence,
        investigation_report_ai_json=analysis_record.model_dump_json(),
    )
    return case_patch


def run_case_analysis(case_row_id: str, trigger: str, queue_message_id: str | None = None) -> None:
    case = Case.get(case_row_id, lazy_load=False)
    if not case:
        logger.error(f"Case analysis skipped, case not found. row_id: {case_row_id}")
        return

    # The queue message may arrive slightly before the case row persists the latest queued message ID.
    # 队列消息可能会比 case 上的最新 message_id 落库更早到达，因此这里做一次短暂重读。
    if queue_message_id and case.analysis_queue_message_id != queue_message_id:
        time.sleep(0.2)
        case = Case.get(case_row_id, lazy_load=False)
        if not case:
            logger.error(f"Case analysis skipped, case missing after queue retry. row_id: {case_row_id}")
            return

    if queue_message_id and case.analysis_queue_message_id and case.analysis_queue_message_id != queue_message_id:
        logger.info(
            f"Case analysis skipped due to stale queue message. row_id: {case_row_id}, "
            f"case_message_id: {case.analysis_queue_message_id}, queue_message_id: {queue_message_id}"
        )
        return

    if queue_message_id and case.analysis_queue_message_id != queue_message_id:
        logger.info(
            f"Case analysis skipped because queue message does not match current queued message. "
            f"row_id: {case_row_id}, case_message_id: {case.analysis_queue_message_id}, queue_message_id: {queue_message_id}"
        )
        return

    # Starting the run clears the queue occupancy and consumes the current next_run_at.
    # 开始执行时会清掉队列占位，并消费当前这一次待执行计划。
    # Capture scheduling metadata before start clears queue_message_id and next_run_at.
    # 在 start 前采集调度元数据（start 之后这两个字段会被清空）。
    _pre_start_queue_message_id = case.analysis_queue_message_id
    _pre_start_next_run_at = (
        case.analysis_next_run_at.isoformat() if case.analysis_next_run_at else None
    )
    start_result = Case.mark_analysis_started(case_row_id, queue_message_id=queue_message_id)
    if start_result is None:
        logger.info(f"Case analysis skipped, failed to mark analysis as started. row_id: {case_row_id}")
        return

    case = Case.get(case_row_id, lazy_load=False)
    if not case:
        logger.error(f"Case analysis aborted, case missing after start marker update. row_id: {case_row_id}")
        return

    try:
        case_json = case.model_dump_json_for_ai(profile=AI_PROFILE_INVESTIGATION)
        knowledge_keywords = extract_knowledge_keywords(case_json)
        knowledge_records = search_knowledge_records(knowledge_keywords)
        discussions = Case.get_discussions_by_row_id(case_row_id) or []
        analysis_input_json = build_analysis_input_json(case_json, knowledge_keywords, knowledge_records, discussions)
        report = generate_investigation_report(analysis_input_json)
        analysis_record = build_analysis_record(
            trigger=trigger,
            queue_message_id=_pre_start_queue_message_id,
            next_run_at=_pre_start_next_run_at,
            case=case,
            knowledge_keywords=knowledge_keywords,
            knowledge_records=knowledge_records,
            report=report,
        )
        case_patch = build_case_analysis_patch(case_row_id, report, analysis_record)

        Case.update(case_patch)
        Case.mark_analysis_completed(case_row_id)
    except Exception as e:
        logger.exception(e)
        Case.mark_analysis_failed(case_row_id, error=str(e))


class KnowledgeExtractionResult(BaseModel):
    has_knowledge: bool = Field(description="Whether the case contains reusable knowledge. 是否包含可复用知识。")
    title: Optional[str] = Field(default=None, description="Knowledge title. 知识标题。")
    body: Optional[str] = Field(default=None, description="Knowledge content in Markdown. Markdown 格式的知识内容。")
    tags: Optional[List[str]] = Field(default=None, description="Knowledge tags for searchability. 可用于搜索的知识标签。")
    reason: str = Field(description="Brief explanation of the extraction decision. 提取或不提取的简要原因。")


def extract_knowledge_from_case(case_id: str, case_json: str, discussions: List[dict[str, Any]]) -> KnowledgeExtractionResult:
    system_prompt = KNOWLEDGE_EXTRACTION_PROMPT_PATH.read_text(encoding="utf-8")
    llm = LLMAPI().get_model(tag="structured_output").with_structured_output(KnowledgeExtractionResult)
    try:
        case_data = json.loads(case_json)
    except json.JSONDecodeError:
        case_data = case_json
    input_json = json.dumps({"case_id": case_id, "case": case_data, "discussions": discussions}, ensure_ascii=False, separators=(",", ":"))
    result = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=input_json),
    ])
    return result
