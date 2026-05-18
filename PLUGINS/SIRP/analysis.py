from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Any

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
MAX_KNOWLEDGE_KEYWORDS = 8
MAX_KNOWLEDGE_RECORDS = 10


class AffectedAsset(BaseModel):
    asset_type: str = Field(
        description="Type of asset affected or directly operated by the attacker, e.g. Host, IP, User, Mailbox, File, Cloud Resource. 受影响或被攻击者直接操作的资产类型，例如 Host、IP、User、Mailbox、File、Cloud Resource。")
    asset_value: str = Field(
        description="Specific identifier of the asset, e.g. hostname, IP, username, email address, file path, cloud resource ARN. 资产的具体标识，例如主机名、IP、用户名、邮箱地址、文件路径、云资源 ARN。")


class EvidenceFinding(BaseModel):
    title: str = Field(
        description="Title of the key finding, e.g. Suspicious login followed by mailbox forwarding rule modification, Lateral movement detected on Host A. 关键发现标题，例如 可疑登录成功后修改邮箱转发规则、主机A出现横向移动痕迹。")
    finding_type: str = Field(
        description="Type of finding, e.g. Identity, Host, Process, Network, Email, Cloud, Policy, Ticket, Other. 发现类型，例如 Identity、Host、Process、Network、Email、Cloud、Policy、Ticket、Other。")
    subject: str = Field(
        description="The subject of this finding, e.g. an account, host, IP, URL, policy name, or alert cluster. 该发现围绕的主体，例如某账号、主机、IP、URL、策略名或告警簇。")
    evidence: str = Field(
        description="Summary of core evidence supporting this finding; include traceable fields, objects, or phenomena where possible. 支撑该发现的核心证据摘要，尽量写出可追溯的字段、对象或现象。")
    conclusion: str = Field(
        description="Conclusion drawn from the evidence, explaining what it means in the context of this case. 基于该证据得出的结论，说明它在本案中意味着什么。")


class AttackChainStep(BaseModel):
    attack_stage: AttackStage = Field(description="MITRE ATT&CK attack stage. MITRE ATT&CK 攻击阶段。")
    description: str = Field(
        description="What happened at this stage, how the attacker achieved it, and the supporting evidence. 该阶段发生了什么、攻击者如何实现、证据依据是什么。")


class TimelineEvent(BaseModel):
    timestamp: str = Field(
        description="Time the event occurred; use relative or approximate time if exact time cannot be determined. 事件发生时间；若无法精确确定，可填相对时间或近似时间。")
    attack_behavior: str = Field(description="Key behavior, operation, or detection phenomenon at this point in time. 该时间点发生的关键行为、操作或检测现象。")
    evidence_field: str = Field(
        description="Key log field, raw excerpt, or correlated evidence supporting this conclusion. 支撑该结论的关键日志字段、原文片段或关联证据。")


class IndicatorOfCompromise(BaseModel):
    indicator_type: str = Field(description="IOC type;IOC 类型。")
    value: str = Field(description="The specific value of the IOC. IOC 的具体值。")
    context: str = Field(
        description="Context of this IOC in the case, e.g. used as download URL, C2, dropped file, lateral movement command. 该 IOC 在本案中的上下文，例如作为下载地址、C2、落地文件、横向移动命令等。")


class Remediation(BaseModel):
    action_type: str = Field(
        description="Type of remediation action, e.g. Isolate host, Disable account, Block URL, Delete file, Fix configuration. 处置动作类型，例如隔离主机、禁用账号、阻断 URL、删除文件、修复配置。")
    description: str = Field(description="Specific and directly actionable remediation or hardening recommendation. 可直接执行的处置或加固建议，要求具体。")
    priority: CasePriority = Field(description="Execution priority of this remediation action itself. 该处置动作自身的执行优先级。")


class InvestigationReport(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    verdict: CaseVerdict = Field(
        description="AI's final determination of the case nature, e.g. True Positive, Suspicious, False Positive, Insufficient Data. AI 对案件最终性质的判断，例如 True Positive、Suspicious、False Positive、Insufficient Data。")
    severity: Severity = Field(description="Severity level of the incident as assessed by AI. AI 评估的事件严重程度。")
    impact: Impact = Field(description="Impact level of the incident as assessed by AI. AI 评估的事件影响等级。")
    priority: CasePriority = Field(description="Response priority as assessed by AI. AI 评估的响应优先级。")
    confidence: Confidence = Field(description="Confidence level of the assessment as determined by AI. AI 评估的事件置信度。")
    digest: str = Field(description="Comprehensive summary of the incident. 事件综合摘要。")
    affected_assets: List[AffectedAsset] = Field(description="List of affected assets. 受影响资产列表。")
    evidence_findings: List[EvidenceFinding] = Field(
        description="List of key evidence findings supporting the case conclusion. 支撑案件结论的关键证据发现列表。")
    attack_chain: List[AttackChainStep] = Field(description="Attack chain steps reconstructed from evidence. 基于证据重建的攻击链步骤。")
    attack_timeline: List[TimelineEvent] = Field(description="Chronologically ordered list of key events. 按时间顺序排列的关键事件时间线。")
    ioc_indicators: List[IndicatorOfCompromise] = Field(
        description="IOC list for investigation, blocking, hunting, or ongoing monitoring. 可用于排查、封禁、搜索或持续监控的 IOC 列表。")
    remediations: List[Remediation] = Field(description="Remediation and hardening recommendations for analysts. 面向分析员的处置与加固建议。")
    unknowns: List[str] = Field(
        description="List of unconfirmed points that require additional evidence or further investigation. 当前仍无法确认、需要补证或需要进一步排查的不确定点列表。")


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
        result: KnowledgeSearchKeywords = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=case_json),
        ])
        knowledge_keywords = normalize_knowledge_keywords(result.keywords)
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
