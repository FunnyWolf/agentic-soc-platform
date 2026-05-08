from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import List

from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, ConfigDict, Field

from Lib.configs import DATA_DIR
from Lib.log import logger
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpbasemodel import AI_PROFILE_INVESTIGATION
from PLUGINS.SIRP.sirpcoremodel import AttackStage, CaseModel, CasePriority, CaseVerdict, Confidence, Impact, Severity

PROMPT_PATH = Path(DATA_DIR) / "Investigation_Agent" / "Investigation_System.md"


class AffectedAsset(BaseModel):
    asset_type: str = Field(description="受影响或被攻击者直接操作的资产类型，例如 Host、IP、User、Mailbox、File、Cloud Resource。")
    asset_value: str = Field(description="资产的具体标识，例如主机名、IP、用户名、邮箱地址、文件路径、云资源 ARN。")


class EvidenceFinding(BaseModel):
    title: str = Field(description="关键发现标题，例如 可疑登录成功后修改邮箱转发规则、主机A出现横向移动痕迹。")
    finding_type: str = Field(description="发现类型，例如 Identity、Host、Process、Network、Email、Cloud、Policy、Ticket、Other。")
    subject: str = Field(description="该发现围绕的主体，例如某账号、主机、IP、URL、策略名或告警簇。")
    evidence: str = Field(description="支撑该发现的核心证据摘要，尽量写出可追溯的字段、对象或现象。")
    conclusion: str = Field(description="基于该证据得出的结论，说明它在本案中意味着什么。")


class AttackChainStep(BaseModel):
    attack_stage: AttackStage = Field(description="MITRE ATT&CK 攻击阶段。")
    description: str = Field(description="该阶段发生了什么、攻击者如何实现、证据依据是什么。")


class TimelineEvent(BaseModel):
    timestamp: str = Field(description="事件发生时间；若无法精确确定，可填相对时间或近似时间。")
    attack_behavior: str = Field(description="该时间点发生的关键行为、操作或检测现象。")
    evidence_field: str = Field(description="支撑该结论的关键日志字段、原文片段或关联证据。")


class IndicatorOfCompromise(BaseModel):
    indicator_type: str = Field(description="IOC 类型，只能从 IP、Domain、URL、FileHash、FilePath、Command、RegistryKey 中选择。")
    value: str = Field(description="IOC 的具体值。")
    context: str = Field(description="该 IOC 在本案中的上下文，例如作为下载地址、C2、落地文件、横向移动命令等。")


class Remediation(BaseModel):
    action_type: str = Field(description="处置动作类型，例如隔离主机、禁用账号、阻断 URL、删除文件、修复配置。")
    description: str = Field(description="可直接执行的处置或加固建议，要求具体。")
    priority: CasePriority = Field(description="该处置动作自身的执行优先级。")


class InvestigationReport(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    verdict: CaseVerdict = Field(description="AI 对案件最终性质的判断，例如 True Positive、Suspicious、False Positive、Insufficient Data。")
    severity: Severity = Field(description="AI 评估的事件严重程度。")
    impact: Impact = Field(description="AI 评估的事件影响等级。")
    priority: CasePriority = Field(description="AI 评估的响应优先级。")
    confidence: Confidence = Field(description="AI 评估的事件置信度。")
    digest: str = Field(description="事件综合摘要。")
    affected_assets: List[AffectedAsset] = Field(description="受影响资产列表。")
    evidence_findings: List[EvidenceFinding] = Field(description="支撑案件结论的关键证据发现列表。")
    attack_chain: List[AttackChainStep] = Field(description="基于证据重建的攻击链步骤。")
    attack_timeline: List[TimelineEvent] = Field(description="按时间顺序排列的关键事件时间线。")
    ioc_indicators: List[IndicatorOfCompromise] = Field(description="可用于排查、封禁、搜索或持续监控的 IOC 列表。")
    remediations: List[Remediation] = Field(description="面向分析员的处置与加固建议。")
    unknowns: List[str] = Field(description="当前仍无法确认、需要补证或需要进一步排查的不确定点列表。")


class AnalysisRecord(BaseModel):
    """调度元数据 + AI 调查报告的完整存储单元。"""
    trigger: str | None = Field(default=None, description="触发本次分析的来源标识。")
    analysis_queue_message_id: str | None = Field(default=None, description="触发本次分析的队列消息 ID。")
    analysis_next_run_at: str | None = Field(default=None, description="下一次分析执行时间（ISO 8601）。")
    analysis_last_started_at: str | None = Field(default=None, description="本次分析实际开始时间（ISO 8601）。")
    analysis_last_completed_at: str | None = Field(default=None, description="本次分析完成时间（ISO 8601）。")
    report: InvestigationReport


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
        content = PROMPT_PATH.read_text(encoding="utf-8")
        system_message = SystemMessage(content=content)
        content = case.model_dump_json_for_ai(profile=AI_PROFILE_INVESTIGATION)

        llm = LLMAPI().get_model(tag="structured_output").with_structured_output(InvestigationReport)
        messages = [
            system_message,
            HumanMessage(content=content),
        ]

        report: InvestigationReport = llm.invoke(messages)
        #
        # logger.info(f"Case analysis test mode active. row_id: {case_row_id}, trigger: {trigger}")
        # import random
        # time.sleep(random.uniform(30.0, 60.0))
        # report = InvestigationReport(
        #     verdict=CaseVerdict.SUSPICIOUS,
        #     severity=Severity.MEDIUM,
        #     impact=Impact.MEDIUM,
        #     priority=CasePriority.MEDIUM,
        #     confidence=Confidence.MEDIUM,
        #     digest=f"Stub investigation report for case {case_row_id}.",
        #     affected_assets=[
        #         AffectedAsset(asset_type="Host", asset_value="stub-host")
        #     ],
        #     evidence_findings=[
        #         EvidenceFinding(
        #             title="Stub evidence finding",
        #             finding_type="Other",
        #             subject=case.title or case_row_id,
        #             evidence="Synthetic evidence generated for runner validation.",
        #             conclusion="This is a non-production placeholder result for queue and scheduler testing.",
        #         )
        #     ],
        #     attack_chain=[
        #         AttackChainStep(
        #             attack_stage=AttackStage.DISCOVERY,
        #             description="Placeholder attack-chain step used for validating the investigation pipeline.",
        #         )
        #     ],
        #     attack_timeline=[
        #         TimelineEvent(
        #             timestamp=str(case.row_updatedAt or case.row_createdAt or "unknown"),
        #             attack_behavior="Stub timeline event for pipeline verification.",
        #             evidence_field="synthetic_test_event",
        #         )
        #     ],
        #     ioc_indicators=[
        #         IndicatorOfCompromise(
        #             indicator_type="IP",
        #             value="203.0.113.10",
        #             context="Synthetic IOC for non-LLM runner testing.",
        #         )
        #     ],
        #     remediations=[
        #         Remediation(
        #             action_type="Review",
        #             description="Review this stub output and verify case state transitions in the UI and worksheet.",
        #             priority=CasePriority.LOW,
        #         )
        #     ],
        #     unknowns=[
        #         "This is a stub result; no real investigation was performed."
        #     ],
        # )

        case_patch = CaseModel(
            row_id=case_row_id,
            verdict_ai=report.verdict,
            severity_ai=report.severity,
            impact_ai=report.impact,
            priority_ai=report.priority,
            confidence_ai=report.confidence,
            investigation_report_ai_json=AnalysisRecord(
                trigger=trigger,
                analysis_queue_message_id=_pre_start_queue_message_id,
                analysis_next_run_at=_pre_start_next_run_at,
                analysis_last_started_at=(
                    case.analysis_last_started_at.isoformat() if case.analysis_last_started_at else None
                ),
                analysis_last_completed_at=datetime.now().astimezone().isoformat(),
                report=report,
            ).model_dump_json(),
        )

        Case.update(case_patch)
        Case.mark_analysis_completed(case_row_id)
        logger.info(f"Case analysis completed. row_id: {case_row_id}, trigger: {trigger}")
    except Exception as e:
        logger.exception(e)
        Case.mark_analysis_failed(case_row_id, error=str(e))
