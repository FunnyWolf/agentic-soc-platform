from typing import List

from langchain_core.messages import HumanMessage
from pydantic import BaseModel, ConfigDict, Field

from Lib.baseplaybook import BasePlaybook
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpcoremodel import AttackStage, CaseModel, CasePriority, CaseVerdict, Confidence, Impact, Severity
from PLUGINS.SIRP.sirpextramodel import PlaybookModel


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


class Playbook(BasePlaybook):
    NAME = "Investigation Agent"
    DESC = "Investigation Agent"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        case = Case.get(self.param_source_row_id)
        content = case.model_dump_json_for_ai()

        system_message = self.load_system_prompt_template("Investigation_System").format()

        llm_api = LLMAPI()
        llm = llm_api.get_model(tag="structured_output")

        messages = [
            system_message,
            HumanMessage(content=content)
        ]
        llm = llm.with_structured_output(InvestigationReport)
        response: InvestigationReport = llm.invoke(messages)

        case_new = CaseModel(
            row_id=self.param_source_row_id,
            verdict_ai=response.verdict,
            severity_ai=response.severity,
            impact_ai=response.impact,
            priority_ai=response.priority,
            confidence_ai=response.confidence,
            summary_ai=response.digest,
            investigation_report_ai_json=response.model_dump_json(),
        )
        Case.update(case_new)
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    model = PlaybookModel(source_row_id='b6383d3f-bbdc-432b-9ac7-debb25535617')
    module = Playbook()
    module._playbook_model = model

    module.run()
