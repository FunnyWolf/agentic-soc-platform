import json
from typing import Dict, List, Optional

from langchain_core.messages import HumanMessage
from pydantic import BaseModel, ConfigDict, Field

from Lib.baseplaybook import BasePlaybook
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpcoremodel import AttackStage, CaseModel, CasePriority, Confidence, Impact, Severity
from PLUGINS.SIRP.sirpextramodel import PlaybookModel


class AffectedAsset(BaseModel):
    asset_type: str = Field(description="受影响或被攻击者直接操作的资产类型，例如 Host、IP、User、Mailbox、File、Cloud Resource。")
    asset_value: str = Field(description="资产的具体标识，例如主机名、IP、用户名、邮箱地址、文件路径、云资源 ARN。")


class ArtifactAnalysis(BaseModel):
    artifact_name: str = Field(description="痕迹、样本或关键对象的标识，例如文件名、进程名、URL、策略名。")
    artifact_type: str = Field(description="痕迹类型，例如 File、Process、Network Traffic、API Call、IAM Policy。")
    properties: Dict[str, str] = Field(
        description="与该痕迹直接相关的关键属性键值对，例如 Hash、Path、CommandLine、UserAgent、APIName、Parameters。"
    )
    analysis_result: str = Field(description="针对该痕迹的技术分析结论，说明其行为、作用、风险和与本案的关联。")
    threat_intelligence: Optional[str] = Field(description="与该痕迹相关的情报、标签或信誉结论；无证据时写空字符串。")


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


class RemediationRecommendation(BaseModel):
    action_type: str = Field(description="处置动作类型，例如隔离主机、禁用账号、阻断 URL、删除文件、修复配置。")
    description: str = Field(description="可直接执行的处置或加固建议，要求具体。")
    priority: CasePriority = Field(description="该处置动作自身的执行优先级。")


class IncidentReport(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    severity: Severity = Field(description="AI 评估的事件严重程度，必须结合攻击链深度、权限水平、受影响范围和业务风险判断。")
    impact: Impact = Field(description="AI 评估的事件影响等级，必须反映事件对资产、账号、数据和业务的实际或潜在影响。")
    priority: CasePriority = Field(description="AI 评估的响应优先级，必须结合当前风险、是否仍在持续、以及是否需要立即响应判断。")
    confidence: Confidence = Field(
        description="事件置信度。High 表示多源证据交叉验证；Medium 表示证据基本闭环但仍有缺口；Low 表示证据不足或更像噪声。"
    )
    digest: str = Field(
        description="事件综合摘要。必须写成详细结论性摘要，至少覆盖：1. 是否真实安全事件；2. 攻击者关键行为与攻击链；3. 已获得的最高权限或控制能力；4. 影响范围与业务风险；5. 关键证据与不确定性。禁止只写一句空泛结论。"
    )
    affected_assets: List[AffectedAsset] = Field(
        description="受影响资产或被攻击者直接操作的目标资产列表。若无法确认真实受影响范围，可列出当前证据支持的潜在目标，并在描述中说明不确定性。"
    )
    attack_chain: List[AttackChainStep] = Field(description="基于证据重建的攻击链步骤，按逻辑顺序排列，只保留有证据支撑的阶段。")
    attack_timeline: List[TimelineEvent] = Field(description="按时间顺序排列的关键事件时间线；无法精确排序时，也要给出相对先后关系。")
    ioc_indicators: List[IndicatorOfCompromise] = Field(description="可用于排查、封禁、搜索或持续监控的 IOC 列表。")
    remediation_recommendations: List[RemediationRecommendation] = Field(
        description="面向分析员的处置与加固建议，要求具体、可执行，并按优先级组织。"
    )


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
        llm = llm.with_structured_output(IncidentReport)
        response: IncidentReport = llm.invoke(messages)

        report_payload = response.model_dump(mode="json")
        comment_payload = {
            key: value
            for key, value in report_payload.items()
            if key not in {"severity", "impact", "priority", "confidence"}
        }

        case_new = CaseModel(
            row_id=self.param_source_row_id,
            severity_ai=response.severity,
            impact_ai=response.impact,
            priority_ai=response.priority,
            confidence_ai=response.confidence,
            comment_ai=json.dumps(comment_payload, ensure_ascii=False, indent=2),
        )
        Case.update(case_new)
        print(report_payload)
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
