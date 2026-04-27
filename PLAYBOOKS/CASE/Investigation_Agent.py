from typing import List, Dict, Optional

from langchain_core.messages import HumanMessage
from pydantic import BaseModel, Field

from Lib.baseplaybook import BasePlaybook
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpcoremodel import AttackStage, CasePriority, Confidence
from PLUGINS.SIRP.sirpextramodel import PlaybookModel


class AffectedAsset(BaseModel):
    asset_type: str = Field(description="资产的类型, 例如Host, IP, User, File, Cloud Resource.")
    asset_value: str = Field(description="资产的具体标识符, 例如IP地址, 主机名, 用户名, 资源ARN.")


class ArtifactAnalysis(BaseModel):
    artifact_name: str = Field(description="痕迹或载荷的标识符, 例如文件名, 进程名, URL或IAM角色名.")
    artifact_type: str = Field(description="痕迹的类型, 例如File, Process, Network Traffic, API Call, IAM Policy.")
    properties: Dict[str, str] = Field(
        description="动态属性键值对. 根据痕迹类型提取不同的关键属性, 例如文件可能包含MD5, Path; 网络请求可能包含Method, User-Agent; 云操作可能包含API Name, Parameters.")
    analysis_result: str = Field(description="对该痕迹的深度技术分析, 解释其执行的恶意行为, 功能机制以及造成的威胁等级.")
    threat_intelligence: Optional[str] = Field(description="与该痕迹相关的威胁情报信息或标签, 如无则为空.")


class AttackChainStep(BaseModel):
    attack_stage: AttackStage = Field(description="攻击链的阶段名称.")
    description: str = Field(description="该阶段的具体行为说明, 描述攻击者如何利用漏洞或执行了什么操作.")


class TimelineEvent(BaseModel):
    timestamp: str = Field(description="事件发生的时间点.")
    attack_behavior: str = Field(description="在该时间点发生的具体攻击行为或检测到的动作.")
    evidence_field: str = Field(description="支撑该行为判断的关键证据字段或日志内容片段.")


class IndicatorOfCompromise(BaseModel):
    indicator_type: str = Field(description="IOC的类型, 必须从以下范围中选择: IP, Domain, URL, FileHash, FilePath, Command, RegistryKey.")
    value: str = Field(description="IOC的具体值, 例如具体的IP地址, MD5字符串或恶意文件路径.")
    context: str = Field(description="简述该IOC在本次事件中的上下文描述, 例如作为C2服务器建立网络连接或被释放的后门文件.")


class RemediationRecommendation(BaseModel):
    action_type: str = Field(description="处置或加固动作的类型, 例如隔离主机, 封禁IP, 清除文件, 修复漏洞等.")
    description: str = Field(description="具体的处置步骤或系统加固建议说明.")
    priority: CasePriority = Field(description="该建议的执行优先级, 例如High, Medium, Low.")


class IncidentReport(BaseModel):
    affected_assets: List[AffectedAsset] = Field(description="受此次事件影响或作为目标的资产列表.")
    attack_chain: List[AttackChainStep] = Field(description="重建的攻击链结构化步骤列表.")
    attack_timeline: List[TimelineEvent] = Field(description="按时间顺序排列的事件时间线.")
    ioc_indicators: List[IndicatorOfCompromise] = Field(description="结构化提取的妥协指标列表.")
    digest: str = Field(description="事件的综合摘要. 需确认攻击是否真实发生, 攻击者获取的最高权限, 核心恶意行为以及总体的影响评估.")
    remediation_recommendations: List[RemediationRecommendation] = Field(description="针对该事件的处置与系统加固建议列表.")
    confidence: Confidence = Field(description="事件的置信度.")


class Playbook(BasePlaybook):
    NAME = "Investigation Agent"
    DESC = "Investigation Agent"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        case = Case.get(self.param_source_row_id)
        content = case.model_dump_json_for_ai()
        # Load system prompt
        system_message = self.load_system_prompt_template("Investigation_System").format()

        # Run
        llm_api = LLMAPI()

        llm = llm_api.get_model(tag="structured_output")

        # Construct message list
        messages = [
            system_message,
            HumanMessage(content=content)
        ]
        llm = llm.with_structured_output(IncidentReport)
        response = llm.invoke(messages)
        response: IncidentReport
        print(response)
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
