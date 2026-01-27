from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import List, Optional, Any, Union, ClassVar

from pydantic import BaseModel, Field, field_validator, ConfigDict, field_serializer

from PLUGINS.SIRP.nocolymodel import AttachmentModel, AccountModel


# region Enums

# class WfStatus(StrEnum):
#     PASS = "通过"
#     REJECT = "否决"
#     ABORT = "中止"
#     IN_PROGRESS = "进行中"
#     EMPTY = ""


class MessageType(StrEnum):
    SYSTEM = "SystemMessage"
    HUMAN = "HumanMessage"
    TOOL = "ToolMessage"
    AI = "AIMessage"


class PlaybookType(StrEnum):
    CASE = "CASE"
    ALERT = "ALERT"
    ARTIFACT = "ARTIFACT"


class KnowledgeSource(StrEnum):
    MANUAL = "Manual"
    CASE = "Case"


class TicketStatus(StrEnum):
    UNKNOWN = 'Unknown'
    NEW = 'New'
    IN_PROGRESS = 'In Progress'
    NOTIFIED = 'Notified'
    ON_HOLD = 'On Hold'
    RESOLVED = 'Resolved'
    CLOSED = 'Closed'
    CANCELED = 'Canceled'
    REOPENED = 'Reopened'
    OTHER = 'Other'


class TicketType(StrEnum):
    OTHER = 'Other'
    JIRA = 'Jira'
    SERVICENOW = 'ServiceNow'
    PAGERDUTY = 'PagerDuty'
    SLACK = 'Slack'


class ArtifactType(StrEnum):
    UNKNOWN = 'Unknown'
    HOSTNAME = 'Hostname'
    IP_ADDRESS = 'IP Address'
    MAC_ADDRESS = 'MAC Address'
    USER_NAME = 'User Name'
    EMAIL_ADDRESS = 'Email Address'
    URL_STRING = 'URL String'
    FILE_NAME = 'File Name'
    HASH = 'Hash'
    PROCESS_NAME = 'Process Name'
    RESOURCE_UID = 'Resource UID'
    PORT = 'Port'
    SUBNET = 'Subnet'
    COMMAND_LINE = 'Command Line'
    COUNTRY = 'Country'
    PROCESS_ID = 'Process ID'
    HTTP_USER_AGENT = 'HTTP User-Agent'
    CWE = 'CWE'
    CVE = 'CVE'
    USER_CREDENTIAL_ID = 'User Credential ID'
    ENDPOINT = 'Endpoint'
    USER = 'User'
    EMAIL = 'Email'
    UNIFORM_RESOURCE_LOCATOR = 'Uniform Resource Locator'
    FILE = 'File'
    PROCESS = 'Process'
    GEO_LOCATION = 'Geo Location'
    CONTAINER = 'Container'
    REGISTRY = 'Registry'
    FINGERPRINT = 'Fingerprint'
    GROUP = 'Group'
    ACCOUNT = 'Account'
    SCRIPT_CONTENT = 'Script Content'
    SERIAL_NUMBER = 'Serial Number'
    RESOURCE = 'Resource'
    MESSAGE = 'Message'
    ADVISORY = 'Advisory'
    FILE_PATH = 'File Path'
    DEVICE = 'Device'
    OTHER = 'Other'


class ArtifactRole(StrEnum):
    UNKNOWN = 'Unknown'
    TARGET = 'Target'
    ACTOR = 'Actor'
    AFFECTED = 'Affected'
    RELATED = 'Related'
    OTHER = 'Other'


class ArtifactReputationScore(StrEnum):
    UNKNOWN = 'Unknown'
    VERY_SAFE = 'Very Safe'
    SAFE = 'Safe'
    PROBABLY_SAFE = 'Probably Safe'
    LEANS_SAFE = 'Leans Safe'
    MAY_NOT_BE_SAFE = 'May not be Safe'
    EXERCISE_CAUTION = 'Exercise Caution'
    SUSPICIOUS_RISKY = 'Suspicious/Risky'
    POSSIBLY_MALICIOUS = 'Possibly Malicious'
    PROBABLY_MALICIOUS = 'Probably Malicious'
    MALICIOUS = 'Malicious'
    OTHER = 'Other'


class Severity(StrEnum):
    UNKNOWN = "Unknown"
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    FATAL = "Fatal"
    OTHER = "Other"


class ImpactLevel(StrEnum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    OTHER = "Other"


class Disposition(StrEnum):
    UNKNOWN = "Unknown"
    ALLOWED = "Allowed"
    BLOCKED = "Blocked"
    QUARANTINED = "Quarantined"
    ISOLATED = "Isolated"
    DELETED = "Deleted"
    DROPPED = "Dropped"
    CUSTOM_ACTION = "Custom Action"
    APPROVED = "Approved"
    RESTORED = "Restored"
    EXONERATED = "Exonerated"
    CORRECTED = "Corrected"
    PARTIALLY_CORRECTED = "Partially Corrected"
    UNCORRECTED = "Uncorrected"
    DELAYED = "Delayed"
    DETECTED = "Detected"
    NO_ACTION = "No Action"
    LOGGED = "Logged"
    TAGGED = "Tagged"
    ALERT = "Alert"
    COUNT = "Count"
    RESET = "Reset"
    CAPTCHA = "Captcha"
    CHALLENGE = "Challenge"
    ACCESS_REVOKED = "Access Revoked"
    REJECTED = "Rejected"
    UNAUTHORIZED = "Unauthorized"
    ERROR = "Error"
    OTHER = "Other"


class AlertAction(StrEnum):
    UNKNOWN = "Unknown"
    ALLOWED = "Allowed"
    DENIED = "Denied"
    OBSERVED = "Observed"
    MODIFIED = "Modified"
    OTHER = "Other"


class Confidence(StrEnum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    OTHER = "Other"


class AlertAnalyticType(StrEnum):
    UNKNOWN = "Unknown"
    RULE = "Rule"
    BEHAVIORAL = "Behavioral"
    STATISTICAL = "Statistical"
    LEARNING = "Learning (ML/DL)"
    FINGERPRINTING = "Fingerprinting"
    TAGGING = "Tagging"
    KEYWORD_MATCH = "Keyword Match"
    REGULAR_EXPRESSIONS = "Regular Expressions"
    EXACT_DATA_MATCH = "Exact Data Match"
    PARTIAL_DATA_MATCH = "Partial Data Match"
    INDEXED_DATA_MATCH = "Indexed Data Match"
    OTHER = "Other"


class AlertAnalyticState(StrEnum):
    UNKNOWN = "Unknown"
    ACTIVE = "Active"
    SUPPRESSED = "Suppressed"
    EXPERIMENTAL = "Experimental"
    OTHER = "Other"


class ProductCategory(StrEnum):
    DLP = "DLP"
    EMAIL = "Email"
    OT = "OT"
    PROXY = "Proxy"
    UEBA = "UEBA"
    TI = "TI"
    IAM = "IAM"
    EDR = "EDR"
    NDR = "NDR"
    CLOUD = "Cloud"
    OTHER = "Other"


class AlertPolicyType(StrEnum):
    IDENTITY_POLICY = "Identity Policy"
    RESOURCE_POLICY = "Resource Policy"
    SERVICE_CONTROL_POLICY = "Service Control Policy"
    OTHER = "Other"


class AlertRiskLevel(StrEnum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    OTHER = "Other"


class AlertStatus(StrEnum):
    UNKNOWN = "Unknown"
    NEW = "New"
    IN_PROGRESS = "In Progress"
    SUPPRESSED = "Suppressed"
    RESOLVED = "Resolved"
    ARCHIVED = "Archived"
    DELETED = "Deleted"
    OTHER = "Other"


class CasePriority(StrEnum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    OTHER = "Other"


class CaseStatus(StrEnum):
    UNKNOWN = "Unknown"
    NEW = "New"
    IN_PROGRESS = "In Progress"
    ON_HOLD = "On Hold"
    RESOLVED = "Resolved"
    CLOSED = "Closed"
    OTHER = "Other"


class CaseVerdict(StrEnum):
    UNKNOWN = "Unknown"
    FALSE_POSITIVE = "False Positive"
    TRUE_POSITIVE = "True Positive"
    DISREGARD = "Disregard"
    SUSPICIOUS = "Suspicious"
    BENIGN = "Benign"
    TEST = "Test"
    INSUFFICIENT_DATA = "Insufficient Data"
    SECURITY_RISK = "Security Risk"
    MANAGED_EXTERNALLY = "Managed Externally"
    DUPLICATE = "Duplicate"
    OTHER = "Other"


class PlaybookJobStatus(StrEnum):
    SUCCESS = 'Success'
    FAILED = 'Failed'
    PENDING = 'Pending'
    RUNNING = 'Running'


class KnowledgeAction(StrEnum):
    STORE = 'Store'
    REMOVE = 'Remove'
    DONE = 'Done'


# endregion Enums


class BaseSystemModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    ai_exclude_fields: ClassVar[set[str]] = set()

    rowid: Optional[str] = Field(default=None, description="数据的唯一行ID")
    ownerid: Optional[AccountModel] = Field(default=None, description="数据的所有者")
    caid: Optional[AccountModel] = Field(default=None, description="创建人")
    ctime: Optional[Union[datetime, str]] = Field(default=None, description="创建时间")
    utime: Optional[Union[datetime, str]] = Field(default=None, description="最后更新时间")
    uaid: Optional[AccountModel] = Field(default=None, description="最后更新人")

    # 流程相关参数
    # wfname: Optional[str] = Field(default=None, description="关联的工作流名称")
    # wfcuaids: Optional[Any] = Field(default=None, description="工作流当前处理人列表")
    # wfcaid: Optional[Any] = Field(default=None, description="工作流当前激活的处理人")
    # wfctime: Optional[Union[datetime, str]] = Field(default=None, description="工作流创建时间")
    # wfrtime: Optional[Union[datetime, str]] = Field(default=None, description="工作流接收时间")
    # wfcotime: Optional[Union[datetime, str]] = Field(default=None, description="工作流完成时间")
    # wfdtime: Optional[Union[datetime, str]] = Field(default=None, description="工作流截止时间")
    # wfftime: Optional[Any] = Field(default=None, description="工作流关注时间")
    # wfstatus: Optional[WfStatus] = Field(default=None, description="工作流状态")

    @field_validator(
        "ctime", "utime", "wfctime", "wfrtime", "wfcotime", "wfdtime",
        "created_time", "modified_time", "first_seen_time", "last_seen_time", "acknowledged_time", "closed_time",
        check_fields=False
    )
    @classmethod
    def parse_datetime(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip():
            try:
                return datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                return v
        return v

    @field_serializer(
        "ctime", "utime", "wfctime", "wfrtime", "wfcotime", "wfdtime",
        "created_time", "modified_time", "first_seen_time", "last_seen_time", "acknowledged_time", "closed_time",
        check_fields=False,
        when_used="json"
    )
    def serialize_datetime(self, v: Any) -> Any:
        if isinstance(v, datetime):
            # 强制输出为你需要的格式
            return v.strftime("%Y-%m-%dT%H:%M:%SZ")
        return v

    def model_dump_json_for_ai(
            self,
            *,
            exclude_none: bool = True,
            exclude_unset: bool = True,
            exclude_default: bool = True,
    ) -> str:
        """
        递归序列化模型为 AI 友好的 JSON 字符串格式。
        在序列化前处理嵌套对象，确保每层都能应用自己的 ai_exclude_fields。

        Args:
            exclude_none: 是否排除值为None的字段
            exclude_unset: 是否排除未被显式设置的字段
            exclude_default: 是否排除值为默认值的字段
        """
        dict_representation = self.model_dump_for_ai(
            exclude_none=exclude_none,
            exclude_unset=exclude_unset,
            exclude_default=exclude_default
        )

        return json.dumps(dict_representation, ensure_ascii=False)

    def model_dump_for_ai(
            self,
            *,
            exclude_none: bool = True,
            exclude_unset: bool = True,
            exclude_default: bool = True,
    ) -> dict[str, Any]:
        """
        递归序列化模型为 AI 友好的字典格式。
        在序列化前处理嵌套对象，确保每层都能应用自己的 ai_exclude_fields。

        Args:
            exclude_none: 是否排除值为None的字段
            exclude_unset: 是否排除未被显式设置的字段
            exclude_default: 是否排除值为默认值的字段
        """
        result = {}
        fields_set = self.__pydantic_fields_set__ if hasattr(self, '__pydantic_fields_set__') else set()

        for field_name, field_value in self.__dict__.items():
            if field_name in self.ai_exclude_fields:
                continue

            if self._should_exclude_field(
                    field_name, field_value, fields_set, exclude_none, exclude_unset, exclude_default
            ):
                continue

            result[field_name] = self._process_value_before_dump(
                field_value, exclude_none, exclude_unset, exclude_default
            )

        return result

    def _should_exclude_field(
            self,
            field_name: str,
            field_value: Any,
            fields_set: set,
            exclude_none: bool,
            exclude_unset: bool,
            exclude_default: bool
    ) -> bool:
        """
        判断是否应该排除该字段。
        """
        if exclude_none and field_value is None:
            return True

        if exclude_unset and field_name not in fields_set:
            return True

        if exclude_default:
            model_fields = self.model_fields
            if field_name in model_fields:
                field_info = model_fields[field_name]
                default_value = field_info.default
                if default_value is not None and field_value == default_value:
                    return True

        return False

    def _process_value_before_dump(
            self,
            value: Any,
            exclude_none: bool = False,
            exclude_unset: bool = False,
            exclude_default: bool = False
    ) -> Any:
        """
        在序列化前处理值，支持递归调用嵌套模型的 model_dump_json_for_ai()。
        """
        if isinstance(value, BaseSystemModel):
            return value.model_dump_for_ai(
                exclude_none=exclude_none,
                exclude_unset=exclude_unset,
                exclude_default=exclude_default
            )
        elif isinstance(value, list):
            return [
                self._process_value_before_dump(item, exclude_none, exclude_unset, exclude_default)
                for item in value
            ]
        elif isinstance(value, dict):
            return {
                k: self._process_value_before_dump(v, exclude_none, exclude_unset, exclude_default)
                for k, v in value.items()
            }
        else:
            return self._serialize_value(value)

    def _serialize_value(self, value: Any) -> Any:
        """
        序列化特殊类型的值（datetime、枚举等）。
        """
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%dT%H:%M:%SZ")
        elif isinstance(value, StrEnum):
            return value.value
        else:
            return value


class MessageModel(BaseSystemModel):
    playbook: Optional[List[Union[PlaybookModel, str]]] = Field(default="", description="所属Playbook的唯一行ID")
    node: Optional[str] = Field(default="", description="消息来源的节点名称或ID")
    content: Optional[str] = Field(default="", description="消息的文本内容")
    data: Optional[str] = Field(default="", description="消息的JSON格式内容，通常用于工具调用和返回")
    type: Optional[MessageType] = Field(default=None,
                                        description="消息类型，用于区分不同角色的发言")


class PlaybookModel(BaseSystemModel):
    source_worksheet: Optional[str] = Field(default="", description="Playbook触发源所在的工作表名称")
    source_rowid: Optional[str] = Field(default="", description="Playbook触发源的行ID，例如具体的告警ID或事件ID")
    job_id: Optional[str] = Field(default="", description="执行Playbook的后台任务ID")
    job_status: Optional[PlaybookJobStatus] = Field(default=None, description="Playbook执行任务的状态")
    remark: Optional[str] = Field(default="", description="关于Playbook执行的备注信息")
    type: Optional[PlaybookType] = Field(default=None, description="Playbook关联的对象类型")
    name: Optional[str] = Field(default="", description="执行的Playbook的名称")

    user_input: Optional[str] = Field(default="", description="用户对Playbook的初始输入或后续指令")
    user: Optional[Union[List[AccountModel], AccountModel, str]] = Field(default=None, description="发起Playbook的用户")

    # 关联表
    messages: Optional[List[Union[MessageModel, str]]] = Field(default=None, description="Playbook执行过程中的所有消息记录，构成对话历史")


class KnowledgeModel(BaseSystemModel):
    title: Optional[str] = Field(default="", description="知识库条目的标题")
    body: Optional[str] = Field(default="", description="知识库条目的正文内容")
    using: Optional[bool] = Field(default=False, description="当前是否正在使用该知识")
    action: Optional[KnowledgeAction] = Field(default=None, description="对知识库条目执行的动作")
    source: Optional[KnowledgeSource] = Field(default=None, description="知识的来源，'Manual'表示手动创建，'Case'表示从安全事件中提取")
    tags: Optional[List[str]] = Field(default=[], description="与知识条目相关的标签列表", json_schema_extra={"type": 2})


class EnrichmentModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}

    name: Optional[str] = Field(default="", description="富化信息的名称或标题")
    type: Optional[str] = Field(default="Other", description="富化信息的类型", json_schema_extra={"type": 2})
    provider: Optional[str] = Field(default="Other", description="富化信息的提供方，例如威胁情报厂商", json_schema_extra={"type": 2})
    value: Optional[str] = Field(default="", description="富化信息的具体值")
    src_url: Optional[str] = Field(default="", description="富化信息的来源URL，方便溯源")
    desc: Optional[str] = Field(default="", description="对富化信息的简要描述")
    data: Optional[str] = Field(default="", description="富化信息的详细数据，通常是JSON字符串")


class TicketModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}

    status: Optional[TicketStatus] = Field(
        default=None, description="外部工单系统中的状态")
    type: Optional[TicketType] = Field(default=None, description="外部工单系统的类型",
                                       json_schema_extra={"type": 2})
    title: Optional[str] = Field(default="", description="工单的标题")
    uid: Optional[str] = Field(default="", description="工单在外部系统中的唯一ID")
    src_url: Optional[str] = Field(default="", description="访问该工单的URL")


class ArtifactModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}

    name: Optional[str] = Field(default="", description="实体（Artifact）的名称，通常与值相同或为其描述")
    type: Optional[ArtifactType] = Field(
        default=None, description="实体的类型, 例如: IP地址, 主机名, 文件哈希等")
    role: Optional[ArtifactRole] = Field(default=None,
                                         description="实体在事件中扮演的角色, 如攻击者(Actor)、受害者(Target)等")
    owner: Optional[str] = Field(default="", description="实体归属的系统或用户")
    value: Optional[str] = Field(default="", description="实体的具体值, 如 '192.168.1.1'")
    reputation_provider: Optional[str] = Field(default="", description="提供信誉评分的威胁情报厂商名称", json_schema_extra={"type": 2})
    reputation_score: Optional[ArtifactReputationScore] = Field(
        default=None, description="实体的信誉评分")

    # 关联表
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="针对此实体的一系列富化结果")  # None 时表示无需处理,[] 时表示要将 link 清空

    # playbooks: Optional[Any] = "" # 内部字段
    # playbook: Optional[Literal['TI Enrichment By AlienVaultOTX', 'TI Enrichment By Mock', None]] = None # 内部字段
    # user_input: Optional[str] = "" # 内部字段


class AlertModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid', "summary_ai", "case"}

    severity: Optional[Severity] = Field(default=None,
                                         description="告警的严重性，由源安全产品定义")
    title: Optional[str] = Field(default="", description="告警的标题")
    impact: Optional[ImpactLevel] = Field(default=None, description="告警可能造成的影响范围")
    disposition: Optional[Disposition] = Field(
        default=None, description="安全产品对该活动的处置结果, 如'Blocked', 'Allowed等")
    action: Optional[AlertAction] = Field(default=None,
                                          description="检测到的原始行为, 如'Allowed', 'Denied等")
    confidence: Optional[Confidence] = Field(default=None,
                                             description="告警的置信度，表示该告警为真阳性的可能性")
    uid: Optional[str] = Field(default="", description="告警的唯一标识符")
    labels: Optional[List[str]] = Field(default=[], description="为告警打上的标签", json_schema_extra={"type": 2})
    desc: Optional[str] = Field(default="", description="对告警的详细描述")

    created_time: Optional[Union[datetime, str]] = Field(default=None, description="告警在SIRP平台中创建的时间")
    modified_time: Optional[Union[datetime, str]] = Field(default=None, description="告警在SIRP平台中最后修改的时间")
    first_seen_time: Optional[Union[datetime, str]] = Field(default=None, description="首次观测到该活动的时间")
    last_seen_time: Optional[Union[datetime, str]] = Field(default=None, description="最后一次观测到该活动的时间")

    rule_id: Optional[str] = Field(default="", description="触发告警的规则ID")
    rule_name: Optional[str] = Field(default="", description="触发告警的规则名称")
    correlation_uid: Optional[str] = Field(default="", description="用于事件关联的唯一ID")
    count: Optional[Union[int, str]] = Field(default=None, description="告警聚合的次数")

    src_url: Optional[str] = Field(default="", description="在源安全产品中查看此告警的URL")
    source_uid: Optional[str] = Field(default="", description="告警在源产品中的唯一ID")
    data_sources: Optional[List[str]] = Field(default=[], description="告警的数据来源，如 'EDR', 'Firewall' 等")

    analytic_name: Optional[str] = Field(default="", description="分析引擎的名称")
    analytic_type: Optional[AlertAnalyticType] = Field(
        default=None, description="分析引擎的类型, 如'Rule', 'Behavioral'等")
    analytic_state: Optional[AlertAnalyticState] = Field(default=None, description="分析规则当前的状态")
    analytic_desc: Optional[str] = Field(default="", description="分析规则的描述")

    tactic: Optional[str] = Field(default="", description="关联的MITRE ATT&CK战术")
    technique: Optional[str] = Field(default="", description="关联的MITRE ATT&CK技术")
    sub_technique: Optional[str] = Field(default="", description="关联的MITRE ATT&CK子技术")
    mitigation: Optional[str] = Field(default="", description="针对该攻击的缓解措施建议")

    product_category: Optional[ProductCategory] = Field(default=None,
                                                        description="产生告警的安全产品类别")
    product_vendor: Optional[str] = Field(default=None, description="安全产品的厂商", json_schema_extra={"type": 2})
    product_name: Optional[str] = Field(default=None, description="安全产品的名称", json_schema_extra={"type": 2})
    product_feature: Optional[str] = Field(default=None, description="产生告警的产品具体功能模块", json_schema_extra={"type": 2})

    policy_name: Optional[str] = Field(default="", description="触发告警的策略名称")
    policy_type: Optional[AlertPolicyType] = Field(default=None,
                                                   description="触发告警的策略类型")
    policy_desc: Optional[str] = Field(default="", description="触发告警的策略描述")

    risk_level: Optional[AlertRiskLevel] = Field(default=None, description="评估的风险等级")
    risk_details: Optional[str] = Field(default="", description="风险详情说明")

    status: Optional[AlertStatus] = Field(default=None,
                                          description="告警的处理状态")
    status_detail: Optional[str] = Field(default="", description="状态的详细说明，例如抑制原因")
    remediation: Optional[str] = Field(default="", description="修复建议或记录")

    comment: Optional[str] = Field(default="", description="分析师对告警的评论")

    unmapped: Optional[str] = Field(default="", description="未被映射到标准字段的原始数据")

    raw_data: Optional[str] = Field(default="", description="原始告警日志，通常为JSON格式的字符串")

    attachments: Optional[Union[List[AttachmentModel], str]] = Field(default=[], description="告警的附件")

    # AI字段
    summary_ai: Optional[str] = Field(default="", description="AI提供的汇总摘要")

    # 反向关联
    case: Optional[List[Union[CaseModel, str]]] = Field(default=None, description="此告警关联到的安全事件（Case）(只保留rowid,避免循环引用)")

    # 关联表
    artifacts: Optional[List[Union[ArtifactModel, str]]] = Field(default=None, description="从告警中提取出的实体（Artifact）列表")
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="对整个告警进行的富化结果")


class CaseModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid', "workbook", "analysis_rationale_ai", "recommended_actions_ai", "attack_stage_ai",
                                             "severity_ai", "confidence_ai",
                                             "threat_hunting_report_ai"}

    title: Optional[str] = Field(default="", description="安全事件的标题, 应能简明扼要地概括事件的核心内容")
    severity: Optional[Severity] = Field(default=None,
                                         description="由分析师评估或重新定义的事件严重性")
    impact: Optional[ImpactLevel] = Field(default=None, description="由分析师评估的事件实际影响")
    priority: Optional[CasePriority] = Field(default=None, description="事件的处置优先级")
    src_url: Optional[str] = Field(default="", description="在源系统中查看此事件的URL")
    confidence: Optional[Confidence] = Field(default=None, description="由分析师评估的事件置信度")
    description: Optional[str] = Field(default="", description="对安全事件的详细描述")

    category: Optional[ProductCategory] = Field(default=None,
                                                description="安全事件的分类，通常与主要告警源的产品类别一致")
    tags: Optional[List[str]] = Field(default=[], description="为事件打上的一系列标签", json_schema_extra={"type": 2})

    status: Optional[CaseStatus] = Field(default=None,
                                         description="安全事件的处理状态")
    assignee_l1: Optional[Union[List[AccountModel], AccountModel, str]] = Field(default=None, description="分配给L1一线分析师")
    acknowledged_time: Optional[Union[datetime, str]] = Field(default=None, description="L1分析师首次确认接收事件的时间")
    comment: Optional[str] = Field(default="", description="分析师对整个事件的评论或处置记录")
    attachments: Optional[Union[List[AttachmentModel], str]] = Field(default=[], description="与事件相关的附件列表")

    assignee_l2: Optional[Union[List[AccountModel], AccountModel, str]] = Field(default=None, description="分配或升级给L2二线分析师")
    assignee_l3: Optional[Union[List[AccountModel], AccountModel, str]] = Field(default=None, description="分配或升级给L3专家分析师")
    closed_time: Optional[Union[datetime, str]] = Field(default=None, description="事件关闭的时间")
    verdict: Optional[CaseVerdict] = Field(
        default=None, description="对事件的最终裁定结论")
    summary: Optional[str] = Field(default="", description="事件关闭时生成的最终摘要总结")

    correlation_uid: Optional[str] = Field(default="", description="用于关联其他事件或数据的唯一ID")

    workbook: Optional[str] = Field(default="", description="事件调查使用的工作簿或调查手册内容")

    # ai 字段
    analysis_rationale_ai: Optional[str] = Field(default="", description="AI对事件的分析基本原理和逻辑")
    recommended_actions_ai: Optional[str] = Field(default="", description="AI推荐的下一步操作或修复建议")
    attack_stage_ai: Optional[str] = Field(default="", description="AI评估的攻击阶段")
    severity_ai: Optional[Severity] = Field(default=None,
                                            description="AI评估的事件严重性")
    confidence_ai: Optional[Confidence] = Field(default=None, description="AI评估的事件置信度")

    threat_hunting_report_ai: Optional[str] = Field(default="", description="AI生成的与此事件相关的威胁狩猎报告")

    # 公式计算字段
    start_time_calc: Optional[Any] = Field(default=None, description="事件开始时间,根据挂载到alert计算,无需手动赋值")
    end_time_calc: Optional[Any] = Field(default=None, description="事件结束时间,根据挂载到alert计算,无需手动赋值")
    detect_time_calc: Optional[Any] = Field(default=None, description="事件检测用时,用于计算MTTD,无需手动赋值")
    acknowledge_time_calc: Optional[Any] = Field(default=None, description="事件确认用时, 用于计算MTTA,无需手动赋值")
    respond_time_calc: Optional[Any] = Field(default=None, description="事件处置用时,用于计算MTTR,无需手动赋值")

    # 关联表
    tickets: Optional[List[Union[TicketModel, str]]] = Field(default=None, description="与此事件关联的外部工单列表")
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="对整个事件进行的富化结果")
    alerts: Optional[List[Union[AlertModel, str]]] = Field(default=None, description="合并到此事件中的告警列表")
