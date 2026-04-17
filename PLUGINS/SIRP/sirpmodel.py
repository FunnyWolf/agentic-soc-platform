from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import List, Optional, Any, Union, ClassVar, Annotated

from pydantic import field_validator, ConfigDict, BaseModel, BeforeValidator, Field, PlainSerializer

from PLUGINS.SIRP.nocolymodel import AttachmentModel, AttachmentCreateModel


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
    REGISTRY_PATH = "Registry Path"
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


class AttackStage(StrEnum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class Impact(StrEnum):
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
    SIEM = "SIEM"
    WAF = "WAF"
    OTHER = "Other"


class AlertPolicyType(StrEnum):
    IDENTITY_POLICY = "Identity Policy"
    RESOURCE_POLICY = "Resource Policy"
    SERVICE_CONTROL_POLICY = "Service Control Policy"
    ACCESS_CONTROL_POLICY = "Access Control Policy"
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
    NEW = "New"
    IN_PROGRESS = "In Progress"
    ON_HOLD = "On Hold"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


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


class AccountModel(BaseModel):
    accountId: Optional[str] = Field(default=None, description="用户的唯一标识ID")
    avatar: Optional[str] = Field(default=None, description="用户头像的URL")
    email: Optional[str] = Field(default=None, description="用户的电子邮件地址")
    fullname: Optional[str] = Field(default=None, description="用户的全名")
    jobNumber: Optional[str] = Field(default=None, description="用户的工号")
    mobilePhone: Optional[str] = Field(default=None, description="用户的手机号码")
    status: Optional[int] = Field(default=None, description="用户状态, 例如: 1表示正常")


def validate_datetime(v: Any) -> Any:
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    if not isinstance(v, str):
        return v

    value = v.strip()
    if not value:
        return None

    local_tz = datetime.now().astimezone().tzinfo or timezone.utc

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=local_tz)
        return dt
    except ValueError:
        pass

    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=local_tz)
    except ValueError:
        raise ValueError(f"Unsupported datetime format: {value}")


def serialize_datetime(v: Any) -> Any:
    if isinstance(v, datetime):
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        dt = v.replace(tzinfo=local_tz) if v.tzinfo is None else v
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return v


AutoDatetime = Annotated[
    datetime,
    BeforeValidator(validate_datetime),
    PlainSerializer(serialize_datetime, when_used="json")
]


def validate_account(v: Any) -> Any:
    if not v:
        return ""
    if isinstance(v, dict):
        return v.get("fullname")
    if isinstance(v, list):
        if len(v) == 0:
            return ""
        elif len(v) == 1:
            if isinstance(v[0], str):
                return v[0]
            elif isinstance(v[0], dict):
                return v[0].get("fullname")
            else:
                raise ValueError(f"Unsupported account format: {v}")
        else:
            tmp = []
            for one in v:
                if isinstance(one, str):
                    tmp.append(one)
                elif isinstance(one, dict):
                    tmp.append(one.get("fullname"))
                else:
                    raise ValueError(f"Unsupported account format: {one}")
            return tmp

    if not isinstance(v, str):
        return v
    raise ValueError(f"Unsupported account format: {v}")


AutoAccount = Annotated[
    str,
    BeforeValidator(validate_account),
]


class BaseSystemModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    _ai_exclude_fields: ClassVar[set[str]] = set()

    row_id: Optional[str] = Field(default=None, description="唯一行 ID (Unique row ID)")
    row_owner: Optional[AutoAccount] = Field(default=None, description="记录所有者 (Record owner)")
    row_createdBy: Optional[AutoAccount] = Field(default=None, description="创建者 (Creator)")
    row_createdAt: Optional[AutoDatetime] = Field(default=None, description="记录创建时间 (Record created time)")
    row_updatedAt: Optional[AutoDatetime] = Field(default=None, description="记录最后更新时间 (Record last updated time)")
    row_updatedBy: Optional[AutoAccount] = Field(default=None, description="最后更新人 (Last updated by)")

    @field_validator("row_owner", mode="before")
    @classmethod
    def empty_list_to_none(cls, v: Any) -> Any:
        if isinstance(v, list) and len(v) == 0:
            return None
        return v

    def model_dump_for_ai(
            self,
            *,
            exclude_none: bool = True,
            exclude_unset: bool = True,
            exclude_default: bool = True,
    ) -> dict[str, Any]:
        return self.model_dump(
            exclude=self._ai_exclude_fields,
            exclude_none=exclude_none,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_default,
            by_alias=True
        )

    def model_dump_json_for_ai(
            self,
            *,
            exclude_none: bool = True,
            exclude_unset: bool = True,
            exclude_default: bool = True,
    ) -> str:
        return self.model_dump_json(
            exclude=self._ai_exclude_fields,
            exclude_none=exclude_none,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_default,
            by_alias=True
        )


class MessageModel(BaseSystemModel):
    playbook: Optional[List[Union[PlaybookModel, str]]] = Field(default="", description="所属剧本行 ID (Owning playbook row ID)")
    node: Optional[str] = Field(default="", description="源节点名称或 ID (Source node name or ID)")
    content: Optional[str] = Field(default="", description="消息文本内容 (Message text content)")
    data: Optional[str] = Field(default="", description="消息 JSON 负载 (Message JSON payload)")
    type: Optional[MessageType] = Field(default=None,
                                        description="消息角色类型 (Message role type)")


class PlaybookModel(BaseSystemModel):
    id: Optional[str] = Field(default=None, description="记录 ID e.g. playbook_000001 (Record ID e.g. playbook_000001)")
    source_row_id: Optional[str] = Field(default="", description="触发源行 ID (Trigger source row ID)")
    source_id: Optional[str] = Field(default="", description="触发源记录 ID (Trigger source record ID e.g. case_00000_1,alert_000001,artifact_000001)")
    type: Optional[PlaybookType] = Field(default=None, description="关联对象类型 (Linked object type)")
    name: Optional[str] = Field(default="", description="执行剧本名称 (Executed playbook name)")
    user_input: Optional[str] = Field(default="", description="初始或后续用户输入 (Initial or follow-up user input)")
    user: Optional[AutoAccount] = Field(default=None, description="剧本请求者 (Playbook requester)")

    job_status: Optional[PlaybookJobStatus] = Field(default=None, description="后台任务状态 (Background job status)")
    job_id: Optional[str] = Field(default="", description="后台任务 ID (Background job ID)")
    remark: Optional[str] = Field(default="", description="执行备注 (Execution remark)")

    # 关联表
    messages: Optional[List[Union[MessageModel, str]]] = Field(default=None, description="执行消息历史 (Execution message history)")


class KnowledgeModel(BaseSystemModel):
    id: Optional[str] = Field(default=None, description="记录 ID e.g. knowledge_000001 (Record ID e.g. knowledge_000001)")
    title: Optional[str] = Field(default="", description="知识标题 (Knowledge title)")
    body: Optional[str] = Field(default="", description="知识内容 (Knowledge content)")
    using: Optional[bool] = Field(default=False, description="当前正在使用 (Currently in use)")
    action: Optional[KnowledgeAction] = Field(default=None, description="知识操作 (Knowledge action)")
    source: Optional[KnowledgeSource] = Field(default=None, description="知识来源 (Knowledge source)")
    tags: Optional[List[str]] = Field(default=[], description="知识标签 (Knowledge tags)", json_schema_extra={"type": 2})


class EnrichmentModel(BaseSystemModel):
    _ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}
    id: Optional[str] = Field(default=None, description="记录 ID e.g. enrichment_000001 (Record ID e.g. enrichment_000001)")
    name: Optional[str] = Field(default="", description="富化名称 (Enrichment name)")
    type: Optional[str] = Field(default="Other", description="富化类型 (Enrichment type)", json_schema_extra={"type": 2})
    provider: Optional[str] = Field(default="Other", description="富化提供商 (Enrichment provider)", json_schema_extra={"type": 2})
    value: Optional[str] = Field(default="", description="富化值 (Enrichment value)")
    src_url: Optional[str] = Field(default="", description="富化来源 URL (Enrichment source URL)")
    desc: Optional[str] = Field(default="", description="富化摘要 (Enrichment summary)")
    data: Optional[str] = Field(default="", description="详细富化 JSON (Detailed enrichment JSON)")


class TicketModel(BaseSystemModel):
    _ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}

    id: Optional[str] = Field(default=None, description="记录 ID e.g. ticket_000001 (Record ID e.g. ticket_000001)")
    status: Optional[TicketStatus] = Field(
        default=None, description="外部工单状态 (External ticket status)")
    type: Optional[TicketType] = Field(default=None, description="外部工单类型 (External ticket type)",
                                       json_schema_extra={"type": 2})
    title: Optional[str] = Field(default="", description="工单标题 (Ticket title)")
    uid: Optional[str] = Field(default="", description="外部工单 ID (External ticket ID)")
    src_url: Optional[str] = Field(default="", description="外部工单 URL (External ticket URL)")

    # 反向关联
    case: Optional[List[Union[CaseModel, str]]] = Field(default=None, description="关联案例行 ID (Linked case row_id)")


class ArtifactModel(BaseSystemModel):
    """存储从告警中提取的实体信息,最小的可调查单元"""
    _ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}

    id: Optional[str] = Field(default=None, description="记录 ID e.g. artifact_000001 (Record ID e.g. artifact_000001)")
    name: Optional[str] = Field(default="", description="实体名称 (Artifact name)")
    type: Optional[ArtifactType] = Field(default=None, description="实体类型 (Artifact type)")
    role: Optional[ArtifactRole] = Field(default=None, description="实体在事件中的角色 (Artifact role in event)")
    value: Optional[str] = Field(default="", description="实体值 (Artifact value)")

    owner: Optional[str] = Field(default="", description="所属系统或用户 (Owning system or user)")
    reputation_provider: Optional[str] = Field(default="", description="威胁情报提供商 (Threat intel provider)", json_schema_extra={"type": 2})
    reputation_score: Optional[ArtifactReputationScore] = Field(default=None, description="实体信誉 (Artifact reputation)")

    # 反向关联,无需手动处理
    alert: Optional[List[Union[AlertModel, str]]] = Field(default=None, description="关联告警行 ID (Linked alert row_id)")

    # 关联表
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None,
                                                                     description="富化信息 (Enrichments information)")  # None 时表示无需处理,[] 时表示要将 link 清空


class AlertModel(BaseSystemModel):
    _ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid', "comment_ai", "attachments", "raw_data"}
    # 系统自动生成字段
    id: Optional[str] = Field(default=None, description="记录 ID e.g. alert_000001, 系统自动生成,无需手动赋值 (Record ID e.g. alert_000001)")

    # 创建记录填写字段
    title: Optional[str] = Field(default="", description="告警标题 (Alert title)")
    severity: Optional[Severity] = Field(default=Severity.UNKNOWN, description="告警来源定义的严重程度 (Source-defined severity)")
    confidence: Optional[Confidence] = Field(default=Confidence.UNKNOWN, description="真阳性置信度 (True-positive confidence)")
    impact: Optional[Impact] = Field(default=Impact.UNKNOWN, description="告警潜在影响 (Potential impact)")
    disposition: Optional[Disposition] = Field(default=Disposition.UNKNOWN, description="告警源处置结果 (Source disposition)")
    action: Optional[AlertAction] = Field(default=AlertAction.UNKNOWN, description="告警源的动作 (Observed action)")

    labels: Optional[List[str]] = Field(default=[], description="告警标签 (Alert labels)", json_schema_extra={"type": 2})
    desc: Optional[str] = Field(default="", description="告警描述 (Alert description)")

    first_seen_time: Optional[AutoDatetime] = Field(default=None, description="首次观测时间 (First observed time)")
    last_seen_time: Optional[AutoDatetime] = Field(default=None, description="最后观测时间 (Last observed time)")

    rule_id: Optional[str] = Field(default="", description="SIEM 规则 ID (SIEM rule ID)")
    rule_name: Optional[str] = Field(default="", description="SIEM 规则名称 (SIEM rule name)")
    correlation_uid: Optional[str] = Field(default="", description="事件关联 ID,相同 correlation_uid 告警关联到同一个事件 (Case correlation ID)")

    src_url: Optional[str] = Field(default="", description="原始告警 URL (Source alert URL)")
    source_uid: Optional[str] = Field(default="", description="原始告警 唯一ID, 可通过该 ID 在原始来源中定位唯一告警 (Source product ID)")
    data_sources: Optional[List[str]] = Field(default=[], description="告警源生成告警的数据来源列表 (Underlying data sources)")

    analytic_name: Optional[str] = Field(default="", description="分析引擎名称 (Analytic engine name)")
    analytic_type: Optional[AlertAnalyticType] = Field(default=AlertAnalyticType.UNKNOWN, description="分析引擎类型 (Analytic engine type)")
    analytic_state: Optional[AlertAnalyticState] = Field(default=None, description="分析规则状态 (Analytic rule state)")
    analytic_desc: Optional[str] = Field(default="", description="分析规则描述 (Analytic rule description)")

    tactic: Optional[str] = Field(default="", description="映射的 MITRE 战术 (Mapped MITRE tactic)")
    technique: Optional[str] = Field(default="", description="映射的 MITRE 技术 (Mapped MITRE technique)")
    sub_technique: Optional[str] = Field(default="", description="映射的 MITRE 子技术 (Mapped MITRE sub-technique)")
    mitigation: Optional[str] = Field(default="", description="建议的缓解措施 (Suggested mitigation)")

    product_category: Optional[ProductCategory] = Field(default=None, description="原始产品类别 (Source product category)")
    product_vendor: Optional[str] = Field(default=None, description="原始厂商 (Source vendor)", json_schema_extra={"type": 2})
    product_name: Optional[str] = Field(default=None, description="原始产品名称 (Source product name)", json_schema_extra={"type": 2})
    product_feature: Optional[str] = Field(default=None, description="原始产品功能 (Source product feature)", json_schema_extra={"type": 2})

    policy_name: Optional[str] = Field(default="", description="触发策略名称 (Trigger policy name)")
    policy_type: Optional[AlertPolicyType] = Field(default=None, description="触发策略类型 (Trigger policy type)")
    policy_desc: Optional[str] = Field(default="", description="触发策略描述 (Trigger policy description)")

    risk_level: Optional[AlertRiskLevel] = Field(default=None, description="评估的风险等级 (Assessed risk level)")
    risk_details: Optional[str] = Field(default="", description="风险评估详情 (Risk assessment details)")

    status: Optional[AlertStatus] = Field(default=None, description="告警处理状态 (Alert handling status)")
    status_detail: Optional[str] = Field(default="", description="处理状态详情 (Handling status details)")
    remediation: Optional[str] = Field(default="", description="处置建议或记录 (Remediation advice or record)")

    unmapped: Optional[str] = Field(default="", description="原始未映射字段 JSON 格式 (Raw unmapped fields, JSON Format)")

    raw_data: Optional[str] = Field(default="", description="原始告警日志 JSON (Raw alert log JSON)")

    # AI字段
    severity_ai: Optional[Severity] = Field(default=None, description="AI 评估严重程度 (AI-assessed severity)")
    confidence_ai: Optional[Confidence] = Field(default=None, description="AI 评估置信度 (AI-assessed confidence)")
    impact_ai: Optional[Impact] = Field(default=Impact.UNKNOWN, description="AI 评估潜在影响 (AI-assessed Potential impact)")
    comment_ai: Optional[str] = Field(default="", description="AI 生成的注释 (AI-generated comment)")

    case: Optional[List[Union[CaseModel, str]]] = Field(default=None, description="关联案例行 ID,反向关联,自动化关联,无需手动设置 (Linked case row_id)")

    artifacts: Optional[List[Union[ArtifactModel, str]]] = Field(default=None, description="关联表, 提取的实体列表 (Extracted artifacts)")
    enrichments: Optional[List[Union[AlertModel, str]]] = Field(default=None, description="关联表, 告警富化 (Alert enrichments)")

    @field_validator('attachments', mode='before')
    def handle_attachments(cls, v):
        if v == "":
            return []
        return v


class CaseModel(BaseSystemModel):
    _ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid', "workbook", "summary_ai", "comment_ai", "attack_stage_ai",
                                              "severity_ai", "confidence_ai",
                                              "threat_hunting_report_ai"}

    id: Optional[str] = Field(default=None, description="记录 ID e.g. case_000001 (Record ID e.g. case_000001)")
    title: Optional[str] = Field(default="", description="案例标题 (Case title)")
    severity: Optional[Severity] = Field(default=None,
                                         description="分析师评估严重程度 (Analyst-assessed severity)")
    impact: Optional[Impact] = Field(default=None, description="分析师评估影响 (Analyst-assessed impact)")
    priority: Optional[CasePriority] = Field(default=None, description="响应优先级 (Response priority)")

    confidence: Optional[Confidence] = Field(default=None, description="分析师评估置信度 (Analyst-assessed confidence)")
    description: Optional[str] = Field(default="", description="案例描述 (Case description)")

    category: Optional[ProductCategory] = Field(default=None,
                                                description="案例类别 (Case category)")
    tags: Optional[List[str]] = Field(default=[], description="案例标签 (Case tags)", json_schema_extra={"type": 2})

    status: Optional[CaseStatus] = Field(default=None,
                                         description="案例处理状态 (Case handling status)")
    assignee_l1: Optional[AutoAccount] = Field(default=None, description="分配的 L1 分析师 (Assigned L1 analyst)")
    acknowledged_time: Optional[AutoDatetime] = Field(default=None, description="L1 首次接手时间 (L1 first acknowledged time)")
    comment: Optional[str] = Field(default="", description="案例分析师注释 (Case analyst comment)")
    attachments: Optional[List[Union[AttachmentModel, AttachmentCreateModel]]] = Field(default=[], description="案例附件 (Case attachments)")

    assignee_l2: Optional[AutoAccount] = Field(default=None,
                                               description="分配或升级的 L2 分析师 (Assigned or escalated L2 analyst)")
    assignee_l3: Optional[AutoAccount] = Field(default=None,
                                               description="分配或升级的 L3 分析师 (Assigned or escalated L3 analyst)")
    closed_time: Optional[AutoDatetime] = Field(default=None, description="案例关闭时间 (Case closed time)")
    verdict: Optional[CaseVerdict] = Field(
        default=None, description="最终判定结果 (Final verdict)")
    summary: Optional[str] = Field(default="", description="结案摘要 (Closure summary)")

    correlation_uid: Optional[str] = Field(default="", description="案例关联 ID (Case correlation ID)")

    workbook: Optional[str] = Field(default="", description="调查工作手册 (Investigation workbook)")

    # ai 字段
    attack_stage_ai: Optional[AttackStage] = Field(default="", description="AI 评估攻击阶段 (AI-assessed attack stage)")
    severity_ai: Optional[Severity] = Field(default=None,
                                            description="AI 评估严重程度 (AI-assessed severity)")
    confidence_ai: Optional[Confidence] = Field(default=None, description="AI 评估置信度 (AI-assessed confidence)")
    comment_ai: Optional[str] = Field(default="", description="AI 生成的注释 (AI-generated comment)")
    summary_ai: Optional[str] = Field(default="", description="AI 生成的结案摘要 (AI-generated closure summary)")
    verdict_ai: Optional[CaseVerdict] = Field(default=None, description="AI 生成的最终判定结果 (AI-generated Final verdict)")
    threat_hunting_report_ai: Optional[str] = Field(default="", description="AI 生成的威胁狩猎报告 (AI-generated hunting report)")

    # 公式计算字段
    start_time_calc: Optional[Any] = Field(default=None, description="计算的开始时间 (Calculated start time)")
    end_time_calc: Optional[Any] = Field(default=None, description="计算的结束时间 (Calculated end time)")
    detect_time_calc: Optional[Any] = Field(default=None, description="计算的检测时间 (Calculated detect time)")
    acknowledge_time_calc: Optional[Any] = Field(default=None, description="计算的接手时间 (Calculated acknowledge time)")
    respond_time_calc: Optional[Any] = Field(default=None, description="计算的响应时间 (Calculated response time)")

    # 关联表
    tickets: Optional[List[Union[TicketModel, str]]] = Field(default=None, description="关联外部工单 (Linked external tickets)")
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="案例富化 (Case enrichments)")
    alerts: Optional[List[Union[AlertModel, str]]] = Field(default=None, description="合并的告警 (Merged alerts)")

    @field_validator('attachments', mode='before')
    def handle_attachments(cls, v):
        if v == "":
            return []
        return v
