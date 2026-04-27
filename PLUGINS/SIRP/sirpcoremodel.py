from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Optional, List, Union, Any

from pydantic import Field

from PLUGINS.SIRP.sirpbasemodel import BaseSystemModel, AutoDatetime, AutoAccount


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


class EnrichmentModel(BaseSystemModel):
    """Artifact/Alert/Case结构化的富化信息"""
    _AI_EXCLUDE_FIELDS: ClassVar[set[str]] = set()
    id: Optional[str] = Field(default=None, init=False, description="Record ID e.g. enrichment_000001 (记录 ID e.g. enrichment_000001)")
    name: Optional[str] = Field(default="", description="Enrichment name (富化名称)")
    type: Optional[str] = Field(default="Other", description="Enrichment type (富化类型)", json_schema_extra={"type": 2})
    provider: Optional[str] = Field(default="Other", description="Enrichment provider (富化提供商)", json_schema_extra={"type": 2})
    value: Optional[str] = Field(default="", description="Enrichment value (富化值)")
    src_url: Optional[str] = Field(default="", description="Enrichment source URL (富化来源 URL)")
    desc: Optional[str] = Field(default="", description="Enrichment summary (富化摘要)")
    data: Optional[str] = Field(default="", description="Detailed enrichment JSON (详细富化 JSON)")


class TicketModel(BaseSystemModel):
    """关联到Case的外部工单信息"""
    _AI_EXCLUDE_FIELDS: ClassVar[set[str]] = {'case'}

    id: Optional[str] = Field(default=None, init=False, description="Record ID e.g. ticket_000001 (记录 ID e.g. ticket_000001)")
    status: Optional[TicketStatus] = Field(
        default=None, description="External ticket status (外部工单状态)")
    type: Optional[TicketType] = Field(default=None, description="External ticket type (外部工单类型)",
                                       json_schema_extra={"type": 2})
    title: Optional[str] = Field(default="", description="Ticket title (工单标题)")
    uid: Optional[str] = Field(default="", description="External ticket ID (外部工单 ID)")
    src_url: Optional[str] = Field(default="", description="External ticket URL (外部工单 URL)")

    # 反向关联,无需手动处理
    case: Optional[List[Union[CaseModel, str]]] = Field(default=None, init=False, description="Linked case row_id (关联案件行 ID)")


class ArtifactModel(BaseSystemModel):
    """Entity information extracted from alerts, the minimum investigate unit"""
    _AI_EXCLUDE_FIELDS: ClassVar[set[str]] = {'alert'}
    # 系统自动生成字段
    id: Optional[str] = Field(default=None, init=False, description="Record ID e.g. artifact_000001 (记录 ID e.g. artifact_000001)")

    # 创建记录填写字段
    name: Optional[str] = Field(default="", description="Artifact name (实体名称)")
    type: Optional[ArtifactType] = Field(default=None, description="Artifact type (实体类型)")
    role: Optional[ArtifactRole] = Field(default=None, description="Artifact role in event (实体在事件中的角色)")
    value: Optional[str] = Field(default="", description="Artifact value (实体值)")

    owner: Optional[str] = Field(default="", description="Owning system or user (所属系统或用户)")
    reputation_provider: Optional[str] = Field(default="", description="Threat intel provider (威胁情报提供商)", json_schema_extra={"type": 2})
    reputation_score: Optional[ArtifactReputationScore] = Field(default=None, description="Artifact reputation (实体信誉)")

    # 反向关联,无需手动处理
    alert: Optional[List[Union[AlertModel, str]]] = Field(default=None, init=False, description="Linked alert row_id (关联告警行 ID)")

    # 关联表
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None,
                                                                     description="Enrichments information (富化信息)")  # None 时表示无需处理,[] 时表示要将 link 清空


class AlertModel(BaseSystemModel):
    """基础告警信息,通常与SIEM Rule 产生的告警进行映射, 是连接 SIEM 告警与 SIRP 案件的核心数据模型"""
    _AI_EXCLUDE_FIELDS: ClassVar[set[str]] = {'raw_data', "case"}

    # 系统自动生成字段
    id: Optional[str] = Field(default=None, init=False,
                              description="Record ID e.g. alert_000001, auto-generated, no manual input needed (记录 ID e.g. alert_000001, 系统自动生成,无需手动赋值)")

    # 创建记录填写字段
    title: Optional[str] = Field(default="", description="Alert title (告警标题)")
    severity: Optional[Severity] = Field(default=Severity.UNKNOWN, description="Source-defined severity (告警来源定义的严重程度)")
    confidence: Optional[Confidence] = Field(default=Confidence.UNKNOWN, description="True-positive confidence (真阳性置信度)")
    impact: Optional[Impact] = Field(default=Impact.UNKNOWN, description="Potential impact (告警潜在影响)")
    disposition: Optional[Disposition] = Field(default=Disposition.UNKNOWN, description="Source disposition (告警源处置结果)")
    action: Optional[AlertAction] = Field(default=AlertAction.UNKNOWN, description="Observed action (告警源的动作)")

    labels: Optional[List[str]] = Field(default=[], description="Alert labels (告警标签)", json_schema_extra={"type": 2})
    desc: Optional[str] = Field(default="", description="Alert description (告警描述)")

    first_seen_time: Optional[AutoDatetime] = Field(default=None, description="First observed time (首次观测时间)")
    last_seen_time: Optional[AutoDatetime] = Field(default=None, description="Last observed time (最后观测时间)")

    rule_id: Optional[str] = Field(default="", description="SIEM rule ID (SIEM 规则 ID)")
    rule_name: Optional[str] = Field(default="", description="SIEM rule name (SIEM 规则名称)")
    correlation_uid: Optional[str] = Field(default="",
                                           description="Case correlation ID, alerts with the same correlation_uid are linked to the same event (事件关联 ID,相同 correlation_uid 告警关联到同一个事件)")

    src_url: Optional[str] = Field(default="", description="Source alert URL (原始告警 URL)")
    source_uid: Optional[str] = Field(default="",
                                      description="Source product ID, can be used to locate the unique alert in the source system (原始告警 唯一ID, 可通过该 ID 在原始来源中定位唯一告警)")
    data_sources: Optional[List[str]] = Field(default=[], description="Underlying data sources (告警源生成告警的数据来源列表)")

    analytic_name: Optional[str] = Field(default="", description="Analytic engine name (分析引擎名称)")
    analytic_type: Optional[AlertAnalyticType] = Field(default=AlertAnalyticType.UNKNOWN, description="Analytic engine type (分析引擎类型)")
    analytic_state: Optional[AlertAnalyticState] = Field(default=None, description="Analytic rule state (分析规则状态)")
    analytic_desc: Optional[str] = Field(default="", description="Analytic rule description (分析规则描述)")

    tactic: Optional[str] = Field(default="", description="Mapped MITRE tactic (映射的 MITRE 战术)")
    technique: Optional[str] = Field(default="", description="Mapped MITRE technique (映射的 MITRE 技术)")
    sub_technique: Optional[str] = Field(default="", description="Mapped MITRE sub-technique (映射的 MITRE 子技术)")
    mitigation: Optional[str] = Field(default="", description="Suggested mitigation (建议的缓解措施)")

    product_category: Optional[ProductCategory] = Field(default=None, description="Source product category (原始产品类别)")
    product_vendor: Optional[str] = Field(default=None, description="Source vendor (原始厂商)", json_schema_extra={"type": 2})
    product_name: Optional[str] = Field(default=None, description="Source product name (原始产品名称)", json_schema_extra={"type": 2})
    product_feature: Optional[str] = Field(default=None, description="Source product feature (原始产品功能)", json_schema_extra={"type": 2})

    policy_name: Optional[str] = Field(default="", description="Trigger policy name (触发策略名称)")
    policy_type: Optional[AlertPolicyType] = Field(default=None, description="Trigger policy type (触发策略类型)")
    policy_desc: Optional[str] = Field(default="", description="Trigger policy description (触发策略描述)")

    risk_level: Optional[AlertRiskLevel] = Field(default=None, description="Assessed risk level (评估的风险等级)")

    status: Optional[AlertStatus] = Field(default=None, description="Alert handling status (告警处理状态)")
    status_detail: Optional[str] = Field(default="", description="Handling status details (处理状态详情)")
    remediation: Optional[str] = Field(default="", description="Remediation advice or record (处置建议或记录)")

    unmapped: Optional[str] = Field(default="", description="Raw unmapped fields, JSON Format (原始未映射字段 JSON 格式)")

    raw_data: Optional[str] = Field(default="", description="Raw alert log JSON (原始告警日志 JSON)")

    # 反向关联,无需手动处理
    case: Optional[List[Union[CaseModel, str]]] = Field(default=None, init=False,
                                                        description="Linked case row_id, reverse association, auto-linked, no manual setting needed (关联案件行 ID,反向关联,自动化关联,无需手动设置)")
    # 关联表
    artifacts: Optional[List[Union[ArtifactModel, str]]] = Field(default=None, description="Extracted artifacts (关联表, 提取的实体列表)")
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="Alert enrichments (关联表, 告警富化)")


class CaseModel(BaseSystemModel):
    """安全案件,多个告警聚合而成,安全人员与AI分析处理的核心对象"""
    _AI_EXCLUDE_FIELDS: ClassVar[set[str]] = {"workbook", "summary_ai", "comment_ai", "attack_stage_ai", "severity_ai", "confidence_ai", "impact_ai",
                                              "priority_ai", "verdict_ai"}
    # 系统自动生成字段
    id: Optional[str] = Field(default=None, init=False, description="Record ID e.g. case_000001 (记录 ID e.g. case_000001,系统自动生成,无需手动赋值)")

    # 创建记录填写字段
    title: Optional[str] = Field(default="", description="Case title (案件标题)")
    severity: Optional[Severity] = Field(default=None, description="Analyst-assessed severity (严重程度)")
    impact: Optional[Impact] = Field(default=None, description="Analyst-assessed impact (影响)")
    priority: Optional[CasePriority] = Field(default=None, description="Response priority (响应优先级)")

    confidence: Optional[Confidence] = Field(default=None, description="Analyst-assessed confidence (分析师评估置信度)")
    description: Optional[str] = Field(default="", description="Case description (案件描述)")

    category: Optional[ProductCategory] = Field(default=None, description="Case category (案件类别)")
    tags: Optional[List[str]] = Field(default=[], description="Case tags (案件标签)", json_schema_extra={"type": 2})

    correlation_uid: Optional[str] = Field(default="", description="Case correlation ID (案件关联 ID)")

    # 用户手动输入字段
    status: Optional[CaseStatus] = Field(default=CaseStatus.NEW, description="Case handling status (案件处理状态)")
    acknowledged_time: Optional[AutoDatetime] = Field(default=None, description="L1 first acknowledged time (L1 首次接手时间)")
    assignee_l1: Optional[AutoAccount] = Field(default=None, description="Assigned L1 analyst (分配的 L1 分析师)")

    comment: Optional[str] = Field(default="", description="Case analyst comment (案件分析师注释)")

    assignee_l2: Optional[AutoAccount] = Field(default=None, description="Assigned or escalated L2 analyst (分配或升级的 L2 分析师)")
    assignee_l3: Optional[AutoAccount] = Field(default=None, description="Assigned or escalated L3 analyst (分配或升级的 L3 分析师)")

    closed_time: Optional[AutoDatetime] = Field(default=None, description="case close time (事件关闭时间)")
    verdict: Optional[CaseVerdict] = Field(default=None, description="Final verdict (最终判定结果)")
    summary: Optional[str] = Field(default="", description="Closure summary (结案摘要)")

    # 自动计算字段,无需手动赋值
    start_time_calc: Optional[AutoDatetime] = Field(default=None, description="Calculated start time (计算的开始时间)")
    end_time_calc: Optional[AutoDatetime] = Field(default=None, description="Calculated end time (计算的结束时间)")
    detect_time_calc: Optional[Any] = Field(default=None, description="Calculated detect time (计算的检测时间)")
    acknowledge_time_calc: Optional[Any] = Field(default=None, description="Calculated acknowledge time (计算的接手时间)")
    respond_time_calc: Optional[Any] = Field(default=None, description="Calculated response time (计算的响应时间)")

    # 关联表
    tickets: Optional[List[Union[TicketModel, str]]] = Field(default=None, description="Linked external tickets (关联外部工单)")
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="Case enrichments (案件富化)")
    alerts: Optional[List[Union[AlertModel, str]]] = Field(default=None, description="Linked alerts (关联的告警)")

    # ai 字段
    severity_ai: Optional[Severity] = Field(default=None, description="AI-assessed severity (AI 评估严重程度)")
    confidence_ai: Optional[Confidence] = Field(default=None, description="AI-assessed confidence (AI 评估置信度)")
    impact_ai: Optional[Impact] = Field(default=None, description="AI-assessed impact (AI 评估影响)")
    priority_ai: Optional[CasePriority] = Field(default=None, description="AI-assessed response priority (AI 评估响应优先级)")
    attack_stage_ai: Optional[AttackStage] = Field(default="", description="AI-assessed attack stage (AI 评估攻击阶段)")
    comment_ai: Optional[str] = Field(default="", description="AI-generated comment (AI 生成的注释)")
    
    verdict_ai: Optional[CaseVerdict] = Field(default=None, description="AI-generated final verdict (AI 生成的最终判定结果)")
    summary_ai: Optional[str] = Field(default="", description="AI-generated closure summary (AI 生成的结案摘要)")
