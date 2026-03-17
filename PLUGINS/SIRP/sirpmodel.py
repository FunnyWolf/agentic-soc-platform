from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import List, Optional, Any, Union, ClassVar

from pydantic import BaseModel, Field, field_validator, ConfigDict, field_serializer

from PLUGINS.SIRP.nocolymodel import AttachmentModel, AccountModel, AttachmentCreateModel


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
    # UNKNOWN = "Unknown"
    NEW = "New"
    IN_PROGRESS = "In Progress"
    ON_HOLD = "On Hold"
    RESOLVED = "Resolved"
    CLOSED = "Closed"
    # OTHER = "Other"


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

    rowid: Optional[str] = Field(default=None, description="Unique row ID")
    ownerid: Optional[AccountModel] = Field(default=None, description="Record owner")
    caid: Optional[AccountModel] = Field(default=None, description="Creator account")
    ctime: Optional[Union[datetime, str]] = Field(default=None, description="Record created time")
    utime: Optional[Union[datetime, str]] = Field(default=None, description="Record last updated time")
    uaid: Optional[AccountModel] = Field(default=None, description="Last updated by")

    # 流程相关参数
    # wfname: Optional[str] = Field(default=None, description="Workflow name")
    # wfcuaids: Optional[Any] = Field(default=None, description="Current assignees")
    # wfcaid: Optional[Any] = Field(default=None, description="Current assignee")
    # wfctime: Optional[Union[datetime, str]] = Field(default=None, description="Workflow created at")
    # wfrtime: Optional[Union[datetime, str]] = Field(default=None, description="Workflow received at")
    # wfcotime: Optional[Union[datetime, str]] = Field(default=None, description="Workflow completed at")
    # wfdtime: Optional[Union[datetime, str]] = Field(default=None, description="Workflow due at")
    # wfftime: Optional[Any] = Field(default=None, description="Workflow followed at")
    # wfstatus: Optional[WfStatus] = Field(default=None, description="Workflow status")

    @field_validator("ownerid", mode="before")
    def empty_list_to_none(cls, v):
        if isinstance(v, list) and len(v) == 0:
            return None
        return v

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
    playbook: Optional[List[Union[PlaybookModel, str]]] = Field(default="", description="Owning playbook row ID")
    node: Optional[str] = Field(default="", description="Source node name or ID")
    content: Optional[str] = Field(default="", description="Message text content")
    data: Optional[str] = Field(default="", description="Message JSON payload")
    type: Optional[MessageType] = Field(default=None,
                                        description="Message role type")


class PlaybookModel(BaseSystemModel):
    source_worksheet: Optional[str] = Field(default="", description="Trigger source worksheet")
    source_rowid: Optional[str] = Field(default="", description="Trigger source row ID")
    job_id: Optional[str] = Field(default="", description="Background job ID")
    job_status: Optional[PlaybookJobStatus] = Field(default=None, description="Background job status")
    remark: Optional[str] = Field(default="", description="Execution remark")
    type: Optional[PlaybookType] = Field(default=None, description="Linked object type")
    name: Optional[str] = Field(default="", description="Executed playbook name")

    user_input: Optional[str] = Field(default="", description="Initial or follow-up user input")
    user: Optional[Union[List[AccountModel], AccountModel, str]] = Field(default=None, description="Playbook requester")

    # 关联表
    messages: Optional[List[Union[MessageModel, str]]] = Field(default=None, description="Execution message history")


class KnowledgeModel(BaseSystemModel):
    title: Optional[str] = Field(default="", description="Knowledge title")
    body: Optional[str] = Field(default="", description="Knowledge content")
    using: Optional[bool] = Field(default=False, description="Currently in use")
    action: Optional[KnowledgeAction] = Field(default=None, description="Knowledge action")
    source: Optional[KnowledgeSource] = Field(default=None, description="Knowledge source")
    tags: Optional[List[str]] = Field(default=[], description="Knowledge tags", json_schema_extra={"type": 2})


class EnrichmentModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default="", description="Enrichment name")
    type: Optional[str] = Field(default="Other", description="Enrichment type", json_schema_extra={"type": 2})
    provider: Optional[str] = Field(default="Other", description="Enrichment provider", json_schema_extra={"type": 2})
    value: Optional[str] = Field(default="", description="Enrichment value")
    src_url: Optional[str] = Field(default="", description="Enrichment source URL")
    desc: Optional[str] = Field(default="", description="Enrichment summary")
    data: Optional[str] = Field(default="", description="Detailed enrichment JSON")


class TicketModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}

    status: Optional[TicketStatus] = Field(
        default=None, description="External ticket status")
    type: Optional[TicketType] = Field(default=None, description="External ticket type",
                                       json_schema_extra={"type": 2})
    title: Optional[str] = Field(default="", description="Ticket title")
    uid: Optional[str] = Field(default="", description="External ticket ID")
    src_url: Optional[str] = Field(default="", description="External ticket URL")


class ArtifactModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid'}
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default="", description="Artifact name")
    type: Optional[ArtifactType] = Field(
        default=None, description="Artifact type")
    role: Optional[ArtifactRole] = Field(default=None,
                                         description="Artifact role in event")
    owner: Optional[str] = Field(default="", description="Owning system or user")
    value: Optional[str] = Field(default="", description="Artifact value")
    reputation_provider: Optional[str] = Field(default="", description="Threat intel provider", json_schema_extra={"type": 2})
    reputation_score: Optional[ArtifactReputationScore] = Field(
        default=None, description="Artifact reputation")

    # 关联表
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="Artifact enrichments")  # None 时表示无需处理,[] 时表示要将 link 清空

    # playbooks: Optional[Any] = "" # 内部字段
    # playbook: Optional[Literal['TI Enrichment By AlienVaultOTX', 'TI Enrichment By Mock', None]] = None # 内部字段
    # user_input: Optional[str] = "" # 内部字段


class AlertModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid', "comment_ai", "case", "attachments"}
    id: Optional[str] = Field(default=None)
    severity: Optional[Severity] = Field(default=None,
                                         description="Source-defined severity")
    title: Optional[str] = Field(default="", description="Alert title")
    impact: Optional[ImpactLevel] = Field(default=None, description="Potential impact")
    disposition: Optional[Disposition] = Field(
        default=None, description="Source disposition")
    action: Optional[AlertAction] = Field(default=None,
                                          description="Observed action")
    confidence: Optional[Confidence] = Field(default=None,
                                             description="True-positive confidence")
    uid: Optional[str] = Field(default="", description="Alert unique ID")
    labels: Optional[List[str]] = Field(default=[], description="Alert labels", json_schema_extra={"type": 2})
    desc: Optional[str] = Field(default="", description="Alert description")

    first_seen_time: Optional[Union[datetime, str]] = Field(default=None, description="First observed time")
    last_seen_time: Optional[Union[datetime, str]] = Field(default=None, description="Last observed time")

    rule_id: Optional[str] = Field(default="", description="Trigger rule ID")
    rule_name: Optional[str] = Field(default="", description="Trigger rule name")
    correlation_uid: Optional[str] = Field(default="", description="Event correlation ID")
    count: Optional[Union[int, str]] = Field(default=None, description="Aggregated event count")

    src_url: Optional[str] = Field(default="", description="Source alert URL")
    source_uid: Optional[str] = Field(default="", description="Source product ID")
    data_sources: Optional[List[str]] = Field(default=[], description="Underlying data sources")

    analytic_name: Optional[str] = Field(default="", description="Analytic engine name")
    analytic_type: Optional[AlertAnalyticType] = Field(
        default=None, description="Analytic engine type")
    analytic_state: Optional[AlertAnalyticState] = Field(default=None, description="Analytic rule state")
    analytic_desc: Optional[str] = Field(default="", description="Analytic rule description")

    tactic: Optional[str] = Field(default="", description="Mapped MITRE tactic")
    technique: Optional[str] = Field(default="", description="Mapped MITRE technique")
    sub_technique: Optional[str] = Field(default="", description="Mapped MITRE sub-technique")
    mitigation: Optional[str] = Field(default="", description="Suggested mitigation")

    product_category: Optional[ProductCategory] = Field(default=None,
                                                        description="Source product category")
    product_vendor: Optional[str] = Field(default=None, description="Source vendor", json_schema_extra={"type": 2})
    product_name: Optional[str] = Field(default=None, description="Source product name", json_schema_extra={"type": 2})
    product_feature: Optional[str] = Field(default=None, description="Source product feature", json_schema_extra={"type": 2})

    policy_name: Optional[str] = Field(default="", description="Trigger policy name")
    policy_type: Optional[AlertPolicyType] = Field(default=None,
                                                   description="Trigger policy type")
    policy_desc: Optional[str] = Field(default="", description="Trigger policy description")

    risk_level: Optional[AlertRiskLevel] = Field(default=None, description="Assessed risk level")
    risk_details: Optional[str] = Field(default="", description="Risk assessment details")

    status: Optional[AlertStatus] = Field(default=None,
                                          description="Alert handling status")
    status_detail: Optional[str] = Field(default="", description="Handling status details")
    remediation: Optional[str] = Field(default="", description="Remediation advice or record")

    comment: Optional[str] = Field(default="", description="Analyst comment")

    unmapped: Optional[str] = Field(default="", description="Raw unmapped fields")

    raw_data: Optional[str] = Field(default="", description="Raw alert log JSON")

    attachments: Optional[Union[List[AttachmentModel], str]] = Field(default=[], description="Alert attachments")

    # AI字段
    comment_ai: Optional[str] = Field(default="", description="AI-generated comment")

    # 反向关联
    case: Optional[List[Union[CaseModel, str]]] = Field(default=None, description="Linked case row IDs")

    # 关联表
    artifacts: Optional[List[Union[ArtifactModel, str]]] = Field(default=None, description="Extracted artifacts")
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="Alert enrichments")

    @field_validator('attachments', mode='before')
    def handle_attachments(cls, v):
        if v == "":
            return []
        return v


class CaseModel(BaseSystemModel):
    ai_exclude_fields: ClassVar[set[str]] = {'ownerid', 'caid', 'uaid', "workbook", "summary_ai", "comment_ai", "attack_stage_ai",
                                             "severity_ai", "confidence_ai",
                                             "threat_hunting_report_ai"}
    id: Optional[str] = Field(default=None)
    title: Optional[str] = Field(default="", description="Case title")
    severity: Optional[Severity] = Field(default=None,
                                         description="Analyst-assessed severity")
    impact: Optional[ImpactLevel] = Field(default=None, description="Analyst-assessed impact")
    priority: Optional[CasePriority] = Field(default=None, description="Response priority")
    src_url: Optional[str] = Field(default="", description="Source case URL")
    confidence: Optional[Confidence] = Field(default=None, description="Analyst-assessed confidence")
    description: Optional[str] = Field(default="", description="Case description")

    category: Optional[ProductCategory] = Field(default=None,
                                                description="Case category")
    tags: Optional[List[str]] = Field(default=[], description="Case tags", json_schema_extra={"type": 2})

    status: Optional[CaseStatus] = Field(default=None,
                                         description="Case handling status")
    assignee_l1: Optional[Union[List[AccountModel], AccountModel, str]] = Field(default=None, description="Assigned L1 analyst")
    acknowledged_time: Optional[Union[datetime, str]] = Field(default=None, description="L1 first acknowledged time")
    comment: Optional[str] = Field(default="", description="Case analyst comment")
    attachments: Optional[List[Union[AttachmentModel, AttachmentCreateModel]]] = Field(default=[], description="Case attachments")

    assignee_l2: Optional[Union[List[AccountModel], AccountModel, str]] = Field(default=None, description="Assigned or escalated L2 analyst")
    assignee_l3: Optional[Union[List[AccountModel], AccountModel, str]] = Field(default=None, description="Assigned or escalated L3 analyst")
    closed_time: Optional[Union[datetime, str]] = Field(default=None, description="Case closed time")
    verdict: Optional[CaseVerdict] = Field(
        default=None, description="Final verdict")
    summary: Optional[str] = Field(default="", description="Closure summary")

    correlation_uid: Optional[str] = Field(default="", description="Case correlation ID")

    workbook: Optional[str] = Field(default="", description="Investigation workbook")

    # ai 字段
    attack_stage_ai: Optional[AttackStage] = Field(default="", description="AI-assessed attack stage")
    severity_ai: Optional[Severity] = Field(default=None,
                                            description="AI-assessed severity")
    confidence_ai: Optional[Confidence] = Field(default=None, description="AI-assessed confidence")
    comment_ai: Optional[str] = Field(default="", description="AI-generated comment")
    summary_ai: Optional[str] = Field(default="", description="AI-generated closure summary")
    threat_hunting_report_ai: Optional[str] = Field(default="", description="AI-generated hunting report")

    # 公式计算字段
    start_time_calc: Optional[Any] = Field(default=None, description="Calculated start time")
    end_time_calc: Optional[Any] = Field(default=None, description="Calculated end time")
    detect_time_calc: Optional[Any] = Field(default=None, description="Calculated detect time")
    acknowledge_time_calc: Optional[Any] = Field(default=None, description="Calculated acknowledge time")
    respond_time_calc: Optional[Any] = Field(default=None, description="Calculated response time")

    # 关联表
    tickets: Optional[List[Union[TicketModel, str]]] = Field(default=None, description="Linked external tickets")
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="Case enrichments")
    alerts: Optional[List[Union[AlertModel, str]]] = Field(default=None, description="Merged alerts")

    @field_validator('attachments', mode='before')
    def handle_attachments(cls, v):
        if v == "":
            return []
        return v
