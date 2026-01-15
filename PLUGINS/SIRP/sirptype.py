from datetime import datetime
from typing import List, Optional, Literal, Any, Union

from pydantic import BaseModel, Field, field_validator, ConfigDict


class Account(BaseModel):
    accountId: Optional[str] = None
    avatar: Optional[str] = None
    email: Optional[str] = None
    fullname: Optional[str] = None
    jobNumber: Optional[str] = None
    mobilePhone: Optional[str] = None
    status: Optional[int] = None


class Attachment(BaseModel):
    DownloadUrl: Optional[str] = None
    WaterMarkInfo: Optional[Any] = None
    allow_down: Optional[bool] = None
    allow_edit: Optional[bool] = None
    allow_view: Optional[bool] = None
    createTime: Optional[Union[datetime, str]] = None
    duration: Optional[float] = None
    file_id: Optional[str] = None
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    file_type: Optional[int] = None
    height: Optional[int] = None
    is_delete: Optional[bool] = None
    is_knowledge: Optional[bool] = None
    large_thumbnail_name: Optional[str] = None
    large_thumbnail_path: Optional[str] = None
    node_id: Optional[str] = ""
    origin_link_url: Optional[str] = None
    original_file_full_path: Optional[str] = None
    original_file_name: Optional[str] = None
    preview_url: Optional[str] = None
    share_folder_url: Optional[str] = None
    short_link_url: Optional[str] = None
    thumbnail_name: Optional[str] = ""
    thumbnail_path: Optional[str] = ""
    width: Optional[int] = None


class BaseSystemModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    rowid: Optional[str] = None
    ownerid: Optional[Account] = None
    caid: Optional[Account] = None
    ctime: Optional[Union[datetime, str]] = None
    utime: Optional[Union[datetime, str]] = None
    uaid: Optional[Account] = None

    # 流程相关参数
    wfname: Optional[str] = None
    wfcuaids: Optional[Any] = None
    wfcaid: Optional[Any] = None
    wfctime: Optional[Union[datetime, str]] = None
    wfrtime: Optional[Union[datetime, str]] = None
    wfcotime: Optional[Union[datetime, str]] = None
    wfdtime: Optional[Union[datetime, str]] = None
    wfftime: Optional[Any] = None
    wfstatus: Optional[Literal["通过", "否决", "中止", "进行中", "", None]] = None

    @field_validator(
        "ctime", "utime", "wfctime", "wfrtime", "wfcotime", "wfdtime",
        "created_time", "modified_time", "first_seen_time", "last_seen_time", "acknowledged_time", "closed_time",
        check_fields=False
    )
    @classmethod
    def parse_datetime(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip():
            try:
                return datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return v
        return v


class AlertModel(BaseSystemModel):
    severity: Optional[Literal["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal", "Other", None]] = None
    title: Optional[str] = ""
    impact: Optional[Literal["Unknown", "Low", "Medium", "High", "Critical", "Other", None]] = None
    disposition: Optional[Literal[
        "Unknown", "Allowed", "Blocked", "Quarantined", "Isolated", "Deleted", "Dropped", "Custom Action", "Approved", "Restored", "Exonerated", "Corrected", "Partially Corrected", "Uncorrected", "Delayed", "Detected", "No Action", "Logged", "Tagged", "Alert", "Count", "Reset", "Captcha", "Challenge", "Access Revoked", "Rejected", "Unauthorized", "Error", "Other", None]] = None
    action: Optional[Literal["Unknown", "Allowed", "Denied", "Observed", "Modified", "Other", None]] = None
    confidence: Optional[Literal["Unknown", "Low", "Medium", "High", "Other", None]] = None
    uid: Optional[str] = ""
    labels: Optional[List[str]] = []
    desc: Optional[str] = ""

    created_time: Optional[Union[datetime, str]] = None
    modified_time: Optional[Union[datetime, str]] = None
    first_seen_time: Optional[Union[datetime, str]] = None
    last_seen_time: Optional[Union[datetime, str]] = None
    correlation: Optional[Any] = ""
    rule_id: Optional[str] = ""
    rule_name: Optional[str] = ""
    correlation_uid: Optional[str] = ""
    count: Optional[Union[int, str]] = None
    case: Optional[List[Any]] = []

    src_url: Optional[str] = ""
    source_uid: Optional[str] = ""
    data_sources: Optional[List[str]] = []
    analytic: Optional[Any] = ""
    analytic_name: Optional[str] = ""
    analytic_type: Optional[Literal[
        "Unknown", "Rule", "Behavioral", "Statistical", "Learning (ML/DL)", "Fingerprinting", "Tagging", "Keyword Match", "Regular Expressions", "Exact Data Match", "Partial Data Match", "Indexed Data Match", "Other", None]] = None
    analytic_state: Optional[Literal["Unknown", "Active", "Suppressed", "Experimental", "Other", None]] = None
    analytic_desc: Optional[str] = ""

    tactic: Optional[str] = ""
    technique: Optional[str] = ""
    sub_technique: Optional[str] = ""
    mitigation: Optional[str] = ""

    product_category: Optional[Literal["DLP", "Email", "OT", "Proxy", "UEBA", "TI", "IAM", "EDR", "NDR", "Cloud", "Other", None]] = None
    product_vender: Optional[str] = None
    product_name: Optional[str] = None
    product_feature: Optional[str] = None

    policy_name: Optional[str] = ""
    policy_type: Optional[Literal["Identity Policy", "Resource Policy", "Service Control Policy", None]] = None
    policy_desc: Optional[str] = ""

    risk_level: Optional[Literal["Info", "Low", "Medium", "High", "Critical", "Other", None]] = None
    risk_details: Optional[str] = ""
    status: Optional[Literal["Unknown", "New", "In Progress", "Suppressed", "Resolved", "Archived", "Deleted", "Other", None]] = None
    status_detail: Optional[str] = ""
    remediation: Optional[str] = ""

    attachments: Optional[Attachment] = ""
    comment: Optional[str] = ""

    suggestion_ai: Optional[str] = ""

    artifacts: Optional[List[Any]] = []

    enrichments: Optional[List[Any]] = []

    unmapped: Optional[str] = ""

    raw_data: Optional[str] = ""

    # playbooks: Optional[Any] = "" # 内部字段
    # playbook: Optional[Literal["Alert Analysis Agent", None]] = None # 内部字段
    # user_input: Optional[str] = "" # 内部字段


class Case(BaseSystemModel):
    title: str = Field(...)
    description: Optional[str] = ""
    status: Optional[Literal["Unknown", "New", "In Progress", "On Hold", "Resolved", "Closed", "Other", None]] = None
    category: Optional[Literal["DLP", "Email", "OT", "Proxy", "UEBA", "TI", "IAM", "EDR", "NDR", "Cloud", "Other", None]] = None
    tags: Optional[List[str]] = []
    created_time: Optional[Union[datetime, str]] = None

    assignee_l1: Optional[Account] = None
    acknowledged_time: Optional[Union[datetime, str]] = None
    comment: Optional[str] = ""

    closed_time: Optional[Union[datetime, str]] = None
    summary: Optional[str] = ""

    attachments: Optional[Attachment] = ""

    severity: Optional[Literal["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal", "Other", None]] = None
    confidence: Optional[Literal["Unknown", "Low", "Medium", "High", "Other", None]] = None

    correlation_uid: Optional[str] = ""
    alerts: Optional[List[Any]] = []

    workbook: Optional[str] = ""

    analysis_rationale_ai: Optional[str] = ""
    recommended_actions_ai: Optional[str] = ""
    attack_stage_ai: Optional[str] = ""
    severity_ai: Optional[Literal["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal", "Other", None]] = None
    confidence_ai: Optional[Literal["Unknown", "Low", "Medium", "High", "Other", None]] = None

    threat_hunting_report: Optional[str] = ""

    assignee_l2: Optional[Account] = None
    assignee_l3: Optional[Account] = None

    enrichments: Optional[List[Any]] = []
    impact: Optional[Literal["Unknown", "Low", "Medium", "High", "Critical", "Other", None]] = None
    priority: Optional[Literal["Unknown", "Low", "Medium", "High", "Critical", "Other", None]] = None
    src_url: Optional[str] = ""
    tickets: Optional[List[Any]] = []
    verdict: Optional[Literal[
        "Unknown", "False Positive", "True Positive", "Disregard", "Suspicious", "Benign", "Test", "Insufficient Data", "Security Risk", "Managed Externally", "Duplicate", "Other", None]] = None

    # start_time: Optional[Any] = None # 使用公式自动化计算,无需处理
    # end_time: Optional[Any] = None # 使用公式自动化计算,无需处理
    # playbook: Optional[Literal["Threat Hunting Agent", "L3 SOC Analyst Agent", "L3 SOC Analyst Agent With Tools", None]] = None # 内部字段
    # user_input: Optional[str] = "" # 内部字段
    # playbooks: Optional[Any] = "" # 内部字段

    # MTTR MTTD
    # detect_time: Optional[Any] = None # 使用公式自动化计算,无需处理
    # acknowledge_time: Optional[Any] = None # 使用公式自动化计算,无需处理
    # respond_time: Optional[Any] = None # 使用公式自动化计算,无需处理


class Artifact(BaseSystemModel):
    name: Optional[str] = ""
    type: Optional[Literal[
        'Unknown', 'Hostname', 'IP Address', 'MAC Address', 'User Name', 'Email Address', 'URL String', 'File Name', 'Hash', 'Process Name', 'Resource UID', 'Port', 'Subnet', 'Command Line', 'Country', 'Process ID', 'HTTP User-Agent', 'CWE', 'CVE', 'User Credential ID', 'Endpoint', 'User', 'Email', 'Uniform Resource Locator', 'File', 'Process', 'Geo Location', 'Container', 'Registry', 'Fingerprint', 'Group', 'Account', 'Script Content', 'Serial Number', 'Resource', 'Message', 'Advisory', 'File Path', 'Device', 'Other', None]] = None
    role: Optional[Literal['Unknown', 'Target', 'Actor', 'Affected', 'Related', 'Other', None]] = None
    owner: Optional[str] = ""
    value: Optional[str] = ""
    reputation_provider: Optional[str] = ""
    reputation_score: Optional[Literal[
        'Unknown', 'Very Safe', 'Safe', 'Probably Safe', 'Leans Safe', 'May not be Safe', 'Exercise Caution', 'Suspicious/Risky', 'Possibly Malicious', 'Probably Malicious', 'Malicious', 'Other', None]] = None
    enrichment: Optional[str] = ""

    # playbooks: Optional[Any] = ""
    # playbook: Optional[Literal['TI Enrichment By AlienVaultOTX', 'TI Enrichment By Mock', None]] = None
    # user_input: Optional[str] = ""


class Enrichment(BaseSystemModel):
    name: str = Field(...)
    type: Literal["Other"] = Field(...)
    provider: Optional[Literal["Other", None]] = None
    created_time: Optional[Union[datetime, str]] = None
    value: str = Field(...)
    src_url: Optional[str] = ""
    desc: Optional[str] = ""
    data: Optional[str] = ""


class Ticket(BaseSystemModel):
    status: Optional[Literal['Unknown', 'New', 'In Progress', 'Notified', 'On Hold', 'Resolved', 'Closed', 'Canceled', 'Reopened', 'Other', None]] = None
    type: Optional[Literal['Other', 'Jira', 'ServiceNow', None]] = None
    title: Optional[str] = ""
    uid: str = Field(...)
    src_url: str = Field(...)
