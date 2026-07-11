from django.db import models

from apps.common.models import BaseModel
from apps.common.readable_ids import save_with_readable_id


def value_labeled(choice_class):
    for member in choice_class:
        member._label_ = member.value
    return choice_class


@value_labeled
class Severity(models.TextChoices):
    UNKNOWN = "Unknown"
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@value_labeled
class Confidence(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@value_labeled
class Impact(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@value_labeled
class Disposition(models.TextChoices):
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


@value_labeled
class AlertAction(models.TextChoices):
    UNKNOWN = "Unknown"
    ALLOWED = "Allowed"
    DENIED = "Denied"
    OBSERVED = "Observed"
    MODIFIED = "Modified"
    OTHER = "Other"


@value_labeled
class AlertAnalyticType(models.TextChoices):
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


@value_labeled
class AlertAnalyticState(models.TextChoices):
    UNKNOWN = "Unknown"
    ACTIVE = "Active"
    SUPPRESSED = "Suppressed"
    EXPERIMENTAL = "Experimental"
    OTHER = "Other"


@value_labeled
class ProductCategory(models.TextChoices):
    DLP = "DLP"
    EMAIL = "Email"
    OT = "OT"
    PROXY = "Proxy"
    UEBA = "UEBA"
    TI = "ThreatIntelligence"
    IAM = "IAM"
    EDR = "EDR"
    NDR = "NDR"
    CLOUD = "Cloud"
    SIEM = "SIEM"
    WAF = "WAF"
    OTHER = "Other"


@value_labeled
class AlertPolicyType(models.TextChoices):
    IDENTITY_POLICY = "Identity Policy"
    RESOURCE_POLICY = "Resource Policy"
    SERVICE_CONTROL_POLICY = "Service Control Policy"
    ACCESS_CONTROL_POLICY = "Access Control Policy"
    OTHER = "Other"


@value_labeled
class AlertRiskLevel(models.TextChoices):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    OTHER = "Other"


@value_labeled
class AlertStatus(models.TextChoices):
    UNKNOWN = "Unknown"
    NEW = "New"
    IN_PROGRESS = "In Progress"
    SUPPRESSED = "Suppressed"
    RESOLVED = "Resolved"
    ARCHIVED = "Archived"
    DELETED = "Deleted"
    OTHER = "Other"


@value_labeled
class AlertTactic(models.TextChoices):
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


class Alert(BaseModel):
    alert_id = models.CharField(max_length=32, unique=True, editable=False, db_index=True, blank=True, default="", help_text="Record ID e.g. alert_000001, auto-generated, no manual input needed (记录 ID e.g. alert_000001, 系统自动生成,无需手动赋值)")
    case = models.ForeignKey("cases.Case", on_delete=models.CASCADE, related_name="alerts", help_text="Linked case id, reverse association, auto-linked, no manual setting needed (关联案件行 ID,反向关联,自动化关联,无需手动设置)")
    title = models.CharField(max_length=500, blank=True, default="", help_text="Alert title (告警标题)")
    severity = models.CharField(max_length=20, choices=Severity, default=Severity.UNKNOWN, help_text="Source-defined severity (告警来源定义的严重程度)")
    confidence = models.CharField(max_length=20, choices=Confidence, default=Confidence.UNKNOWN, help_text="True-positive confidence (真阳性置信度)")
    impact = models.CharField(max_length=20, choices=Impact, default=Impact.UNKNOWN, help_text="Potential impact (告警潜在影响)")
    disposition = models.CharField(max_length=20, choices=Disposition, default=Disposition.UNKNOWN, help_text="Source disposition (告警源处置结果)")
    action = models.CharField(max_length=20, choices=AlertAction, default=AlertAction.UNKNOWN, help_text="Observed action (告警源的动作)")
    labels = models.JSONField(default=list, blank=True, help_text="Alert labels (告警标签)")
    desc = models.TextField(blank=True, default="", help_text="Alert description (告警描述)")
    first_seen_time = models.DateTimeField(null=True, blank=True, help_text="First observed time (首次观测时间)")
    last_seen_time = models.DateTimeField(null=True, blank=True, help_text="Last observed time (最后观测时间)")
    rule_id = models.CharField(max_length=255, blank=True, default="", help_text="SIEM rule ID (SIEM 规则 ID)")
    rule_name = models.CharField(max_length=255, blank=True, default="", help_text="SIEM rule name (SIEM 规则名称)")
    correlation_uid = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Case correlation ID, alerts with the same correlation_uid are linked to the same event (事件关联 ID,相同 correlation_uid 告警关联到同一个事件)")
    src_url = models.URLField(max_length=500, blank=True, default="", help_text="Source alert URL (原始告警 URL)")
    source_uid = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Source product ID, can be used to locate the unique alert in the source system (原始告警 唯一ID, 可通过该 ID 在原始来源中定位唯一告警)")
    data_sources = models.JSONField(default=list, blank=True, help_text="Underlying data sources (告警源生成告警的数据来源列表)")
    analytic_name = models.CharField(max_length=255, blank=True, default="", help_text="Analytic engine name (分析引擎名称)")
    analytic_type = models.CharField(max_length=30, choices=AlertAnalyticType, default=AlertAnalyticType.UNKNOWN, help_text="Analytic engine type (分析引擎类型)")
    analytic_state = models.CharField(max_length=20, choices=AlertAnalyticState, blank=True, default="", help_text="Analytic rule state (分析规则状态)")
    analytic_desc = models.TextField(blank=True, default="", help_text="Analytic rule description (分析规则描述)")
    tactic = models.CharField(max_length=100, choices=AlertTactic, blank=True, default="", help_text="Mapped MITRE tactic (映射的 MITRE 战术)")
    technique = models.CharField(max_length=100, blank=True, default="", help_text="Mapped MITRE technique (映射的 MITRE 技术)")
    sub_technique = models.CharField(max_length=100, blank=True, default="", help_text="Mapped MITRE sub-technique (映射的 MITRE 子技术)")
    mitigation = models.TextField(blank=True, default="", help_text="Suggested mitigation (建议的缓解措施)")
    product_category = models.CharField(max_length=30, choices=ProductCategory, blank=True, default="", help_text="Source product category (原始产品类别)")
    product_vendor = models.CharField(max_length=255, blank=True, default="", help_text="Source vendor (原始厂商)")
    product_name = models.CharField(max_length=255, blank=True, default="", help_text="Source product name (原始产品名称)")
    product_feature = models.CharField(max_length=255, blank=True, default="", help_text="Source product feature (原始产品功能)")
    policy_name = models.CharField(max_length=255, blank=True, default="", help_text="Trigger policy name (触发策略名称)")
    policy_type = models.CharField(max_length=30, choices=AlertPolicyType, blank=True, default="", help_text="Trigger policy type (触发策略类型)")
    policy_desc = models.TextField(blank=True, default="", help_text="Trigger policy description (触发策略描述)")
    risk_level = models.CharField(max_length=20, choices=AlertRiskLevel, blank=True, default="", help_text="Assessed risk level (评估的风险等级)")
    status = models.CharField(max_length=20, choices=AlertStatus, default=AlertStatus.NEW, help_text="Alert handling status (告警处理状态)")
    status_detail = models.TextField(blank=True, default="", help_text="Handling status details (处理状态详情)")
    remediation = models.TextField(blank=True, default="", help_text="Remediation advice or record (处置建议或记录)")
    unmapped = models.JSONField(default=dict, blank=True, help_text="Raw unmapped fields, JSON Format (原始未映射字段 JSON 格式)")
    raw_data = models.JSONField(default=dict, blank=True, help_text="Raw alert log JSON (原始告警日志 JSON)")

    # M2M
    artifacts = models.ManyToManyField("artifacts.Artifact", related_name="alerts", blank=True, help_text="Extracted artifacts (关联表, 提取的实体列表)")

    def save(self, *args, **kwargs):
        return save_with_readable_id(self, "alert_id", "alert", *args, **kwargs)

    class Meta:
        db_table = "alerts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "-id"], name="alert_created_id_idx"),
            models.Index(fields=["-first_seen_time", "-id"], name="alert_first_seen_id_idx"),
        ]

    def __str__(self):
        return self.title or str(self.id)
