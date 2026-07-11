from django.conf import settings
from django.db import models

from apps.common.models import BaseModel
from apps.common.readable_ids import save_with_readable_id


class CaseSeverity(models.TextChoices):
    UNKNOWN = "Unknown"
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class CaseImpact(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class CasePriority(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class CaseConfidence(models.TextChoices):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class CaseStatus(models.TextChoices):
    NEW = "New"
    IN_PROGRESS = "In Progress"
    ON_HOLD = "On Hold"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


class CaseVerdict(models.TextChoices):
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


class CaseCategory(models.TextChoices):
    DLP = "DLP", "DLP"
    EMAIL = "Email"
    OT = "OT", "OT"
    PROXY = "Proxy"
    UEBA = "UEBA", "UEBA"
    TI = "ThreatIntelligence", "TI"
    IAM = "IAM", "IAM"
    EDR = "EDR", "EDR"
    NDR = "NDR", "NDR"
    CLOUD = "Cloud"
    SIEM = "SIEM", "SIEM"
    WAF = "WAF", "WAF"
    OTHER = "Other"


class Case(BaseModel):
    case_id = models.CharField(max_length=32, unique=True, editable=False, db_index=True, blank=True, default="", help_text="Record ID e.g. case_000001 (记录 ID e.g. case_000001,系统自动生成,无需手动赋值)")
    title = models.CharField(max_length=500, help_text="Case title (案件标题)")
    severity = models.CharField(max_length=20, choices=CaseSeverity, blank=True, default="", help_text="Analyst-assessed severity (严重程度)")
    impact = models.CharField(max_length=20, choices=CaseImpact, blank=True, default="", help_text="Analyst-assessed impact (影响)")
    priority = models.CharField(max_length=20, choices=CasePriority, blank=True, default="", help_text="Response priority (响应优先级)")
    confidence = models.CharField(max_length=20, choices=CaseConfidence, blank=True, default="", help_text="Analyst-assessed confidence (分析师评估置信度)")
    description = models.TextField(blank=True, default="", help_text="Case description (案件描述)")
    category = models.CharField(max_length=30, choices=CaseCategory, blank=True, default="", help_text="Case category (案件类别)")
    tags = models.JSONField(default=list, blank=True, help_text="Case tags (案件标签)")
    status = models.CharField(max_length=20, choices=CaseStatus, default=CaseStatus.NEW, help_text="Case handling status (案件处理状态)")
    verdict = models.CharField(max_length=30, choices=CaseVerdict, blank=True, default="", help_text="Final verdict (最终判定结果)")
    summary = models.TextField(blank=True, default="", help_text="Closure summary (结案摘要)")
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_cases",
        help_text="Current assigned analyst handling the case (当前正在处理案件的分析师)",
    )
    acknowledged_time = models.DateTimeField(null=True, blank=True, help_text="L1 first acknowledged time (L1 首次接手时间)")
    closed_time = models.DateTimeField(null=True, blank=True, help_text="case close time (事件关闭时间)")
    correlation_uid = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Case correlation ID (案件关联 ID)")

    # AI fields
    severity_ai = models.CharField(max_length=20, choices=CaseSeverity, blank=True, default="", help_text="AI-assessed severity (AI 评估严重程度)")
    confidence_ai = models.CharField(max_length=20, choices=CaseConfidence, blank=True, default="", help_text="AI-assessed confidence (AI 评估置信度)")
    impact_ai = models.CharField(max_length=20, choices=CaseImpact, blank=True, default="", help_text="AI-assessed impact (AI 评估影响)")
    priority_ai = models.CharField(max_length=20, choices=CasePriority, blank=True, default="", help_text="AI-assessed response priority (AI 评估响应优先级)")
    verdict_ai = models.CharField(max_length=30, choices=CaseVerdict, blank=True, default="", help_text="AI-generated final verdict (AI 生成的最终判定结果)")
    investigation_report_ai_json = models.TextField(blank=True, default="", help_text="AI-generated investigation report JSON Format (AI 生成的调查报告 JSON 格式)")

    def save(self, *args, **kwargs):
        return save_with_readable_id(self, "case_id", "case", *args, **kwargs)

    class Meta:
        db_table = "cases"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "-id"], name="case_created_id_idx"),
        ]

    def __str__(self):
        return self.title or str(self.id)
