"""Reusable mock data importer.

Run from ``backend``:

    .\\.venv\\Scripts\\python.exe manage.py shell -c "from mock.import_mock_data import run; run()"

The script is safe to run repeatedly. Each run creates a new mock batch instead
of overwriting earlier mock data. Audit logs are generated with the
``automation`` user as actor.
"""

import json
from datetime import timedelta

from django.utils import timezone

from apps.accounts.models import User
from apps.alerts.models import (
    Alert,
    AlertAction,
    AlertAnalyticState,
    AlertAnalyticType,
    AlertPolicyType,
    AlertRiskLevel,
    AlertStatus,
    Confidence,
    Disposition,
    Impact,
    ProductCategory,
    Severity,
)
from apps.artifacts.models import Artifact, ArtifactName, ArtifactRole, ArtifactType
from apps.audit.context import audit_actor
from apps.cases.models import (
    Case,
    CaseCategory,
    CaseConfidence,
    CaseImpact,
    CasePriority,
    CaseSeverity,
    CaseStatus,
    CaseVerdict,
)
from apps.comments.services import create_record_comment
from apps.enrichments.models import Enrichment, EnrichmentProvider, EnrichmentType
from apps.knowledge.models import Knowledge, KnowledgeSource
from apps.playbooks.models import Playbook, PlaybookJobStatus

MOCK_TAG = "mock-data"
MOCK_MARKER = "[mock-data]"
MOCK_CORRELATION_PREFIX = "MOCK-CORR-"
MOCK_ALERT_SOURCE_PREFIX = "MOCK-SRC-"
MOCK_ENRICHMENT_UID_PREFIX = "mock:"
MOCK_PLAYBOOK_JOB_PREFIX = "mock-job-"

PLAYBOOK_INVESTIGATION = "Investigation"
PLAYBOOK_KNOWLEDGE_EXTRACTION = "Knowledge Extraction"
PLAYBOOK_TI_ENRICHMENT = "Threat Intelligence Enrichment"
PLAYBOOK_CMDB_ENRICHMENT = "CMDB Enrichment"


def minutes(value):
    return timedelta(minutes=value)


def hours(value):
    return timedelta(hours=value)


def days(value):
    return timedelta(days=value)


def new_batch_id():
    return timezone.now().strftime("%Y%m%d%H%M%S%f")


def batch_tag(batch_id):
    return f"{MOCK_TAG}:{batch_id}"


CASE_SPECS = [
    {
        "key": "ransomware-finance",
        "title": "Critical ransomware indicators on finance workstation",
        "category": CaseCategory.EDR,
        "severity": CaseSeverity.CRITICAL,
        "confidence": CaseConfidence.HIGH,
        "impact": CaseImpact.CRITICAL,
        "priority": CasePriority.CRITICAL,
        "status": CaseStatus.IN_PROGRESS,
        "verdict": CaseVerdict.SECURITY_RISK,
        "assignee": "alice.chen",
        "tags": ["ransomware", "finance", "endpoint", "critical"],
        "first_seen_offset": days(2) + hours(4),
        "detection_delay": minutes(11),
        "ack_delay": minutes(7),
        "resolution_delay": None,
        "summary": "Containment started. Endpoint isolated and credential reset requested for the affected user.",
        "description": "EDR detected shadow copy deletion, suspicious encryption activity, and ransom note creation on a finance endpoint.",
        "ai": {"hypothesis": "Active ransomware behavior", "confidence": "High", "recommended_actions": ["isolate host", "preserve disk image", "reset credentials"]},
    },
    {
        "key": "cloud-impossible-travel",
        "title": "Impossible travel followed by privileged cloud console access",
        "category": CaseCategory.IAM,
        "severity": CaseSeverity.HIGH,
        "confidence": CaseConfidence.HIGH,
        "impact": CaseImpact.HIGH,
        "priority": CasePriority.HIGH,
        "status": CaseStatus.NEW,
        "verdict": CaseVerdict.UNKNOWN,
        "assignee": "bob.li",
        "tags": ["identity", "cloud", "aws", "impossible-travel"],
        "first_seen_offset": hours(18),
        "detection_delay": minutes(24),
        "ack_delay": None,
        "resolution_delay": None,
        "summary": "",
        "description": "Identity provider sign-in telemetry shows impossible travel and subsequent AWS IAM policy enumeration.",
        "ai": {"hypothesis": "Credential compromise", "entities": ["user", "aws role"], "confidence": "Medium"},
    },
    {
        "key": "dns-tunneling",
        "title": "Suspicious outbound DNS tunneling pattern",
        "category": CaseCategory.NDR,
        "severity": CaseSeverity.MEDIUM,
        "confidence": CaseConfidence.MEDIUM,
        "impact": CaseImpact.MEDIUM,
        "priority": CasePriority.MEDIUM,
        "status": CaseStatus.ON_HOLD,
        "verdict": CaseVerdict.SUSPICIOUS,
        "assignee": "maya.singh",
        "tags": ["dns", "tunneling", "ndr"],
        "first_seen_offset": days(3) + hours(6),
        "detection_delay": hours(2) + minutes(10),
        "ack_delay": minutes(46),
        "resolution_delay": None,
        "summary": "Waiting for endpoint owner confirmation before blocking the domain at DNS layer.",
        "description": "NDR detected high-volume TXT queries to a newly registered domain with encoded subdomain labels.",
        "ai": {"hypothesis": "Possible DNS tunneling", "confidence": "Medium", "open_questions": ["business justification"]},
    },
    {
        "key": "executive-phishing",
        "title": "Phishing campaign targeting executives",
        "category": CaseCategory.EMAIL,
        "severity": CaseSeverity.HIGH,
        "confidence": CaseConfidence.HIGH,
        "impact": CaseImpact.MEDIUM,
        "priority": CasePriority.HIGH,
        "status": CaseStatus.RESOLVED,
        "verdict": CaseVerdict.TRUE_POSITIVE,
        "assignee": "alice.chen",
        "tags": ["phishing", "executive", "email"],
        "first_seen_offset": days(5) + hours(1),
        "detection_delay": minutes(18),
        "ack_delay": minutes(12),
        "resolution_delay": hours(6) + minutes(35),
        "summary": "Campaign confirmed. Sender blocked, URLs submitted for takedown, and affected recipients notified.",
        "description": "Multiple mailbox detections share the same sender infrastructure, payload URL pattern, and executive recipient group.",
        "ai": {"hypothesis": "Coordinated phishing campaign", "confidence": "High", "actions_completed": ["block sender", "quarantine mail", "notify recipients"]},
    },
    {
        "key": "dlp-source-code",
        "title": "Source code archive uploaded to personal cloud storage",
        "category": CaseCategory.DLP,
        "severity": CaseSeverity.HIGH,
        "confidence": CaseConfidence.HIGH,
        "impact": CaseImpact.HIGH,
        "priority": CasePriority.HIGH,
        "status": CaseStatus.IN_PROGRESS,
        "verdict": CaseVerdict.SUSPICIOUS,
        "assignee": "bob.li",
        "tags": ["dlp", "source-code", "cloud-storage"],
        "first_seen_offset": hours(9),
        "detection_delay": minutes(4),
        "ack_delay": minutes(18),
        "resolution_delay": None,
        "summary": "Legal hold request opened. Waiting for manager confirmation and endpoint collection.",
        "description": "DLP detected a compressed repository archive uploaded from a developer workstation to unsanctioned storage.",
        "ai": {"hypothesis": "Possible data exfiltration", "confidence": "Medium", "data_types": ["source code", "secrets candidate"]},
    },
    {
        "key": "waf-sql-injection",
        "title": "SQL injection attempts against customer portal",
        "category": CaseCategory.WAF,
        "severity": CaseSeverity.MEDIUM,
        "confidence": CaseConfidence.HIGH,
        "impact": CaseImpact.MEDIUM,
        "priority": CasePriority.MEDIUM,
        "status": CaseStatus.RESOLVED,
        "verdict": CaseVerdict.TRUE_POSITIVE,
        "assignee": "maya.singh",
        "tags": ["waf", "sql-injection", "portal"],
        "first_seen_offset": days(1) + hours(8),
        "detection_delay": minutes(2),
        "ack_delay": minutes(9),
        "resolution_delay": hours(1) + minutes(30),
        "summary": "WAF rule blocked all observed requests. Source ASN added to temporary block list.",
        "description": "WAF detected repeated SQL injection payloads against login and search endpoints.",
        "ai": {"hypothesis": "Automated SQL injection probing", "confidence": "High", "impact": "Blocked at WAF"},
    },
    {
        "key": "proxy-malware-download",
        "title": "Suspicious malware download over corporate proxy",
        "category": CaseCategory.PROXY,
        "severity": CaseSeverity.MEDIUM,
        "confidence": CaseConfidence.MEDIUM,
        "impact": CaseImpact.MEDIUM,
        "priority": CasePriority.MEDIUM,
        "status": CaseStatus.CLOSED,
        "verdict": CaseVerdict.FALSE_POSITIVE,
        "assignee": "alice.chen",
        "tags": ["proxy", "download", "false-positive"],
        "first_seen_offset": days(8),
        "detection_delay": minutes(16),
        "ack_delay": minutes(25),
        "resolution_delay": hours(2) + minutes(5),
        "summary": "Confirmed sanctioned red-team file retrieval. Knowledge updated for future suppression.",
        "description": "Proxy alert matched a malware test filename downloaded by a red-team workstation.",
        "ai": {"hypothesis": "Possible malware download", "confidence": "Low", "analyst_override": "Red-team activity"},
    },
    {
        "key": "ti-c2-domain",
        "title": "Threat intelligence match for C2 domain in DNS logs",
        "category": CaseCategory.TI,
        "severity": CaseSeverity.HIGH,
        "confidence": CaseConfidence.HIGH,
        "impact": CaseImpact.HIGH,
        "priority": CasePriority.HIGH,
        "status": CaseStatus.NEW,
        "verdict": CaseVerdict.SUSPICIOUS,
        "assignee": "bob.li",
        "tags": ["threat-intelligence", "c2", "dns"],
        "first_seen_offset": hours(3),
        "detection_delay": minutes(8),
        "ack_delay": None,
        "resolution_delay": None,
        "summary": "",
        "description": "Threat intelligence provider flagged a queried domain as likely command-and-control infrastructure.",
        "ai": {"hypothesis": "C2 beacon candidate", "confidence": "Medium", "needs": ["endpoint process tree", "DNS history"]},
    },
]

ARTIFACT_SPECS = [
    ("fin-wks-023.corp.example", ArtifactType.HOSTNAME, ArtifactRole.AFFECTED, ArtifactName.AFFECTED_HOST),
    ("finance.user@example.com", ArtifactType.USER_NAME, ArtifactRole.ACTOR, ArtifactName.SOURCE_USER),
    ("vssadmin.exe delete shadows /all /quiet", ArtifactType.COMMAND_LINE, ArtifactRole.RELATED, ArtifactName.PROCESS_COMMAND_LINE),
    ("C:\\Users\\Public\\README_RESTORE_FILES.txt", ArtifactType.FILE_PATH, ArtifactRole.RELATED, ArtifactName.FILE_PATH),
    ("44d88612fea8a8f36de82e1278abb02f", ArtifactType.HASH, ArtifactRole.RELATED, ArtifactName.FILE_HASH),
    ("185.199.110.153", ArtifactType.IP_ADDRESS, ArtifactRole.ACTOR, ArtifactName.SOURCE_IP),
    ("arn:aws:iam::111122223333:role/SecurityAudit", ArtifactType.RESOURCE, ArtifactRole.TARGET, ArtifactName.CLOUD_ROLE),
    ("d3f4c2a9.exfil-example.net", ArtifactType.HOSTNAME, ArtifactRole.RELATED, ArtifactName.DNS_QUERY_NAME),
    ("benefits-update@payroll-secure.example", ArtifactType.EMAIL_ADDRESS, ArtifactRole.ACTOR, ArtifactName.SENDER_EMAIL),
    ("https://login-m365-security.example/verify", ArtifactType.URL_STRING, ArtifactRole.RELATED, ArtifactName.PHISHING_URL),
    ("dev-wks-044.corp.example", ArtifactType.HOSTNAME, ArtifactRole.AFFECTED, ArtifactName.AFFECTED_HOST),
    ("repo-secrets-2026.zip", ArtifactType.FILE_NAME, ArtifactRole.RELATED, ArtifactName.FILE_NAME),
    ("customer-portal.example.com", ArtifactType.HOSTNAME, ArtifactRole.TARGET, ArtifactName.DESTINATION_HOST),
    ("203.0.113.45", ArtifactType.IP_ADDRESS, ArtifactRole.ACTOR, ArtifactName.SOURCE_IP),
    ("redteam-workstation-07", ArtifactType.HOSTNAME, ArtifactRole.RELATED, ArtifactName.HOSTNAME),
    ("c2-payment-check.example", ArtifactType.HOSTNAME, ArtifactRole.RELATED, ArtifactName.DOMAIN),
]


def ensure_users():
    users = {}
    for username, full_name in [
        ("alice.chen", "Alice Chen"),
        ("bob.li", "Bob Li"),
        ("maya.singh", "Maya Singh"),
        ("liam.ops", "Liam Ops"),
        ("automation", "ASP Automation"),
    ]:
        first_name, last_name = full_name.split(" ", 1)
        user, _created = User.objects.get_or_create(username=username)
        user.first_name = first_name
        user.last_name = last_name
        user.email = f"{username}@example.com"
        user.mobile_phone = "+86-138-0000-0000" if username != "automation" else ""
        user.set_password("mockpass")
        user.save()
        users[username] = user
    return users


def metric_text(spec):
    ttd = spec["detection_delay"]
    tta = spec["ack_delay"]
    ttr = spec["resolution_delay"]
    parts = [f"TTD={format_delta(ttd)}"]
    parts.append(f"TTA={format_delta(tta)}" if tta else "TTA=pending")
    parts.append(f"TTR={format_delta(ttr)}" if ttr else "TTR=pending")
    return ", ".join(parts)


def format_delta(value):
    total_minutes = int(value.total_seconds() // 60)
    days_part, remainder = divmod(total_minutes, 1440)
    hours_part, minutes_part = divmod(remainder, 60)
    chunks = []
    if days_part:
        chunks.append(f"{days_part}d")
    if hours_part:
        chunks.append(f"{hours_part}h")
    if minutes_part or not chunks:
        chunks.append(f"{minutes_part}m")
    return "".join(chunks)


def create_cases(users, batch_id):
    now = timezone.now()
    cases = {}
    current_batch_tag = batch_tag(batch_id)
    for index, spec in enumerate(CASE_SPECS, start=1):
        first_seen = now - spec["first_seen_offset"]
        detected_at = first_seen + spec["detection_delay"]
        acknowledged_at = detected_at + spec["ack_delay"] if spec["ack_delay"] else None
        closed_at = acknowledged_at + spec["resolution_delay"] if acknowledged_at and spec["resolution_delay"] else None
        case = Case.objects.create(
            title=f"{spec['title']} ({batch_id})",
            severity=spec["severity"],
            severity_ai=spec["severity"],
            confidence=spec["confidence"],
            confidence_ai=spec["confidence"],
            impact=spec["impact"],
            impact_ai=spec["impact"],
            priority=spec["priority"],
            priority_ai=spec["priority"],
            description=f"{spec['description']} Response metrics: {metric_text(spec)}.",
            category=spec["category"],
            tags=[MOCK_TAG, current_batch_tag, *spec["tags"]],
            status=spec["status"],
            verdict=spec["verdict"],
            verdict_ai=spec["verdict"] if spec["verdict"] != CaseVerdict.UNKNOWN else CaseVerdict.SUSPICIOUS,
            summary=spec["summary"],
            assignee=users[spec["assignee"]],
            acknowledged_time=acknowledged_at,
            closed_time=closed_at,
            correlation_uid=f"{MOCK_CORRELATION_PREFIX}{batch_id}-{index:02d}-{spec['key'].upper()}",
            investigation_report_ai_json=json.dumps(
                {
                    **spec["ai"],
                    "metrics": {
                        "ttd": format_delta(spec["detection_delay"]),
                        "tta": format_delta(spec["ack_delay"]) if spec["ack_delay"] else None,
                        "ttr": format_delta(spec["resolution_delay"]) if spec["resolution_delay"] else None,
                    },
                },
                ensure_ascii=False,
            ),
        )
        Case.objects.filter(pk=case.pk).update(created_at=detected_at, updated_at=closed_at or acknowledged_at or detected_at)
        case.refresh_from_db()
        cases[spec["key"]] = {"case": case, "first_seen": first_seen, "detected_at": detected_at}
    return cases


def create_artifacts():
    artifacts = {}
    for value, type_, role, name in ARTIFACT_SPECS:
        artifacts[value] = Artifact.objects.create(name=name, type=type_, role=role, value=value)
    return artifacts


def alert_payload(case, case_key, alert_index, title, severity, confidence, impact, disposition, action, product_category, analytic_type, first_seen, last_seen, tactic, technique):
    return {
        "case": case,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "impact": impact,
        "disposition": disposition,
        "action": action,
        "labels": [MOCK_TAG, "soc", case.category.lower(), severity.lower()],
        "desc": f"{title}. Detection includes telemetry correlation, entity context, and recommended triage actions.",
        "first_seen_time": first_seen,
        "last_seen_time": last_seen,
        "rule_id": f"MOCK-{case.category}-{alert_index:03d}",
        "rule_name": title,
        "correlation_uid": case.correlation_uid,
        "src_url": f"https://console.example.local/alerts/{case_key}/{alert_index:03d}",
        "source_uid": f"{MOCK_ALERT_SOURCE_PREFIX}{case.correlation_uid}-{case_key}-{alert_index:03d}",
        "data_sources": [product_category.lower(), "mock.telemetry"],
        "analytic_name": f"{title} Analytic",
        "analytic_type": analytic_type,
        "analytic_state": AlertAnalyticState.ACTIVE,
        "analytic_desc": "Mock analytic generated from realistic SOC detection logic.",
        "tactic": tactic,
        "technique": technique,
        "mitigation": "Validate scope, preserve evidence, and apply containment according to severity.",
        "product_category": product_category,
        "product_vendor": product_vendor(product_category),
        "product_name": product_name(product_category),
        "product_feature": product_feature(product_category),
        "policy_name": f"Mock Detection Policy {alert_index:03d}",
        "policy_type": policy_type(product_category),
        "policy_desc": "Policy tuned for enterprise SOC mock telemetry.",
        "risk_level": risk_level_from_severity(severity),
        "status": status_for_case(case.status),
        "status_detail": f"{MOCK_MARKER} Generated alert for {case.case_id}",
        "remediation": "Follow the playbook, confirm business context, and document analyst conclusion.",
        "unmapped": {"mock_case_key": case_key, "mock_alert_index": alert_index, "parser": "mock-importer"},
        "raw_data": {"event_id": f"mock-{case_key}-{alert_index:03d}", "case": case.case_id, "title": title},
    }


def create_alerts(cases, artifacts, batch_id):
    specs = [
        ("ransomware-finance", "Shadow copy deletion and mass file rename", Severity.CRITICAL, Confidence.HIGH, Impact.CRITICAL, Disposition.DETECTED, AlertAction.OBSERVED, ProductCategory.EDR, AlertAnalyticType.BEHAVIORAL, ["fin-wks-023.corp.example", "finance.user@example.com", "vssadmin.exe delete shadows /all /quiet", "44d88612fea8a8f36de82e1278abb02f"], "Impact", "T1490 - Inhibit System Recovery"),
        ("ransomware-finance", "Ransom note created in public user directory", Severity.HIGH, Confidence.HIGH, Impact.HIGH, Disposition.LOGGED, AlertAction.OBSERVED, ProductCategory.EDR, AlertAnalyticType.RULE, ["fin-wks-023.corp.example", "C:\\Users\\Public\\README_RESTORE_FILES.txt"], "Impact", "T1486 - Data Encrypted for Impact"),
        ("cloud-impossible-travel", "Impossible travel with MFA fatigue indicators", Severity.HIGH, Confidence.HIGH, Impact.HIGH, Disposition.ALERT, AlertAction.OBSERVED, ProductCategory.IAM, AlertAnalyticType.STATISTICAL, ["finance.user@example.com", "arn:aws:iam::111122223333:role/SecurityAudit", "185.199.110.153"], "Credential Access", "T1110 - Brute Force"),
        ("cloud-impossible-travel", "AWS IAM policy enumeration after suspicious login", Severity.MEDIUM, Confidence.MEDIUM, Impact.HIGH, Disposition.LOGGED, AlertAction.OBSERVED, ProductCategory.CLOUD, AlertAnalyticType.RULE, ["arn:aws:iam::111122223333:role/SecurityAudit"], "Discovery", "T1087 - Account Discovery"),
        ("dns-tunneling", "High entropy DNS TXT query burst", Severity.MEDIUM, Confidence.MEDIUM, Impact.MEDIUM, Disposition.LOGGED, AlertAction.OBSERVED, ProductCategory.NDR, AlertAnalyticType.RULE, ["d3f4c2a9.exfil-example.net", "fin-wks-023.corp.example"], "Command and Control", "T1071.004 - DNS"),
        ("executive-phishing", "Executive mailbox phishing link clicked", Severity.HIGH, Confidence.HIGH, Impact.MEDIUM, Disposition.QUARANTINED, AlertAction.DENIED, ProductCategory.EMAIL, AlertAnalyticType.KEYWORD_MATCH, ["benefits-update@payroll-secure.example", "https://login-m365-security.example/verify"], "Initial Access", "T1566.002 - Spearphishing Link"),
        ("executive-phishing", "Lookalike sender domain newly registered", Severity.MEDIUM, Confidence.MEDIUM, Impact.LOW, Disposition.TAGGED, AlertAction.OBSERVED, ProductCategory.EMAIL, AlertAnalyticType.FINGERPRINTING, ["benefits-update@payroll-secure.example"], "Resource Development", "T1583.001 - Domains"),
        ("dlp-source-code", "Repository archive uploaded to unsanctioned storage", Severity.HIGH, Confidence.HIGH, Impact.HIGH, Disposition.ALERT, AlertAction.OBSERVED, ProductCategory.DLP, AlertAnalyticType.EXACT_DATA_MATCH, ["dev-wks-044.corp.example", "repo-secrets-2026.zip"], "Exfiltration", "T1567.002 - Exfiltration to Cloud Storage"),
        ("waf-sql-injection", "SQL injection blocked at customer portal", Severity.MEDIUM, Confidence.HIGH, Impact.MEDIUM, Disposition.BLOCKED, AlertAction.DENIED, ProductCategory.WAF, AlertAnalyticType.REGULAR_EXPRESSIONS, ["customer-portal.example.com", "203.0.113.45"], "Initial Access", "T1190 - Exploit Public-Facing Application"),
        ("proxy-malware-download", "Malware test file downloaded via proxy", Severity.MEDIUM, Confidence.MEDIUM, Impact.MEDIUM, Disposition.ALERT, AlertAction.OBSERVED, ProductCategory.PROXY, AlertAnalyticType.KEYWORD_MATCH, ["redteam-workstation-07", "44d88612fea8a8f36de82e1278abb02f"], "Execution", "T1204.002 - Malicious File"),
        ("ti-c2-domain", "Threat intelligence C2 domain match", Severity.HIGH, Confidence.HIGH, Impact.HIGH, Disposition.ALERT, AlertAction.OBSERVED, ProductCategory.TI, AlertAnalyticType.RULE, ["c2-payment-check.example", "fin-wks-023.corp.example"], "Command and Control", "T1071 - Application Layer Protocol"),
    ]

    alerts = []
    case_alert_counts = {}
    for index, spec in enumerate(specs, start=1):
        case_key, title, severity, confidence, impact, disposition, action, product_category, analytic_type, artifact_values, tactic, technique = spec
        timeline = cases[case_key]
        case = timeline["case"]
        case_alert_counts[case_key] = case_alert_counts.get(case_key, 0) + 1
        case_alert_index = case_alert_counts[case_key]
        detection_window = timeline["detected_at"] - timeline["first_seen"]
        first_seen = timeline["first_seen"] + min(minutes((case_alert_index - 1) * 3), detection_window)
        last_seen = min(first_seen + minutes(35), timeline["detected_at"])
        alert = Alert.objects.create(
            **alert_payload(
                case,
                case_key,
                index,
                title,
                severity,
                confidence,
                impact,
                disposition,
                action,
                product_category,
                analytic_type,
                first_seen,
                last_seen,
                tactic,
                technique,
            )
        )
        alert.artifacts.set([artifacts[value] for value in artifact_values if value in artifacts])
        Alert.objects.filter(pk=alert.pk).update(created_at=timeline["detected_at"] + minutes(index), updated_at=timeline["detected_at"] + minutes(index))
        alert.refresh_from_db()
        alerts.append(alert)
    return alerts


def status_for_case(status):
    if status == CaseStatus.CLOSED:
        return AlertStatus.ARCHIVED
    if status == CaseStatus.RESOLVED:
        return AlertStatus.RESOLVED
    if status == CaseStatus.IN_PROGRESS:
        return AlertStatus.IN_PROGRESS
    if status == CaseStatus.ON_HOLD:
        return AlertStatus.SUPPRESSED
    return AlertStatus.NEW


def risk_level_from_severity(severity):
    return {
        Severity.CRITICAL: AlertRiskLevel.CRITICAL,
        Severity.HIGH: AlertRiskLevel.HIGH,
        Severity.MEDIUM: AlertRiskLevel.MEDIUM,
        Severity.LOW: AlertRiskLevel.LOW,
        Severity.INFORMATIONAL: AlertRiskLevel.INFO,
    }.get(severity, AlertRiskLevel.OTHER)


def product_vendor(category):
    return {
        ProductCategory.EDR: "CrowdStrike",
        ProductCategory.IAM: "Okta",
        ProductCategory.NDR: "Vectra",
        ProductCategory.EMAIL: "Proofpoint",
        ProductCategory.CLOUD: "AWS",
        ProductCategory.DLP: "Microsoft Purview",
        ProductCategory.WAF: "Cloudflare",
        ProductCategory.PROXY: "Zscaler",
        ProductCategory.TI: "AlienVaultOTX",
    }.get(category, "ASP Mock")


def product_name(category):
    return {
        ProductCategory.EDR: "Falcon",
        ProductCategory.IAM: "Workforce Identity",
        ProductCategory.NDR: "Cognito",
        ProductCategory.EMAIL: "TAP",
        ProductCategory.CLOUD: "CloudTrail",
        ProductCategory.DLP: "Purview DLP",
        ProductCategory.WAF: "WAF",
        ProductCategory.PROXY: "Internet Access",
        ProductCategory.TI: "OTX",
    }.get(category, "Mock Telemetry")


def product_feature(category):
    return {
        ProductCategory.EDR: "Process Monitoring",
        ProductCategory.IAM: "Sign-in Risk",
        ProductCategory.NDR: "DNS Analytics",
        ProductCategory.EMAIL: "Email Security",
        ProductCategory.CLOUD: "IAM Auditing",
        ProductCategory.DLP: "File Exfiltration",
        ProductCategory.WAF: "HTTP Firewall",
        ProductCategory.PROXY: "Web Proxy",
        ProductCategory.TI: "IOC Matching",
    }.get(category, "Detection")


def policy_type(category):
    if category in {ProductCategory.IAM, ProductCategory.CLOUD}:
        return AlertPolicyType.IDENTITY_POLICY
    if category in {ProductCategory.WAF, ProductCategory.PROXY}:
        return AlertPolicyType.ACCESS_CONTROL_POLICY
    if category == ProductCategory.DLP:
        return AlertPolicyType.RESOURCE_POLICY
    return AlertPolicyType.OTHER


def create_enrichment(content_object, name, type_, provider, value, desc, data, batch_id):
    parent_kwargs = {content_object._meta.model_name: content_object}
    return Enrichment.objects.create(
        **parent_kwargs,
        name=name,
        type=type_,
        provider=provider,
        uid=f"{MOCK_ENRICHMENT_UID_PREFIX}{batch_id}:{content_object._meta.model_name}:{provider}:{value}",
        value=value,
        desc=desc,
        data=data,
    )


def create_enrichments(cases, alerts, artifacts, batch_id):
    case_map = {key: item["case"] for key, item in cases.items()}
    enrichments = [
        create_enrichment(case_map["ransomware-finance"], "EDR host isolation status", EnrichmentType.REMEDIATION, EnrichmentProvider.CROWDSTRIKE_FALCON, "fin-wks-023 isolated", "Host isolation confirmed in EDR console.", {"isolated": True, "policy": "containment"}, batch_id),
        create_enrichment(case_map["cloud-impossible-travel"], "Okta user risk profile", EnrichmentType.IDENTITY, EnrichmentProvider.OKTA, "finance.user@example.com", "User shows recent impossible travel and high risk score.", {"risk_score": 87, "mfa_pushes": 9}, batch_id),
        create_enrichment(case_map["dns-tunneling"], "Passive DNS history", EnrichmentType.PASSIVE_DNS, EnrichmentProvider.SECURITYTRAILS, "exfil-example.net", "Domain registered recently with sparse passive DNS history.", {"first_seen_days": 3}, batch_id),
        create_enrichment(case_map["executive-phishing"], "Proofpoint campaign cluster", EnrichmentType.CORRELATION, EnrichmentProvider.PROOFPOINT, "exec-phish-campaign", "Mail security clustered related executive phishing messages.", {"messages": 18, "recipients": 12}, batch_id),
        create_enrichment(case_map["dlp-source-code"], "Source code sensitivity summary", EnrichmentType.OBSERVATION, EnrichmentProvider.MICROSOFT_GRAPH, "repo-secrets-2026.zip", "Archive includes repositories with possible credential material.", {"repos": 4, "secret_candidates": 11}, batch_id),
        create_enrichment(case_map["waf-sql-injection"], "WAF block summary", EnrichmentType.DETECTION, EnrichmentProvider.CLOUDFLARE, "customer portal SQLi", "Requests were blocked before reaching the origin.", {"blocked": 127, "source_asn": 64512}, batch_id),
        create_enrichment(case_map["ti-c2-domain"], "OTX pulse context", EnrichmentType.THREAT_INTELLIGENCE, EnrichmentProvider.ALIENVAULT_OTX, "c2-payment-check.example", "Domain appears in recent C2 pulse collections.", {"pulse_count": 4, "risk": "high"}, batch_id),
    ]

    for provider, value, desc in [
        (EnrichmentProvider.VIRUSTOTAL, "44d88612fea8a8f36de82e1278abb02f", "Hash has multiple malicious detections."),
        (EnrichmentProvider.ABUSEIPDB, "185.199.110.153", "Source IP has recent abuse reports."),
        (EnrichmentProvider.DOMAINTOOLS, "payroll-secure.example", "Domain was registered recently and uses privacy-protected WHOIS."),
    ]:
        enrichments.append(create_enrichment(alerts[0], f"{provider} alert enrichment", EnrichmentType.THREAT_INTELLIGENCE, provider, value, desc, {"confidence": "High"}, batch_id))

    for artifact_value, provider, type_, desc in [
        ("fin-wks-023.corp.example", EnrichmentProvider.INTERNAL_CMDB, EnrichmentType.CMDB, "Finance workstation owned by APAC finance team."),
        ("finance.user@example.com", EnrichmentProvider.MICROSOFT_ENTRA_ID, EnrichmentType.IDENTITY, "User is member of Finance and privileged approval groups."),
        ("c2-payment-check.example", EnrichmentProvider.ALIENVAULT_OTX, EnrichmentType.THREAT_INTELLIGENCE, "High-risk C2 infrastructure candidate."),
        ("customer-portal.example.com", EnrichmentProvider.INTERNAL_CMDB, EnrichmentType.ASSET, "Customer-facing portal with high business criticality."),
    ]:
        if artifact_value in artifacts:
            artifact = artifacts[artifact_value]
            enrichments.append(create_enrichment(artifact, f"{provider} artifact context", type_, provider, artifact.value, desc, {"artifact": artifact.artifact_id}, batch_id))
    return enrichments


def create_knowledge(cases, batch_id):
    case_map = {key: item["case"] for key, item in cases.items()}
    current_batch_tag = batch_tag(batch_id)
    return [
        Knowledge.objects.create(
            title="Ransomware endpoint containment checklist",
            body="# Ransomware endpoint containment\n\n1. Isolate the endpoint in EDR.\n2. Preserve disk and memory evidence.\n3. Reset affected credentials.\n4. Search for lateral movement indicators.\n5. Document recovery and closure summary.",
            source=KnowledgeSource.MANUAL,
            tags=[MOCK_TAG, current_batch_tag, "ransomware", "edr", "containment"],
        ),
        Knowledge.objects.create(
            title="Cloud identity impossible travel triage guide",
            body="# Impossible travel triage\n\nValidate geolocation, VPN usage, device fingerprint, MFA events, and privileged role activity. Escalate when impossible travel is followed by policy or role enumeration.",
            source=KnowledgeSource.MANUAL,
            tags=[MOCK_TAG, current_batch_tag, "identity", "cloud", "iam", "mfa"],
            expires_at=timezone.now() + days(180),
        ),
        Knowledge.objects.create(
            title="Executive phishing campaign response notes",
            body="# Executive phishing response\n\nCluster by sender domain, URL pattern, and recipient group. Preserve headers, quarantine related messages, and notify executive assistants.",
            source=KnowledgeSource.CASE,
            case=case_map["executive-phishing"],
            tags=[MOCK_TAG, current_batch_tag, "phishing", "executive", "knowledge-extraction"],
        ),
    ]


def create_playbooks(cases, users, batch_id):
    case_map = {key: item["case"] for key, item in cases.items()}
    specs = [
        (case_map["ransomware-finance"], PLAYBOOK_INVESTIGATION, users["automation"], "Generate final ransomware investigation summary.", PlaybookJobStatus.SUCCESS, "Investigation completed: active ransomware behavior confirmed."),
        (case_map["executive-phishing"], PLAYBOOK_KNOWLEDGE_EXTRACTION, users["alice.chen"], "Extract reusable phishing response knowledge.", PlaybookJobStatus.SUCCESS, "Knowledge created: Executive phishing campaign response notes."),
        (case_map["ti-c2-domain"], PLAYBOOK_TI_ENRICHMENT, users["bob.li"], "Enrich all case artifacts with threat intelligence.", PlaybookJobStatus.RUNNING, "Threat intelligence enrichment running for case artifacts."),
        (case_map["cloud-impossible-travel"], PLAYBOOK_CMDB_ENRICHMENT, users["bob.li"], "Lookup CMDB owner and cloud account context.", PlaybookJobStatus.PENDING, "Queued for CMDB lookup."),
        (case_map["proxy-malware-download"], PLAYBOOK_INVESTIGATION, users["automation"], "Review red-team false positive history.", PlaybookJobStatus.FAILED, "ValueError: Case has insufficient linked evidence for automated investigation."),
    ]
    playbooks = []
    for index, (case, name, user, user_input, status, remark) in enumerate(specs, start=1):
        playbooks.append(Playbook.objects.create(
            case=case,
            name=name,
            user=user,
            user_input=user_input,
            job_status=status,
            job_id=f"{MOCK_PLAYBOOK_JOB_PREFIX}{batch_id}-{index:03d}",
            remark=remark,
        ))
    return playbooks


def create_comments(cases, users, batch_id):
    case_map = {key: item["case"] for key, item in cases.items()}
    for key, author, body, mentions in [
        ("ransomware-finance", "alice.chen", f"{MOCK_MARKER} batch={batch_id} Endpoint isolated. Need credential reset confirmation from identity team.", ["bob.li"]),
        ("cloud-impossible-travel", "bob.li", f"{MOCK_MARKER} batch={batch_id} Waiting for user callback. MFA fatigue indicators need SIEM validation.", ["maya.singh"]),
        ("dns-tunneling", "maya.singh", f"{MOCK_MARKER} batch={batch_id} DNS owner says this host runs a legacy telemetry agent; keeping case on hold.", []),
        ("executive-phishing", "alice.chen", f"{MOCK_MARKER} batch={batch_id} Campaign closed. Knowledge extracted for future executive phishing waves.", []),
        ("dlp-source-code", "bob.li", f"{MOCK_MARKER} batch={batch_id} Manager review requested before containment decision.", ["alice.chen"]),
    ]:
        create_record_comment(
            author=users[author],
            content_object=case_map[key],
            body=body,
            mentions=[users[name] for name in mentions],
        )


def exercise_audit_examples(cases, alerts, artifacts, batch_id):
    case = cases["cloud-impossible-travel"]["case"]
    case.summary = "Initial identity triage queued; waiting for user verification and MFA reset confirmation."
    case.save(update_fields=["summary", "updated_at"])
    alerts[2].status_detail = "Analyst confirmed suspicious sign-in context and requested session revocation."
    alerts[2].save(update_fields=["status_detail", "updated_at"])

    if "185.199.110.153" in artifacts:
        alerts[0].artifacts.add(artifacts["185.199.110.153"])
    if "44d88612fea8a8f36de82e1278abb02f" in artifacts:
        alerts[0].artifacts.remove(artifacts["44d88612fea8a8f36de82e1278abb02f"])

    transient = create_enrichment(
        cases["ransomware-finance"]["case"],
        "Transient deleted enrichment demo",
        EnrichmentType.OBSERVATION,
        EnrichmentProvider.INTERNAL_SIRP,
        f"deleted-demo-{batch_id}",
        "This enrichment is created and deleted by the mock importer to demonstrate deleted relationship audit logs.",
        {"demo": "deleted relationship event"},
        batch_id,
    )
    transient.delete()


def run():
    batch_id = new_batch_id()
    users = ensure_users()
    with audit_actor(users["automation"]):
        cases = create_cases(users, batch_id)
        artifacts = create_artifacts()
        alerts = create_alerts(cases, artifacts, batch_id)
        enrichments = create_enrichments(cases, alerts, artifacts, batch_id)
        knowledge_records = create_knowledge(cases, batch_id)
        playbooks = create_playbooks(cases, users, batch_id)
        create_comments(cases, users, batch_id)
        exercise_audit_examples(cases, alerts, artifacts, batch_id)
    print(
        f"Imported mock batch {batch_id}: "
        f"{len(cases)} cases, "
        f"{len(alerts)} alerts, "
        f"{len(artifacts)} artifacts, "
        f"{len(enrichments)} enrichments, "
        f"{len(knowledge_records)} knowledge records, "
        f"{len(playbooks)} playbooks."
    )
