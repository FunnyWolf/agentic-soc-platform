from PLUGINS.Mock.SIRP.mock_alert import *
from PLUGINS.Mock.SIRP.mock_enrichment import *
from PLUGINS.Mock.SIRP.mock_ticket import *
from PLUGINS.SIRP.sirpcoremodel import Severity, Impact, Confidence, ProductCategory, CasePriority, CaseStatus, CaseVerdict, CaseModel

# === Case 1: Phishing Email Attack (100% Coverage) ===
case1_phishing = CaseModel(
    title="Phishing Campaign Detected - 'Urgent Payroll Update'",
    severity=Severity.HIGH,
    impact=Impact.MEDIUM,
    priority=CasePriority.HIGH,
    confidence=Confidence.HIGH,
    description="A targeted phishing campaign was identified. The email lured users to a fake login page to harvest credentials and deployed malware via an attachment.",
    category=ProductCategory.EMAIL,
    tags=["phishing", "credential-harvesting", "malware-delivery", "FIN-department"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=now,
    comment="L1 Analyst: Confirmed phishing. Escalating to L2 for impact analysis and remediation tracking.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-PHISH-XYZ-123",
    severity_ai=Severity.HIGH,
    confidence_ai=Confidence.HIGH,
    tickets=[ticket_jira],
    enrichments=[enrichment_business],
    alerts=[alert_user_reported_phishing, alert_malware_blocked]
)

# === Case 2: Endpoint Lateral Movement (100% Coverage) ===
case2_lateral_movement = CaseModel(
    title="Lateral Movement Detected via PsExec from DC01 to WS-FINANCE-05",
    severity=Severity.CRITICAL,
    impact=Impact.HIGH,
    priority=CasePriority.CRITICAL,
    confidence=Confidence.HIGH,
    description="An attacker, having compromised the Domain Controller 'DC01', is attempting to move laterally to a high-value workstation 'WS-FINANCE-05' in the Finance department using PsExec.",
    category=ProductCategory.EDR,
    tags=["lateral-movement", "psexec", "golden-ticket", "domain-compromise"],
    status=CaseStatus.RESOLVED,
    acknowledged_time=past_5m,
    comment="Incident Response Complete. IOCs have been added to blocklists. Awaiting final report.",
    closed_time=now,
    verdict=CaseVerdict.TRUE_POSITIVE,
    summary="Attacker compromised DC01 and moved to WS-FINANCE-05. Both hosts have been isolated and are pending reimaging. All domain admin credentials have been rotated.",
    correlation_uid="CORR-LAT-MOV-456",

    severity_ai=Severity.CRITICAL,
    confidence_ai=Confidence.HIGH,

    tickets=[ticket_servicenow],
    alerts=[alert_psexec_lateral, alert_credential_dumping]
)

# === Case 3: DNS Tunneling C2 (100% Coverage) ===
case3_dns_tunnel = CaseModel(
    title="Suspected DNS Tunneling for C2 Communication from WS-MARKETING-12",
    severity=Severity.MEDIUM,
    impact=Impact.LOW,
    priority=CasePriority.MEDIUM,
    confidence=Confidence.HIGH,
    description="An endpoint 'WS-MARKETING-12' is exhibiting DNS query patterns indicative of DNS tunneling, likely for command-and-control (C2) communication. This is a low-and-slow exfiltration or C2 method.",
    category=ProductCategory.NDR,
    tags=["dns-tunneling", "c2", "ndr", "exfiltration"],
    status=CaseStatus.ON_HOLD,
    acknowledged_time=now,
    comment="Awaiting more data. Placed host in a monitoring group. No immediate action taken to avoid tipping off the attacker.",
    closed_time=None,
    verdict=CaseVerdict.SUSPICIOUS,
    summary="",
    correlation_uid="CORR-DNS-TUN-789",
    severity_ai=Severity.MEDIUM,
    confidence_ai=Confidence.MEDIUM,
    tickets=[],
    enrichments=[],
    alerts=[alert_dns_tunnel_volume, alert_dns_long_query]
)

# === Case 4: SSH Brute Force Attack ===
case4_brute_force = CaseModel(
    title="SSH Brute Force Attack on SQL Server Database",
    severity=Severity.HIGH,
    impact=Impact.MEDIUM,
    priority=CasePriority.HIGH,
    confidence=Confidence.HIGH,
    description="An external attacker is performing a coordinated SSH brute force attack against the production SQL database server. Multiple failed login attempts detected from a known malicious IP.",
    category=ProductCategory.OT,
    tags=["brute-force", "ssh", "database", "credential-access"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=past_1d_18h,
    comment="Attack blocked by firewall rules. Monitoring enabled. User credentials reset as precaution.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-BRUTE-001",
    severity_ai=Severity.HIGH,
    confidence_ai=Confidence.HIGH,
    tickets=[ticket_jira],
    alerts=[alert_brute_force_ssh]
)

# === Case 5: Ransomware Detection and Response ===
case5_ransomware = CaseModel(
    title="Ransomware Execution Detected - Immediate Containment",
    severity=Severity.CRITICAL,
    impact=Impact.HIGH,
    priority=CasePriority.CRITICAL,
    confidence=Confidence.HIGH,
    description="A ransomware malware has been executed on a workstation. File encryption behaviors detected. Immediate isolation and containment actions initiated.",
    category=ProductCategory.EDR,
    tags=["ransomware", "malware", "encryption", "incident-response"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=past_2d_6h,
    comment="Endpoint isolated from network. Forensic imaging in progress. Backup restore plan initiated.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-RANSOMWARE-001",
    severity_ai=Severity.CRITICAL,
    confidence_ai=Confidence.HIGH,
    tickets=[ticket_pagerduty],
    alerts=[alert_malware_execution]
)

# === Case 6: Unauthorized Access and Data Theft ===
case6_unauthorized_access = CaseModel(
    title="Unauthorized Access to Confidential Data - Insider Threat Investigation",
    severity=Severity.MEDIUM,
    impact=Impact.MEDIUM,
    priority=CasePriority.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="User 'sarah.johnson' from Sales department accessed restricted executive confidential files outside of business hours. Potential insider threat or compromised account.",
    category=ProductCategory.IAM,
    tags=["insider-threat", "unauthorized-access", "data-theft", "user-behavior"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=past_3d_12h,
    comment="User management notified. Account under enhanced monitoring. Behavioral analysis in progress.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-UNAUTH-002",
    severity_ai=Severity.MEDIUM,
    confidence_ai=Confidence.MEDIUM,
    tickets=[],
    alerts=[alert_unauthorized_access]
)

# === Case 7: Data Exfiltration via C2 ===
case7_data_exfil = CaseModel(
    title="Suspected Data Exfiltration via C2 Channel",
    severity=Severity.CRITICAL,
    impact=Impact.CRITICAL,
    priority=CasePriority.CRITICAL,
    confidence=Confidence.HIGH,
    description="A server is transferring large volumes of sensitive data to an external suspicious domain. Pattern matches known C2 exfiltration techniques.",
    category=ProductCategory.DLP,
    tags=["data-exfiltration", "c2", "advanced-threat", "incident-response"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=past_4d_20h,
    comment="Server isolated. Network traffic capture in progress. Law enforcement notified.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-EXFIL-003",
    severity_ai=Severity.CRITICAL,
    confidence_ai=Confidence.HIGH,
    tickets=[ticket_servicenow],
    alerts=[alert_data_exfiltration]
)

# === Case 8: Email-based Attack Campaign ===
case8_email_campaign = CaseModel(
    title="Malicious Email Campaign with Office Macro Malware",
    severity=Severity.HIGH,
    impact=Impact.MEDIUM,
    priority=CasePriority.HIGH,
    confidence=Confidence.HIGH,
    description="A coordinated email campaign distributing documents with malicious macros. Multiple recipients targeted. Gateway quarantine prevented infections.",
    category=ProductCategory.EMAIL,
    tags=["phishing", "malware", "macro", "email-campaign"],
    status=CaseStatus.RESOLVED,
    acknowledged_time=past_5d_8h,
    comment="All emails quarantined. Sender domain blacklisted. User training scheduled.",
    closed_time=now,
    verdict=CaseVerdict.TRUE_POSITIVE,
    summary="Email campaign was successfully detected and quarantined before any endpoints were compromised.",
    correlation_uid="CORR-MACRO-004",

    severity_ai=Severity.HIGH,
    confidence_ai=Confidence.HIGH,

    tickets=[ticket_jira],
    alerts=[alert_malicious_email_attachment]
)

# === Case 9: Privilege Escalation Attack ===
case9_priv_esc = CaseModel(
    title="Privilege Escalation Attack via UAC Bypass",
    severity=Severity.CRITICAL,
    impact=Impact.HIGH,
    priority=CasePriority.CRITICAL,
    confidence=Confidence.HIGH,
    description="An attacker exploited a known UAC bypass vulnerability to escalate from user context to SYSTEM privileges. Potential for full system compromise.",
    category=ProductCategory.EDR,
    tags=["privilege-escalation", "windows", "exploit", "uac-bypass"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=past_6d_15h,
    comment="Endpoint isolated. Vulnerability patching in progress. Post-exploitation analysis ongoing.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-PE-005",

    severity_ai=Severity.CRITICAL,
    confidence_ai=Confidence.HIGH,

    tickets=[ticket_pagerduty],
    alerts=[alert_privilege_escalation]
)

# === Case 10: Cloud Security Misconfiguration ===
case10_cloud_misconfig = CaseModel(
    title="S3 Bucket Exposed to Internet - Customer Data at Risk",
    severity=Severity.CRITICAL,
    impact=Impact.CRITICAL,
    priority=CasePriority.CRITICAL,
    confidence=Confidence.HIGH,
    description="A production AWS S3 bucket containing customer PII was exposed to public read access. Potentially millions of records affected.",
    category=ProductCategory.CLOUD,
    tags=["cloud-security", "aws", "data-exposure", "compliance"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=past_7d,
    comment="Bucket policy reverted. Data breach notification team activated. Forensic analysis of modification initiated.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-CLOUD-006",

    severity_ai=Severity.CRITICAL,
    confidence_ai=Confidence.HIGH,

    tickets=[ticket_servicenow],
    alerts=[alert_cloud_config_change]
)

# === Case 11: Brute Force SSH Attack (From SIEM Scenario) ===
case11_brute_force = CaseModel(
    title="Brute Force Attack: Multiple Failed Login Attempts Followed by Successful Compromise",
    severity=Severity.CRITICAL,
    impact=Impact.HIGH,
    priority=CasePriority.CRITICAL,
    confidence=Confidence.HIGH,
    description="External attacker from China (IP: 45.95.11.22) conducted a brute force attack against production web server admin account. After 7 failed attempts, attacker successfully compromised the admin account.",
    category=ProductCategory.SIEM,
    tags=["brute-force", "ssh", "credential-attack", "account-compromise", "china", "high-risk"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=past_1h,
    comment="L2 Analyst: Admin account is confirmed compromised. Immediate password reset, session termination, and command audit in progress. Source IP blocked at firewall.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-BRUTE-FORCE-001",

    severity_ai=Severity.CRITICAL,
    confidence_ai=Confidence.HIGH,
    tickets=[ticket_pagerduty],
    enrichments=[enrichment_business],
    alerts=[alert_brute_force_siem]
)

# === Case 12: SQL Injection Web Attack (From SIEM Scenario) ===
case12_sql_injection = CaseModel(
    title="SQL Injection Attack: Automated Scanner Detected and Blocked by WAF",
    severity=Severity.HIGH,
    impact=Impact.MEDIUM,
    priority=CasePriority.HIGH,
    confidence=Confidence.HIGH,
    description="Web Application Firewall detected SQL injection attack from Russia using automated sqlmap tool. Attacker attempted multiple SQL injection vectors against the user API endpoint. All attacks were successfully blocked.",
    category=ProductCategory.WAF,
    tags=["sql-injection", "web-attack", "waf", "automated-scanner", "owasp-top-10"],
    status=CaseStatus.RESOLVED,
    acknowledged_time=past_30m,
    comment="L3 Security Engineer: Attack was fully contained by WAF rules. No database compromise detected. Recommended code review to identify and fix potential SQL injection vulnerabilities.",
    closed_time=now,
    verdict=CaseVerdict.TRUE_POSITIVE,
    summary="SQL injection attack was detected and blocked by WAF. No application or database compromise occurred. Attacker IP has been blocked and monitoring is ongoing.",
    correlation_uid="CORR-SQL-INJ-001",

    severity_ai=Severity.HIGH,
    confidence_ai=Confidence.HIGH,

    tickets=[ticket_jira],
    enrichments=[enrichment_urlhaus_malware],
    alerts=[alert_sql_injection_siem]
)

# === Case 13: Active Ransomware Encryption (From SIEM Scenario) ===
case13_ransomware = CaseModel(
    title="CRITICAL: Active Ransomware Execution on Production Database Server",
    severity=Severity.CRITICAL,
    impact=Impact.CRITICAL,
    priority=CasePriority.CRITICAL,
    confidence=Confidence.HIGH,
    description="CRITICAL INCIDENT: Ransomware malware detected executing on production database server 'srv-db-master' with three confirmed attack indicators: 1) Shadow Copy deletion via vssadmin.exe 2) Bulk file encryption (20+ files renamed to .encrypted) 3) Ransom note creation. Immediate response required.",
    category=ProductCategory.EDR,
    tags=["ransomware", "file-encryption", "critical-incident", "active-threat", "recovery-required"],
    status=CaseStatus.IN_PROGRESS,
    acknowledged_time=past_2h,
    comment="INCIDENT COMMANDER: All-hands-on-deck response initiated. Host isolated. Crisis management team assembled. Legal/Law Enforcement notifications pending. Do NOT negotiate with attacker. Do NOT shutdown infected system. Prepare for potential multi-day recovery.",
    closed_time=None,
    verdict=None,
    summary="",
    correlation_uid="CORR-RANSOMWARE-ACTIVE-001",

    severity_ai=Severity.CRITICAL,
    confidence_ai=Confidence.HIGH,
    tickets=[ticket_servicenow, ticket_pagerduty],
    enrichments=[enrichment_carbonblack_execution],
    alerts=[alert_ransomware_siem]
)
