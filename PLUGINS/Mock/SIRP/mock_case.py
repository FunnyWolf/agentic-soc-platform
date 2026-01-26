import json
import random
import string
from datetime import datetime, timedelta, timezone

from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpmodel import (
    CaseModel, AlertModel, ArtifactModel, EnrichmentModel, TicketModel, TicketStatus,
    ArtifactType, ArtifactRole, ArtifactReputationScore, TicketType, Severity, ImpactLevel, Disposition, AlertAction,
    Confidence, AlertAnalyticType, AlertAnalyticState, ProductCategory, AlertRiskLevel, AlertStatus, CaseStatus,
    CasePriority, CaseVerdict, AlertPolicyType
)

now = datetime.now(timezone.utc)
past_5m = now - timedelta(minutes=5)
past_10m = now - timedelta(minutes=10)
past_15m = now - timedelta(minutes=15)
past_30m = now - timedelta(minutes=30)
past_1h = now - timedelta(hours=1)
past_2h = now - timedelta(hours=2)
past_3h = now - timedelta(hours=3)
past_6h = now - timedelta(hours=6)
past_12h = now - timedelta(hours=12)
past_24h = now - timedelta(hours=24)
past_2d = now - timedelta(days=2)
past_3d = now - timedelta(days=3)
past_7d = now - timedelta(days=7)


def gen_hash(length=64):
    return ''.join(random.choices(string.hexdigits[:16], k=length))


def gen_uuid():
    return f"{gen_hash(8)}-{gen_hash(4)}-{gen_hash(4)}-{gen_hash(4)}-{gen_hash(12)}"


def gen_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"


# --- Reusable Enrichment Snippets ---
enrichment_otx_evil_domain = EnrichmentModel(
    name="OTX Pulse for evil-domain.com",
    type="Threat Intelligence",
    provider="OTX",
    value="evil-domain.com",
    src_url="https://otx.alienvault.com/indicator/domain/evil-domain.com",
    desc="This domain is associated with the 'Gootkit' malware family.",
    data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
)

enrichment_virustotal = EnrichmentModel(
    name="VirusTotal Report for Hash 'a1b2c3d4...'",
    type="Threat Intelligence",
    provider="VirusTotal",
    value="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    src_url="https://www.virustotal.com/gui/file/a1b2c3d4e5f6.../detection",
    desc="72/75 vendors flagged this as malicious 'Trojan.Generic'.",
    data=json.dumps({"scan_id": "a1b2c3d4e5f6-1678886400", "positives": 72, "total": 75})
)
enrichment_business = EnrichmentModel(
    name="Affected Business Unit", type="Asset Information", provider="CMDB",
    value="Finance Department", desc="Internal CMDB Information: High-value target.",
    data=json.dumps({"scan_id": "a1b2c3d4e5f6-1678886400", "positives": 72, "total": 75})
)
enrichment_otx_8888 = EnrichmentModel(
    name="OTX Pulse for 8.8.8.8",
    type="Threat Intelligence",
    provider="OTX",
    value="8.8.8.8",
    src_url="https://otx.alienvault.com/indicator/domain/8.8.8.8",
    desc="This domain is associated with the 'Gootkit' malware family.",
    data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
)

enrichment_greynoise_scanner = EnrichmentModel(
    name="GreyNoise Report for 185.220.101.45",
    type="Threat Intelligence",
    provider="GreyNoise",
    value="185.220.101.45",
    src_url="https://www.greynoise.io/viz/ip/185.220.101.45",
    desc="Known mass-scanner. Classification: malicious. Last seen scanning 2 hours ago.",
    data=json.dumps({"classification": "malicious", "tags": ["SSH Bruteforce", "Mass Scanner"], "last_seen": "2h"})
)

enrichment_abuseipdb_ransomware = EnrichmentModel(
    name="AbuseIPDB Report for 103.95.196.78",
    type="Threat Intelligence",
    provider="AbuseIPDB",
    value="103.95.196.78",
    src_url="https://www.abuseipdb.com/check/103.95.196.78",
    desc="Abuse confidence score: 98%. Associated with ransomware C2 infrastructure.",
    data=json.dumps({"confidence_score": 98, "reports": 156, "categories": ["ransomware", "c2"]})
)

enrichment_urlhaus_malware = EnrichmentModel(
    name="URLhaus Report for malicious payload",
    type="Threat Intelligence",
    provider="URLhaus",
    value="http://malicious-payload-server.ru/payload.exe",
    src_url="https://urlhaus.abuse.ch/url/12345678/",
    desc="Known malware distribution URL. Payload: Emotet. Status: Online.",
    data=json.dumps({"threat": "Emotet", "status": "online", "first_seen": "2024-01-15"})
)

enrichment_shodan_exposed_rdp = EnrichmentModel(
    name="Shodan Scan for exposed RDP",
    type="Asset Information",
    provider="Shodan",
    value="203.0.113.50",
    src_url="https://www.shodan.io/host/203.0.113.50",
    desc="Exposed RDP service on port 3389. No encryption. Vulnerable to BlueKeep (CVE-2019-0708).",
    data=json.dumps({"ports": [3389], "vulns": ["CVE-2019-0708"], "org": "Example Corp"})
)

enrichment_whois_domain = EnrichmentModel(
    name="WHOIS for cryptominer-pool.xyz",
    type="Domain Intelligence",
    provider="WHOIS",
    value="cryptominer-pool.xyz",
    src_url="https://whois.domaintools.com/cryptominer-pool.xyz",
    desc="Registered 3 days ago. Registrar: NameCheap. Privacy protection enabled.",
    data=json.dumps({"created": "2024-01-18", "registrar": "NameCheap", "privacy": True})
)

enrichment_geoip_russia = EnrichmentModel(
    name="GeoIP Location for 185.220.101.45",
    type="Geolocation",
    provider="MaxMind GeoIP",
    value="185.220.101.45",
    desc="Location: Moscow, Russia. ASN: AS12345 (SuspiciousHosting LLC)",
    data=json.dumps({"country": "RU", "city": "Moscow", "asn": "AS12345", "org": "SuspiciousHosting LLC"})
)

enrichment_virustotal_cryptominer = EnrichmentModel(
    name="VirusTotal Report for cryptominer binary",
    type="Threat Intelligence",
    provider="VirusTotal",
    value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    src_url="https://www.virustotal.com/gui/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    desc="68/72 vendors flagged this as 'CoinMiner.Generic'. XMRig variant detected.",
    data=json.dumps({"scan_id": "e3b0c442-1678886400", "positives": 68, "total": 72, "malware_family": "XMRig"})
)

enrichment_crowdstrike_ioc = EnrichmentModel(
    name="CrowdStrike Threat Intel for Lazarus Group",
    type="Threat Intelligence",
    provider="CrowdStrike",
    value="Lazarus Group",
    desc="APT38/Lazarus Group TTPs detected. Known for supply chain attacks and ransomware.",
    data=json.dumps({"apt_group": "Lazarus", "aka": ["APT38", "Hidden Cobra"], "motivation": "Financial"})
)

enrichment_okta_user = EnrichmentModel(
    name="Okta User Profile for compromised account",
    type="Identity Information",
    provider="Okta",
    value="bob.contractor@example.com",
    desc="Contractor account. Department: IT. Privileged access to AWS console.",
    data=json.dumps({"department": "IT", "role": "contractor", "privileged": True, "mfa_enabled": False})
)

enrichment_aws_s3_public = EnrichmentModel(
    name="AWS S3 Bucket Misconfiguration",
    type="Cloud Security",
    provider="AWS Security Hub",
    value="s3://example-customer-data-prod",
    desc="Public read access enabled. Contains 45,000 files including PII.",
    data=json.dumps({"public_access": True, "file_count": 45000, "contains_pii": True})
)

enrichment_cve_detail = EnrichmentModel(
    name="CVE-2021-44228 (Log4Shell) Details",
    type="Vulnerability Intelligence",
    provider="NVD",
    value="CVE-2021-44228",
    src_url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    desc="CVSS Score: 10.0 (Critical). Remote code execution in Log4j. Actively exploited in the wild.",
    data=json.dumps({"cvss_score": 10.0, "severity": "CRITICAL", "exploited": True})
)

ticket_jira = TicketModel(
    status=TicketStatus.IN_PROGRESS,
    type=TicketType.JIRA,
    title='[Security] Investigate Phishing Campaign SEC-1234',
    uid='SEC-1234',
    src_url='https://jira.example.com/browse/SEC-1234'
)

ticket_servicenow = TicketModel(
    status=TicketStatus.RESOLVED,
    type=TicketType.SERVICENOW,
    title='CRITICAL: Active Lateral Movement Detected',
    uid='INC001002',
    src_url='https://servicenow.example.com/nav_to.do?uri=incident.do?sys_id=INC001002'
)

ticket_pagerduty = TicketModel(
    status=TicketStatus.NOTIFIED,
    type=TicketType.PAGERDUTY,
    title='P1: Ransomware Encryption Activity Detected',
    uid='PD-INC-789456',
    src_url='https://example.pagerduty.com/incidents/PD-INC-789456'
)

ticket_slack = TicketModel(
    status=TicketStatus.NEW,
    type=TicketType.SLACK,
    title='Security Alert: Suspicious Cloud Activity',
    uid='SLACK-2024-001',
    src_url='https://example.slack.com/archives/C01234/p1674567890123456'
)

# --- Reusable Artifacts ---
artifact_evil_email = ArtifactModel(
    name="no-reply@evil-domain.com",
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="no-reply@evil-domain.com",
    reputation_provider="Internal Blocklist",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_otx_evil_domain]
)
artifact_fake_url = ArtifactModel(
    name="http://fake-payroll-login.com",
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="http://fake-payroll-login.com",
    reputation_score=ArtifactReputationScore.SUSPICIOUS_RISKY
)
artifact_malware_file = ArtifactModel(
    name="payroll_update.zip",
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="payroll_update.zip"
)
artifact_malware_hash = ArtifactModel(
    name="a1b2c3d4e5f6...",
    type=ArtifactType.HASH,
    role=ArtifactRole.RELATED,
    value="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    reputation_provider="VirusTotal",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_virustotal]
)
artifact_psexesvc = ArtifactModel(
    name="PSEXESVC.exe",
    type=ArtifactType.PROCESS_NAME,
    role=ArtifactRole.RELATED,
    value="PSEXESVC.exe",
    owner="System"
)
artifact_dc01 = ArtifactModel(
    name="DC01",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.ACTOR,
    value="DC01",
)
artifact_lsass = ArtifactModel(
    name="lsass.exe",
    type=ArtifactType.PROCESS_NAME,
    role=ArtifactRole.TARGET,
    value="lsass.exe",
    owner="System"
)
artifact_mimikatz = ArtifactModel(
    name="mimikatz.exe",
    type=ArtifactType.PROCESS_NAME,
    role=ArtifactRole.ACTOR,
    value="mimikatz.exe",
)
artifact_internal_ip = ArtifactModel(
    name="10.1.1.5",
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="10.1.1.5",
    owner="Workstation-Pool-DHCP"
)
artifact_c2_domain = ArtifactModel(
    name="c2.bad-actor-infra.net",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.RELATED,
    value="c2.bad-actor-infra.net",
    reputation_score=ArtifactReputationScore.SUSPICIOUS_RISKY
)
artifact_dns_port = ArtifactModel(
    name="UDP-53",
    type=ArtifactType.PORT,
    role=ArtifactRole.RELATED,
    value="53",
)
artifact_google_dns = ArtifactModel(
    name="8.8.8.8",
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.RELATED,
    value="8.8.8.8",
    enrichments=[enrichment_otx_8888]
)

artifact_ransomware_ip = ArtifactModel(
    name="103.95.196.78",
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="103.95.196.78",
    reputation_provider="AbuseIPDB",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_abuseipdb_ransomware, enrichment_geoip_russia]
)

artifact_ransom_note = ArtifactModel(
    name="README_DECRYPT.txt",
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="README_DECRYPT.txt"
)

artifact_encrypted_file = ArtifactModel(
    name="financial_report_Q4.xlsx.locked",
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="C:\\Users\\john.smith\\Documents\\financial_report_Q4.xlsx.locked"
)

artifact_ransomware_hash = ArtifactModel(
    name="Ransomware Binary Hash",
    type=ArtifactType.HASH,
    role=ArtifactRole.ACTOR,
    value="5f4dcc3b5aa765d61d8327deb882cf99b4c2d6e6e6b4e6f6e6e6e6e6e6e6e6e6",
    reputation_provider="VirusTotal",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_virustotal]
)

artifact_cryptominer_binary = ArtifactModel(
    name="svchost.exe",
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.ACTOR,
    value="C:\\Windows\\Temp\\svchost.exe",
    enrichments=[enrichment_virustotal_cryptominer]
)

artifact_cryptominer_hash = ArtifactModel(
    name="Cryptominer Hash",
    type=ArtifactType.HASH,
    role=ArtifactRole.ACTOR,
    value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    reputation_provider="VirusTotal",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_virustotal_cryptominer]
)

artifact_mining_pool = ArtifactModel(
    name="cryptominer-pool.xyz",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.RELATED,
    value="cryptominer-pool.xyz",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_whois_domain]
)

artifact_insider_user = ArtifactModel(
    name="bob.contractor@example.com",
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="bob.contractor@example.com",
    owner="IT Department",
    enrichments=[enrichment_okta_user]
)

artifact_s3_bucket = ArtifactModel(
    name="s3://example-customer-data-prod",
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.TARGET,
    value="s3://example-customer-data-prod",
    enrichments=[enrichment_aws_s3_public]
)

artifact_exfil_destination = ArtifactModel(
    name="185.220.101.45",
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.RELATED,
    value="185.220.101.45",
    reputation_provider="GreyNoise",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_greynoise_scanner, enrichment_geoip_russia]
)

artifact_log4j_vuln = ArtifactModel(
    name="CVE-2021-44228",
    type=ArtifactType.CVE,
    role=ArtifactRole.RELATED,
    value="CVE-2021-44228",
    enrichments=[enrichment_cve_detail]
)

artifact_exploit_url = ArtifactModel(
    name="http://malicious-payload-server.ru/payload.exe",
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="http://malicious-payload-server.ru/payload.exe",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_urlhaus_malware]
)

artifact_vulnerable_server = ArtifactModel(
    name="WEB-SERVER-01",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="WEB-SERVER-01"
)

# --- Reusable Alerts ---
alert_user_reported_phishing = AlertModel(
    title="User Reported Phishing Email via Outlook Plugin",
    severity=Severity.MEDIUM,
    impact=ImpactLevel.MEDIUM,
    disposition=Disposition.ALLOWED,
    action=AlertAction.OBSERVED,
    confidence=Confidence.HIGH,
    uid="ALERT-USER-001",
    labels=["user-reported", "phishing"],
    desc="User 'john.doe' reported a suspicious email with subject 'Urgent Payroll Update'.",
    modified_time=now,
    first_seen_time=past_10m,
    last_seen_time=past_10m,
    rule_id="USER-REPORT-01",
    rule_name="User Reported Phishing",
    correlation_uid="CORR-PHISH-XYZ-123",
    count=1,
    src_url="https://exchange.example.com/messages/msg-id-12345",
    source_uid="MSG-ID-12345",
    data_sources=["MS Exchange", "Outlook Plugin"],
    analytic_name="Phishing Report Plugin",
    analytic_type=AlertAnalyticType.TAGGING,
    analytic_state=AlertAnalyticState.ACTIVE,
    analytic_desc="Identifies emails reported by users.",
    tactic="Reconnaissance",
    technique="T1598.003",
    sub_technique="",
    mitigation="User Training, Email Filtering",
    product_category=ProductCategory.EMAIL,
    product_vendor="Microsoft",
    product_name="Outlook",
    product_feature="Phishing Report Add-in",
    policy_name="",
    policy_type=None,
    policy_desc="",
    risk_level=AlertRiskLevel.MEDIUM,
    risk_details="Potential for credential theft.",
    status=AlertStatus.NEW,
    status_detail="Awaiting analyst review.",
    remediation="Based on the analysis, it is recommended to block the sender's domain 'evil-domain.com' and IP address at the email gateway and firewall. Purge the phishing email from all recipient mailboxes. Force password reset for the user who reported the email and any other potential recipients.",
    comment="Initial report from user.",
    unmapped=json.dumps({"x-original-ip": "123.123.123.123"}),
    raw_data=json.dumps({"subject": "Urgent Payroll Update", "from": "no-reply@evil-domain.com", "to": "john.doe@example.com"}),
    summary_ai="A user reported a suspicious email with urgent language regarding payroll.",
    case=None,
    enrichments=[],
    artifacts=[artifact_evil_email, artifact_fake_url]
)

alert_malware_blocked = AlertModel(
    title="Malicious Attachment Blocked by Email Gateway",
    severity=Severity.HIGH,
    impact=ImpactLevel.MEDIUM,
    disposition=Disposition.BLOCKED,
    action=AlertAction.DENIED,
    confidence=Confidence.HIGH,
    uid="ALERT-GW-002",
    labels=["malware", "email-gateway", "trojan"],
    desc="Email Gateway blocked an attachment 'payroll_update.zip' containing known malware 'Trojan.Generic'.",
    modified_time=now,
    first_seen_time=past_10m,
    last_seen_time=past_10m,
    rule_id="MAL-ATTACH-101",
    rule_name="BlockKnownMalwareAttachment.VirusTotal",
    correlation_uid="CORR-PHISH-XYZ-123",
    count=5,
    src_url="https://gateway.example.com/logs/log-id-abcdef",
    source_uid="log-id-abcdef",
    data_sources=["Email Gateway", "VirusTotal API"],
    analytic_name="Gateway Malware Scanner",
    analytic_type=AlertAnalyticType.RULE,
    analytic_state=AlertAnalyticState.ACTIVE,
    analytic_desc="Blocks attachments with hashes matching high-confidence threat feeds.",
    tactic="Execution",
    technique="T1204.002",
    sub_technique="",
    mitigation="Email Attachment Sandboxing, Threat Intelligence Feed Integration",
    product_category=ProductCategory.EMAIL,
    product_vendor="SecureMail Inc.",
    product_name="SecureMail Gateway",
    product_feature="AV-Scan-Module",
    policy_name="Inbound-Malware-Policy",
    policy_type=None,
    policy_desc="Blocks all inbound attachments with a VT score > 50.",
    risk_level=AlertRiskLevel.HIGH,
    risk_details="Malware could lead to endpoint compromise.",
    status=AlertStatus.RESOLVED,
    status_detail="File was quarantined by the email gateway's automated policy.",
    remediation="The malware was blocked and quarantined, no immediate action required for this specific alert. It is recommended to add the file hash to the endpoint detection and response (EDR) system's blocklist to prevent execution from other vectors. Also, conduct a threat hunt to ensure no other systems were compromised.",
    comment="Blocked 5 attempts to deliver this file to different users.",
    unmapped="",
    raw_data=json.dumps({"attachment_hash": "a1b2c3d4e5f6...", "recipient_count": 5}),
    summary_ai="The email gateway blocked a malicious attachment identified by its hash.",
    case=None,
    enrichments=[enrichment_virustotal],
    artifacts=[artifact_malware_file, artifact_malware_hash]
)

alert_psexec_lateral = AlertModel(
    title="Suspicious Service Installation (PSEXESVC) on WS-FINANCE-05",
    severity=Severity.HIGH,
    impact=ImpactLevel.HIGH,
    disposition=Disposition.DETECTED,
    action=AlertAction.OBSERVED,
    confidence=Confidence.HIGH,
    uid="ALERT-EDR-101",
    labels=["psexec", "lateral-movement"],
    desc="PsExec service (PSEXESVC.exe) was created and started on WS-FINANCE-05, originating from DC01.",
    created_time=past_5m,
    modified_time=now,
    first_seen_time=past_5m,
    last_seen_time=past_5m,
    rule_id="EDR-RULE-LM-001",
    rule_name="PsExec Service Execution",
    correlation_uid="CORR-LAT-MOV-456",
    count=1,
    src_url="https://edr.example.com/alerts/ALERT-EDR-101",
    source_uid="be7a2f3a-8b1d-4a8a-9b1a-5d1e3e0f1e1a",
    data_sources=["EDR", "Windows Security Events"],
    analytic_name="Sysmon Behavioral Detection",
    analytic_type=AlertAnalyticType.BEHAVIORAL,
    analytic_state=AlertAnalyticState.ACTIVE,
    analytic_desc="Detects the creation of the PsExec service executable.",
    tactic="Lateral Movement",
    technique="T1569.002",
    sub_technique="",
    mitigation="Restrict Service Creation, Network Segmentation",
    product_category=ProductCategory.EDR,
    product_vendor="CrowdStrike",
    product_name="Falcon",
    product_feature="Behavioral-Detection-Engine",
    policy_name="Default Workstation Policy",
    policy_type=AlertPolicyType.IDENTITY_POLICY,
    policy_desc="Monitors for suspicious service installations.",
    risk_level=AlertRiskLevel.HIGH,
    risk_details="Indicates an attacker is moving through the network.",
    status=AlertStatus.ARCHIVED,
    status_detail="Alert has been correlated into Case-2 for incident response.",
    remediation="The SOAR playbook has successfully isolated the source host DC01 and destination host WS-FINANCE-05. Immediate investigation into the initial compromise vector on DC01 is required. It is recommended to dump memory and disk images from both systems for forensic analysis.",
    comment="Clear indicator of lateral movement.",
    unmapped="",
    raw_data=json.dumps({"event_id": 4697, "service_name": "PSEXESVC", "source_host": "DC01"}),
    summary_ai="PsExec was used to move from DC01 to a finance workstation.",
    case=None,
    enrichments=[],
    artifacts=[artifact_psexesvc, artifact_dc01]
)

alert_credential_dumping = AlertModel(
    title="Credential Dumping via LSASS Memory Access on DC01",
    severity=Severity.CRITICAL,
    impact=ImpactLevel.CRITICAL,
    disposition=Disposition.ALERT,
    action=AlertAction.OBSERVED,
    confidence=Confidence.HIGH,
    uid="ALERT-EDR-100",
    labels=["credential-dumping", "mimikatz", "lsass"],
    desc="An untrusted process 'mimikatz.exe' accessed the memory of lsass.exe, indicating credential dumping.",
    created_time=past_10m,
    modified_time=now,
    first_seen_time=past_10m,
    last_seen_time=past_10m,
    rule_id="EDR-RULE-CD-005",
    rule_name="LSASS Memory Access by Untrusted Process",
    correlation_uid="CORR-LAT-MOV-456",
    count=1,
    src_url="https://edr.example.com/alerts/ALERT-EDR-100",
    source_uid="aa1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
    data_sources=["EDR"],
    analytic_name="Credential Access Detection",
    analytic_type=AlertAnalyticType.BEHAVIORAL,
    analytic_state=AlertAnalyticState.ACTIVE,
    analytic_desc="Monitors for processes reading memory from LSASS.",
    tactic="Credential Access",
    technique="T1003.001",
    sub_technique="",
    mitigation="Credential Guard, LSA Protection",
    product_category=ProductCategory.EDR,
    product_vendor="CrowdStrike",
    product_name="Falcon",
    product_feature="Credential-Theft-Protection",
    policy_name="Domain Controller Policy",
    policy_type=None,
    policy_desc="",
    risk_level=AlertRiskLevel.CRITICAL,
    risk_details="Domain credentials may be compromised.",
    status=AlertStatus.ARCHIVED,
    status_detail="Alert has been correlated into Case-2, serving as a precursor to the lateral movement alert.",
    remediation="Enable LSA Protection (RunAsPPL) on domain controllers. Deploy Credential Guard to protect LSASS from memory access. Monitor for and alert on processes accessing LSASS memory, especially from untrusted processes.",
    comment="This was likely the initial point of credential theft enabling lateral movement.",
    unmapped="",
    raw_data=json.dumps({"source_process": "mimikatz.exe", "target_process": "lsass.exe"}),
    summary_ai="Credential dumping tool Mimikatz was detected on the domain controller.",
    case=None,
    enrichments=[],
    artifacts=[artifact_lsass, artifact_mimikatz]
)

alert_dns_tunnel_volume = AlertModel(
    title="Anomalous DNS Query Volume (TXT Records)",
    severity=Severity.MEDIUM,
    impact=ImpactLevel.LOW,
    action=AlertAction.OBSERVED,
    disposition=Disposition.LOGGED,
    confidence=Confidence.MEDIUM,
    uid="ALERT-NDR-301",
    labels=["dns-tunneling", "ndr"],
    desc="Endpoint 10.1.1.5 (WS-MARKETING-12) made an unusually high number of DNS TXT queries to a single domain, c2.bad-actor-infra.net.",
    created_time=now,
    modified_time=now,
    first_seen_time=past_10m,
    last_seen_time=now,
    rule_id="NDR-DNS-007",
    rule_name="High Volume of DNS TXT Queries to Single Domain",
    correlation_uid="CORR-DNS-TUN-789",
    count=245,
    src_url="https://ndr.example.com/alerts/ALERT-NDR-301",
    source_uid="ndr-flow-98765",
    data_sources=["NDR", "DNS Logs"],
    analytic_name="DNS Exfiltration Detector",
    analytic_type=AlertAnalyticType.BEHAVIORAL,
    analytic_state=AlertAnalyticState.ACTIVE,
    analytic_desc="Flags high-frequency TXT/NULL queries.",
    tactic="Command and Control",
    technique="T1071.004",
    sub_technique="",
    mitigation="DNS Sinkholing, Egress Traffic Filtering",
    product_category=ProductCategory.NDR,
    product_vendor="Vectra",
    product_name="Cognito",
    product_feature="DNS-Analytics",
    policy_name="",
    policy_type=None,
    policy_desc="",
    risk_level=AlertRiskLevel.MEDIUM,
    risk_details="Potential for covert C2 channel or data exfiltration.",
    status=AlertStatus.NEW,
    status_detail="The alert is currently under investigation. The affected host has been placed in a high-monitoring group to observe traffic without tipping off the potential attacker.",
    remediation="Configure DNS sinkholing for the suspicious domain 'c2.bad-actor-infra.net' to analyze C2 commands safely. Review and tighten egress DNS filtering rules. Perform packet capture on the affected host for deeper analysis of the DNS query contents.",
    comment="",
    unmapped="",
    raw_data=json.dumps({"query_count": 245, "domain": "c2.bad-actor-infra.net"}),
    summary_ai="High volume of DNS TXT queries suggests a DNS tunnel.",
    case=None,
    enrichments=[enrichment_otx_evil_domain],
    artifacts=[artifact_internal_ip, artifact_c2_domain]
)

alert_dns_long_query = AlertModel(
    title="Firewall Detected Unusually Long DNS Query",
    severity=Severity.LOW,
    impact=ImpactLevel.LOW,
    action=AlertAction.DENIED,
    disposition=Disposition.ALLOWED,
    confidence=Confidence.LOW,
    uid="ALERT-FW-905",
    labels=["dns", "firewall"],
    desc="A DNS query with an unusually long label (>63 chars) was observed, which can be an indicator of tunneling.",
    created_time=past_5m,
    modified_time=now,
    first_seen_time=past_5m,
    last_seen_time=past_5m,
    rule_id="FW-DNS-002",
    rule_name="Long DNS Label Detected",
    correlation_uid="CORR-DNS-TUN-789",
    count=1,
    src_url="https://fw.example.com/logs/log-id-54321",
    source_uid="log-id-54321",
    data_sources=["Firewall"],
    analytic_name="Firewall DNS Protocol Anomaly",
    analytic_type=AlertAnalyticType.RULE,
    analytic_state=AlertAnalyticState.EXPERIMENTAL,
    analytic_desc="Flags DNS queries that violate standard label length.",
    tactic="Command and Control",
    technique="T1071.004",
    sub_technique="",
    mitigation="Egress DNS Filtering",
    product_category=ProductCategory.CLOUD,
    product_vendor="Palo Alto",
    product_name="PA-Series Firewall",
    product_feature="DNS-Security",
    policy_name="Default-DNS-Allow",
    policy_type=AlertPolicyType.SERVICE_CONTROL_POLICY,
    policy_desc="Default policy allowing outbound DNS traffic.",
    risk_level=AlertRiskLevel.LOW,
    risk_details="Suspicious but could be a false positive from non-standard software.",
    status=AlertStatus.NEW,
    status_detail="This alert corroborates the NDR alert for DNS tunneling. Awaiting further analysis from the primary alert.",
    remediation="Implement firewall policies to block or alert on DNS queries with label lengths exceeding RFC standards (63 characters). Ensure DNS traffic is logged comprehensively for threat hunting and historical analysis.",
    comment="Correlates with the NDR alert, increasing confidence.",
    unmapped=json.dumps({"dns_flags": "RD"}),
    raw_data=json.dumps({"qname": "verylonglabelthatmightbeencodeddata.c2.bad-actor-infra.net"}),
    summary_ai="An unusually long DNS query was detected by the firewall.",
    case=None,
    enrichments=[enrichment_otx_evil_domain, enrichment_virustotal],
    artifacts=[artifact_dns_port, artifact_google_dns]
)

# === Case 1: Phishing Email Attack (100% Coverage) ===
case1_phishing = CaseModel(
    title="Phishing Campaign Detected - 'Urgent Payroll Update'",
    severity=Severity.HIGH,
    impact=ImpactLevel.MEDIUM,
    priority=CasePriority.HIGH,
    src_url="https://sirp.example.com/cases/1",
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
    workbook="### Phishing Investigation PlaybookLoader\n1. Analyze headers (`done`)\n2. Detonate URL/Attachment (`done`)\n3. Identify recipients (`in-progress`)\n4. Purge emails from mailboxes\n5. Reset compromised user passwords\n",
    analysis_rationale_ai="The email originates from an external, un-reputable domain and uses urgent language, a common phishing tactic. The URL leads to a non-standard login page with a self-signed certificate. The attachment hash matches known malware.",
    recommended_actions_ai="- Block sender domain 'evil-domain.com'\n- Reset passwords for all users who clicked the link\n- Scan all endpoints for the malware hash 'a1b2c3d4e5f6...'",
    attack_stage_ai="Initial Access, Execution",
    severity_ai=Severity.HIGH,
    confidence_ai=Confidence.HIGH,
    threat_hunting_report_ai="Threat hunting query initiated to find other emails from the same sender IP or with similar subject lines across the organization.",
    # Time-based fields for metrics
    start_time=past_10m.isoformat(),
    end_time=None,
    detect_time=past_5m.isoformat(),
    acknowledge_time=now.isoformat(),
    respond_time=None,
    tickets=[ticket_jira],
    enrichments=[enrichment_business],
    alerts=[alert_user_reported_phishing, alert_malware_blocked]
)

# === Case 2: Endpoint Lateral Movement (100% Coverage) ===
case2_lateral_movement = CaseModel(
    title="Lateral Movement Detected via PsExec from DC01 to WS-FINANCE-05",
    severity=Severity.CRITICAL,
    impact=ImpactLevel.HIGH,
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
    workbook="### Lateral Movement PlaybookLoader\n1. Isolate source and destination (`done`)\n2. Dump memory from hosts (`done`)\n3. Analyze for persistence (`done`)\n4. Rotate credentials (`done`)",
    analysis_rationale_ai="PsExec execution from a domain controller to a workstation is highly anomalous. The initial compromise vector on DC01 appears to be related to a credential dumping alert moments before the lateral movement.",
    recommended_actions_ai="- Isolate both DC01 and WS-FINANCE-05 immediately.\n- Investigate DC01 for initial compromise.\n- Rotate all privileged credentials.",
    attack_stage_ai="Lateral Movement",
    severity_ai=Severity.CRITICAL,
    confidence_ai=Confidence.HIGH,
    threat_hunting_report_ai="",
    start_time=past_10m.isoformat(),
    end_time=now.isoformat(),
    detect_time=past_5m.isoformat(),
    acknowledge_time=past_5m.isoformat(),
    respond_time=now.isoformat(),
    tickets=[ticket_servicenow],
    alerts=[alert_psexec_lateral, alert_credential_dumping]
)

# === Case 3: DNS Tunneling C2 (100% Coverage) ===
case3_dns_tunnel = CaseModel(
    title="Suspected DNS Tunneling for C2 Communication from WS-MARKETING-12",
    severity=Severity.MEDIUM,
    impact=ImpactLevel.LOW,
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
    workbook="### DNS Tunneling PlaybookLoader\n1. Analyze query patterns (TXT/NULL record types, query length)\n2. Check domain reputation\n3. Perform packet capture on host\n4. Compare against baseline DNS traffic",
    analysis_rationale_ai="The high volume of TXT queries to a single, non-business related domain is a strong indicator of DNS tunneling. The query payloads appear to be encoded.",
    recommended_actions_ai="- Place the host in a sinkhole network to observe C2 traffic safely.\n- Do not block immediately to gather more intelligence on the attacker's infrastructure.",
    attack_stage_ai="Command and Control",
    severity_ai=Severity.MEDIUM,
    confidence_ai=Confidence.MEDIUM,
    threat_hunting_report_ai="",
    start_time=past_10m.isoformat(),
    end_time=None,
    detect_time=now.isoformat(),
    acknowledge_time=now.isoformat(),
    respond_time=None,
    tickets=[],
    enrichments=[],
    alerts=[alert_dns_tunnel_volume, alert_dns_long_query]
)

if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()

    for case in [case1_phishing, case2_lateral_movement, case3_dns_tunnel]:
        Case.update_or_create(case)

    # Alert.update_or_create(alert_malware_blocked)
    # alert_model = AlertModel()
    # alert_model.rowid = "aec8cdf3-6e40-4768-8f2b-be589eb3fff4"
    # alert_model.product_vendor = "Test"
    # Alert.update_or_create(alert_model)
