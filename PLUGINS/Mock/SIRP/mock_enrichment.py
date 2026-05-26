import json

from PLUGINS.SIRP.sirpcoremodel import EnrichmentModel, EnrichmentType, EnrichmentProvider

enrichment_otx_evil_domain = EnrichmentModel(
    name="OTX Pulse for evil-domain.com",
    type=EnrichmentType.THREAT_INTELLIGENCE,
    provider=EnrichmentProvider.ALIENVAULT_OTX,
    value="evil-domain.com",
    desc="This domain is associated with the 'Gootkit' malware family.",
    data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
)
enrichment_virustotal = EnrichmentModel(
    name="VirusTotal Report for Hash 'a1b2c3d4...'",
    type=EnrichmentType.THREAT_INTELLIGENCE,
    provider=EnrichmentProvider.VIRUSTOTAL,
    value="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    desc="72/75 vendors flagged this as malicious 'Trojan.Generic'.",
    data=json.dumps({"scan_id": "a1b2c3d4e5f6-1678886400", "positives": 72, "total": 75})
)
enrichment_business = EnrichmentModel(
    name="Affected Business Unit", type=EnrichmentType.ASSET, provider=EnrichmentProvider.INTERNAL_CMDB,
    value="Finance Department", desc="Internal CMDB Information: High-value target.",
    data=json.dumps({"scan_id": "a1b2c3d4e5f6-1678886400", "positives": 72, "total": 75})
)
enrichment_otx_8888 = EnrichmentModel(
    name="OTX Pulse for 8.8.8.8",
    type=EnrichmentType.THREAT_INTELLIGENCE,
    provider=EnrichmentProvider.ALIENVAULT_OTX,
    value="8.8.8.8",
    desc="This domain is associated with the 'Gootkit' malware family.",
    data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
)
enrichment_greynoise_scanner = EnrichmentModel(
    name="GreyNoise Report for 45.95.11.22",
    type=EnrichmentType.THREAT_INTELLIGENCE,
    provider=EnrichmentProvider.GREYNOISE,
    value="45.95.11.22",
    desc="Known mass-scanner. Classification: malicious. Last seen scanning 2 hours ago.",
    data=json.dumps({"classification": "malicious", "tags": ["SSH Bruteforce", "Mass Scanner"], "last_seen": "2h"})
)
enrichment_abuseipdb_ransomware = EnrichmentModel(
    name="AbuseIPDB Report for 103.95.196.78",
    type=EnrichmentType.THREAT_INTELLIGENCE,
    provider=EnrichmentProvider.ABUSEIPDB,
    value="103.95.196.78",
    desc="Abuse confidence score: 98%. Associated with ransomware C2 infrastructure.",
    data=json.dumps({"confidence_score": 98, "reports": 156, "categories": ["ransomware", "c2"]})
)
enrichment_urlhaus_malware = EnrichmentModel(
    name="URLhaus Report for malicious payload",
    type=EnrichmentType.THREAT_INTELLIGENCE,
    provider=EnrichmentProvider.URLHAUS,
    value="http://malicious-payload-server.ru/payload.exe",
    desc="Known malware distribution URL. Payload: Emotet. Status: Online.",
    data=json.dumps({"threat": "Emotet", "status": "online", "first_seen": "2024-01-15"})
)
enrichment_shodan_exposed_rdp = EnrichmentModel(
    name="Shodan Scan for exposed RDP",
    type=EnrichmentType.EXPOSURE,
    provider=EnrichmentProvider.SHODAN,
    value="203.0.113.50",
    desc="Exposed RDP service on port 3389. No encryption. Vulnerable to BlueKeep (CVE-2019-0708).",
    data=json.dumps({"ports": [3389], "vulns": ["CVE-2019-0708"], "org": "Example Corp"})
)
enrichment_whois_domain = EnrichmentModel(
    name="WHOIS for cryptominer-pool.xyz",
    type=EnrichmentType.WHOIS,
    provider=EnrichmentProvider.DOMAINTOOLS,
    value="cryptominer-pool.xyz",
    desc="Registered 3 days ago. Registrar: NameCheap. Privacy protection enabled.",
    data=json.dumps({"created": "2024-01-18", "registrar": "NameCheap", "privacy": True})
)
enrichment_geoip_russia = EnrichmentModel(
    name="GeoIP Location for 45.95.11.22",
    type=EnrichmentType.GEO_LOCATION,
    provider=EnrichmentProvider.MAXMIND,
    value="45.95.11.22",
    desc="Location: Moscow, Russia. ASN: AS12345 (SuspiciousHosting LLC)",
    data=json.dumps({"country": "RU", "city": "Moscow", "asn": "AS12345", "org": "SuspiciousHosting LLC"})
)
enrichment_virustotal_cryptominer = EnrichmentModel(
    name="VirusTotal Report for cryptominer binary",
    type=EnrichmentType.THREAT_INTELLIGENCE,
    provider=EnrichmentProvider.VIRUSTOTAL,
    value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    desc="68/72 vendors flagged this as 'CoinMiner.Generic'. XMRig variant detected.",
    data=json.dumps({"scan_id": "e3b0c442-1678886400", "positives": 68, "total": 72, "malware_family": "XMRig"})
)
enrichment_crowdstrike_ioc = EnrichmentModel(
    name="CrowdStrike Threat Intel for Lazarus Group",
    type=EnrichmentType.THREAT_INTELLIGENCE,
    provider=EnrichmentProvider.CROWDSTRIKE,
    value="Lazarus Group",
    desc="APT38/Lazarus Group TTPs detected. Known for supply chain attacks and ransomware.",
    data=json.dumps({"apt_group": "Lazarus", "aka": ["APT38", "Hidden Cobra"], "motivation": "Financial"})
)
enrichment_okta_user = EnrichmentModel(
    name="Okta User Profile for compromised account",
    type=EnrichmentType.IDENTITY,
    provider=EnrichmentProvider.OKTA,
    value="bob.contractor@example.com",
    desc="Contractor account. Department: IT. Privileged access to AWS console.",
    data=json.dumps({"department": "IT", "role": "contractor", "privileged": True, "mfa_enabled": False})
)
enrichment_aws_s3_public = EnrichmentModel(
    name="AWS S3 Bucket Misconfiguration",
    type=EnrichmentType.EXPOSURE,
    provider=EnrichmentProvider.AWS_SECURITY_HUB,
    value="s3://example-customer-data-prod",
    desc="Public read access enabled. Contains 45,000 files including PII.",
    data=json.dumps({"public_access": True, "file_count": 45000, "contains_pii": True})
)
enrichment_cve_detail = EnrichmentModel(
    name="CVE-2021-44228 (Log4Shell) Details",
    type=EnrichmentType.VULNERABILITY,
    provider=EnrichmentProvider.NVD,
    value="CVE-2021-44228",
    desc="CVSS Score: 10.0 (Critical). Remote code execution in Log4j. Actively exploited in the wild.",
    data=json.dumps({"cvss_score": 10.0, "severity": "CRITICAL", "exploited": True})
)
enrichment_splunk_anomaly = EnrichmentModel(
    name="Splunk Behavioral Baseline Anomaly",
    type=EnrichmentType.BEHAVIOR,
    provider=EnrichmentProvider.SPLUNK,
    value="10.5.30.45",
    desc="Unusual outbound connection patterns detected. 300% above baseline for this endpoint.",
    data=json.dumps({"baseline": 50, "current": 200, "anomaly_score": 0.95})
)
enrichment_carbonblack_execution = EnrichmentModel(
    name="Carbon Black Advanced Threat Analytics",
    type=EnrichmentType.BEHAVIOR,
    provider=EnrichmentProvider.VMWARE_CARBON_BLACK,
    value="suspicious_process.exe",
    desc="Behavioral analysis indicates ransomware execution patterns.",
    data=json.dumps({"threat_level": "HIGH", "behaviors": ["file_encryption", "network_scanning", "process_injection"]})
)
enrichment_zerofox_brand = EnrichmentModel(
    name="ZeroFox Brand Monitoring Alert",
    type=EnrichmentType.EXPOSURE,
    provider=EnrichmentProvider.ZEROFOX,
    value="example.com",
    desc="Phishing domain impersonating example.com detected on social media.",
    data=json.dumps({"fake_domain": "examp1e.com", "platform": "Facebook", "reports": 25})
)
enrichment_darktrace_ai = EnrichmentModel(
    name="Darktrace AI Anomaly Score",
    type=EnrichmentType.BEHAVIOR,
    provider=EnrichmentProvider.DARKTRACE,
    value="172.16.50.200",
    desc="AI detected unusual connection patterns. Mimics data exfiltration behavior.",
    data=json.dumps({"anomaly_score": 0.92, "device_name": "Sales-Server-03", "connection_target": "148.251.200.100"})
)
enrichment_proofpoint_sandbox = EnrichmentModel(
    name="Proofpoint Advanced Threat Protection Sandbox",
    type=EnrichmentType.SANDBOX,
    provider=EnrichmentProvider.PROOFPOINT,
    value="malicious_macro.docx",
    desc="Document detonated in sandbox. Confirmed malicious macro executes powershell scripts.",
    data=json.dumps({"detonation_time": "2s", "verdict": "MALICIOUS", "execution": "PowerShell"})
)
enrichment_yara_detection = EnrichmentModel(
    name="YARA Rule Match for APT28 Artifacts",
    type=EnrichmentType.DETECTION,
    provider=EnrichmentProvider.CUSTOM_YARA,
    value="malware_sample.exe",
    desc="Matched YARA rule 'APT28_Backdoor_v1'. Confirms known APT28 malware family.",
    data=json.dumps({"rule_name": "APT28_Backdoor_v1", "severity": "CRITICAL", "false_positive_rate": 0.02})
)
enrichment_kubernetes_pod = EnrichmentModel(
    name="Kubernetes Pod Configuration Analysis",
    type=EnrichmentType.EXPOSURE,
    provider=EnrichmentProvider.KUBERNETES_API,
    value="prod-webapp-deployment",
    desc="Pod running with elevated privileges. Root filesystem mounted as read-write.",
    data=json.dumps({"namespace": "production", "privilege_level": "elevated", "security_policy": "violated"})
)
enrichment_sentinel_threat = EnrichmentModel(
    name="Azure Sentinel Threat Intelligence",
    type=EnrichmentType.EXPOSURE,
    provider=EnrichmentProvider.MICROSOFT_SENTINEL,
    value="suspicious_user_logon",
    desc="Impossible travel detected. User logged in from two countries within 5 minutes.",
    data=json.dumps({"first_location": "US", "second_location": "CN", "time_difference": "5min"})
)
