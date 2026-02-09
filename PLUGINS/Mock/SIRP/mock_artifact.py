from PLUGINS.Mock.SIRP.mock_enrichment import *
from PLUGINS.SIRP.sirpmodel import ArtifactModel, ArtifactType, ArtifactRole, ArtifactReputationScore

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
artifact_sql_server = ArtifactModel(
    name="SQL-SERVER-PROD-01",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="SQL-SERVER-PROD-01",
    owner="Database Team"
)
artifact_user_account = ArtifactModel(
    name="sarah.johnson@example.com",
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="sarah.johnson@example.com",
    owner="Sales Department"
)
artifact_ransomware_ip_2 = ArtifactModel(
    name="177.19.44.123",
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="177.19.44.123",
    reputation_provider="AbuseIPDB",
    reputation_score=ArtifactReputationScore.MALICIOUS
)
artifact_powershell_script = ArtifactModel(
    name="invoke_malware.ps1",
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.ACTOR,
    value="C:\\Users\\Public\\Downloads\\invoke_malware.ps1"
)
artifact_malware_registry = ArtifactModel(
    name="HKLM\\Software\\Malware",
    type=ArtifactType.REGISTRY_PATH,
    role=ArtifactRole.ACTOR,
    value="HKLM\\Software\\Malware"
)
artifact_suspicious_domain_2 = ArtifactModel(
    name="update-check.badguy.net",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.RELATED,
    value="update-check.badguy.net",
    reputation_score=ArtifactReputationScore.MALICIOUS
)
artifact_suspicious_domain_3 = ArtifactModel(
    name="check-version.exfil.xyz",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.RELATED,
    value="check-version.exfil.xyz",
    reputation_score=ArtifactReputationScore.SUSPICIOUS_RISKY
)
artifact_aws_role = ArtifactModel(
    name="arn:aws:iam::123456789012:role/lambda-execution",
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.ACTOR,
    value="arn:aws:iam::123456789012:role/lambda-execution"
)
artifact_cloudtrail_event = ArtifactModel(
    name="DeleteBucket API Call",
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="s3:DeleteBucket"
)
artifact_user_account_2 = ArtifactModel(
    name="admin.user@example.com",
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="admin.user@example.com",
    owner="IT Administration"
)
artifact_slack_channel = ArtifactModel(
    name="#general",
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="https://example.slack.com/archives/C0123456789"
)
artifact_brute_force_ip = ArtifactModel(
    name="45.95.11.22",
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="45.95.11.22",
    reputation_provider="AbuseIPDB",
    reputation_score=ArtifactReputationScore.MALICIOUS,
    enrichments=[enrichment_greynoise_scanner, enrichment_geoip_russia]
)
artifact_target_user_brute = ArtifactModel(
    name="admin@example.com",
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.TARGET,
    value="admin@example.com",
    owner="System"
)
artifact_target_host_brute = ArtifactModel(
    name="srv-web-prod-01",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="srv-web-prod-01",
    owner="Operations"
)
artifact_malicious_url_sqli = ArtifactModel(
    name="https://web-3.example.com/api/user?id=1' OR '1'='1",
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="https://web-3.example.com/api/user?id=1' OR '1'='1",
    reputation_score=ArtifactReputationScore.MALICIOUS
)
artifact_sqlmap_tool = ArtifactModel(
    name="sqlmap/1.5.2",
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.ACTOR,
    value="sqlmap/1.5.2 (SQL Injection Scanner)"
)
artifact_waf_server = ArtifactModel(
    name="web-3.example.com",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="web-3.example.com",
    owner="Web Operations"
)
artifact_vssadmin_process = ArtifactModel(
    name="vssadmin.exe",
    type=ArtifactType.PROCESS_NAME,
    role=ArtifactRole.ACTOR,
    value="vssadmin.exe delete shadows /all /quiet"
)
artifact_decryptor_malware = ArtifactModel(
    name="decryptor.exe",
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.ACTOR,
    value="decryptor.exe",
    reputation_provider="VirusTotal",
    reputation_score=ArtifactReputationScore.MALICIOUS
)
artifact_ransom_note_file = ArtifactModel(
    name="README_TO_DECRYPT.txt",
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="README_TO_DECRYPT.txt"
)
artifact_encrypted_files = ArtifactModel(
    name="*.encrypted",
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="Multiple encrypted files (docx, pdf, xlsx, jpg)"
)
artifact_ransomware_host = ArtifactModel(
    name="srv-db-master",
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="srv-db-master",
    owner="Database Team"
)
artifact_ransomware_user = ArtifactModel(
    name="dbadmin@example.com",
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.TARGET,
    value="dbadmin@example.com",
    owner="Database Team"
)
