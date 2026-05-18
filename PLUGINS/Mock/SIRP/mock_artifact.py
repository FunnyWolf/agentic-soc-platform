from PLUGINS.Mock.SIRP.mock_enrichment import *
from PLUGINS.SIRP.sirpcoremodel import ArtifactName, ArtifactType, ArtifactRole, ArtifactReputationScore, ArtifactModel

artifact_evil_email = ArtifactModel(
    name=ArtifactName.SENDER_EMAIL,
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="no-reply@evil-domain.com",

    enrichments=[enrichment_otx_evil_domain]
)
artifact_fake_url = ArtifactModel(
    name=ArtifactName.PHISHING_URL,
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="http://fake-payroll-login.com",

)
artifact_malware_file = ArtifactModel(
    name=ArtifactName.ATTACHMENT_FILE,
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="payroll_update.zip"
)
artifact_malware_hash = ArtifactModel(
    name=ArtifactName.FILE_HASH,
    type=ArtifactType.HASH,
    role=ArtifactRole.RELATED,
    value="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",

    enrichments=[enrichment_virustotal]
)
artifact_psexesvc = ArtifactModel(
    name=ArtifactName.PROCESS_NAME,
    type=ArtifactType.PROCESS_NAME,
    role=ArtifactRole.RELATED,
    value="PSEXESVC.exe",
    owner="System"
)
artifact_dc01 = ArtifactModel(
    name=ArtifactName.SOURCE_HOST,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.ACTOR,
    value="DC01",
)
artifact_lsass = ArtifactModel(
    name=ArtifactName.TARGET_PROCESS,
    type=ArtifactType.PROCESS_NAME,
    role=ArtifactRole.TARGET,
    value="lsass.exe",
    owner="System"
)
artifact_mimikatz = ArtifactModel(
    name=ArtifactName.ACTING_PROCESS,
    type=ArtifactType.PROCESS_NAME,
    role=ArtifactRole.ACTOR,
    value="mimikatz.exe",
)
artifact_internal_ip = ArtifactModel(
    name=ArtifactName.SOURCE_IP,
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="10.1.1.5",
    owner="Workstation-Pool-DHCP"
)
artifact_c2_domain = ArtifactModel(
    name=ArtifactName.DOMAIN,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.RELATED,
    value="c2.bad-actor-infra.net",

)
artifact_dns_port = ArtifactModel(
    name=ArtifactName.DESTINATION_PORT,
    type=ArtifactType.PORT,
    role=ArtifactRole.RELATED,
    value="53",
)
artifact_google_dns = ArtifactModel(
    name=ArtifactName.DNS_SERVER_IP,
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.RELATED,
    value="8.8.8.8",
    enrichments=[enrichment_otx_8888]
)
artifact_ransomware_ip = ArtifactModel(
    name=ArtifactName.SOURCE_IP,
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="103.95.196.78",

    enrichments=[enrichment_abuseipdb_ransomware, enrichment_geoip_russia]
)
artifact_ransom_note = ArtifactModel(
    name=ArtifactName.FILE_NAME,
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="README_DECRYPT.txt"
)
artifact_encrypted_file = ArtifactModel(
    name=ArtifactName.TARGET_FILE,
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="C:\\Users\\john.smith\\Documents\\financial_report_Q4.xlsx.locked"
)
artifact_ransomware_hash = ArtifactModel(
    name=ArtifactName.FILE_HASH,
    type=ArtifactType.HASH,
    role=ArtifactRole.ACTOR,
    value="5f4dcc3b5aa765d61d8327deb882cf99b4c2d6e6e6b4e6f6e6e6e6e6e6e6e6e6",

    enrichments=[enrichment_virustotal]
)
artifact_cryptominer_binary = ArtifactModel(
    name=ArtifactName.FILE_PATH,
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.ACTOR,
    value="C:\\Windows\\Temp\\svchost.exe",
    enrichments=[enrichment_virustotal_cryptominer]
)
artifact_cryptominer_hash = ArtifactModel(
    name=ArtifactName.FILE_HASH,
    type=ArtifactType.HASH,
    role=ArtifactRole.ACTOR,
    value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",

    enrichments=[enrichment_virustotal_cryptominer]
)
artifact_mining_pool = ArtifactModel(
    name=ArtifactName.DOMAIN,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.RELATED,
    value="cryptominer-pool.xyz",

    enrichments=[enrichment_whois_domain]
)
artifact_insider_user = ArtifactModel(
    name=ArtifactName.USER_EMAIL,
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="bob.contractor@example.com",
    owner="IT Department",
    enrichments=[enrichment_okta_user]
)
artifact_s3_bucket = ArtifactModel(
    name=ArtifactName.CLOUD_BUCKET,
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.TARGET,
    value="s3://example-customer-data-prod",
    enrichments=[enrichment_aws_s3_public]
)
artifact_exfil_destination = ArtifactModel(
    name=ArtifactName.DESTINATION_IP,
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.RELATED,
    value="185.220.101.45",

    enrichments=[enrichment_greynoise_scanner, enrichment_geoip_russia]
)
artifact_log4j_vuln = ArtifactModel(
    name=ArtifactName.CVE,
    type=ArtifactType.CVE,
    role=ArtifactRole.RELATED,
    value="CVE-2021-44228",
    enrichments=[enrichment_cve_detail]
)
artifact_exploit_url = ArtifactModel(
    name=ArtifactName.DOWNLOAD_URL,
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="http://malicious-payload-server.ru/payload.exe",

    enrichments=[enrichment_urlhaus_malware]
)
artifact_vulnerable_server = ArtifactModel(
    name=ArtifactName.TARGET_HOST,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="WEB-SERVER-01"
)
artifact_sql_server = ArtifactModel(
    name=ArtifactName.TARGET_HOST,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="SQL-SERVER-PROD-01",
    owner="Database Team"
)
artifact_user_account = ArtifactModel(
    name=ArtifactName.USER_EMAIL,
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="sarah.johnson@example.com",
    owner="Sales Department"
)
artifact_ransomware_ip_2 = ArtifactModel(
    name=ArtifactName.SOURCE_IP,
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="177.19.44.123",

)
artifact_powershell_script = ArtifactModel(
    name=ArtifactName.FILE_PATH,
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.ACTOR,
    value="C:\\Users\\Public\\Downloads\\invoke_malware.ps1"
)
artifact_malware_registry = ArtifactModel(
    name=ArtifactName.REGISTRY_PATH,
    type=ArtifactType.REGISTRY_PATH,
    role=ArtifactRole.ACTOR,
    value="HKLM\\Software\\Malware"
)
artifact_suspicious_domain_2 = ArtifactModel(
    name=ArtifactName.DOMAIN,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.RELATED,
    value="update-check.badguy.net",
    reputation_score=ArtifactReputationScore.MALICIOUS
)
artifact_suspicious_domain_3 = ArtifactModel(
    name=ArtifactName.DOMAIN,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.RELATED,
    value="check-version.exfil.xyz",
    reputation_score=ArtifactReputationScore.SUSPICIOUS_RISKY
)
artifact_aws_role = ArtifactModel(
    name=ArtifactName.IAM_ROLE,
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.ACTOR,
    value="arn:aws:iam::123456789012:role/lambda-execution"
)
artifact_cloudtrail_event = ArtifactModel(
    name=ArtifactName.IAM_ACTION,
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="s3:DeleteBucket"
)
artifact_user_account_2 = ArtifactModel(
    name=ArtifactName.USER_EMAIL,
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="admin.user@example.com",
    owner="IT Administration"
)
artifact_slack_channel = ArtifactModel(
    name=ArtifactName.URL,
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="https://example.slack.com/archives/C0123456789"
)
artifact_brute_force_ip = ArtifactModel(
    name=ArtifactName.SOURCE_IP,
    type=ArtifactType.IP_ADDRESS,
    role=ArtifactRole.ACTOR,
    value="45.95.11.22",

    enrichments=[enrichment_greynoise_scanner, enrichment_geoip_russia]
)
artifact_target_user_brute = ArtifactModel(
    name=ArtifactName.TARGET_USER,
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.TARGET,
    value="admin@example.com",
    owner="System"
)
artifact_target_host_brute = ArtifactModel(
    name=ArtifactName.TARGET_HOST,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="srv-web-prod-01",
    owner="Operations"
)
artifact_malicious_url_sqli = ArtifactModel(
    name=ArtifactName.REQUEST_URL,
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.RELATED,
    value="https://web-3.example.com/api/user?id=1' OR '1'='1",
)
artifact_sqlmap_tool = ArtifactModel(
    name=ArtifactName.HTTP_USER_AGENT,
    type=ArtifactType.URL_STRING,
    role=ArtifactRole.ACTOR,
    value="sqlmap/1.5.2 (SQL Injection Scanner)"
)
artifact_waf_server = ArtifactModel(
    name=ArtifactName.TARGET_HOST,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="web-3.example.com",
    owner="Web Operations"
)
artifact_vssadmin_process = ArtifactModel(
    name=ArtifactName.PROCESS_COMMAND_LINE,
    type=ArtifactType.PROCESS_NAME,
    role=ArtifactRole.ACTOR,
    value="vssadmin.exe delete shadows /all /quiet"
)
artifact_decryptor_malware = ArtifactModel(
    name=ArtifactName.FILE_NAME,
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.ACTOR,
    value="decryptor.exe",
)
artifact_ransom_note_file = ArtifactModel(
    name=ArtifactName.FILE_NAME,
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="README_TO_DECRYPT.txt"
)
artifact_encrypted_files = ArtifactModel(
    name=ArtifactName.TARGET_FILE,
    type=ArtifactType.FILE_NAME,
    role=ArtifactRole.RELATED,
    value="Multiple encrypted files (docx, pdf, xlsx, jpg)"
)
artifact_ransomware_host = ArtifactModel(
    name=ArtifactName.TARGET_HOST,
    type=ArtifactType.HOSTNAME,
    role=ArtifactRole.TARGET,
    value="srv-db-master",
    owner="Database Team"
)
artifact_ransomware_user = ArtifactModel(
    name=ArtifactName.TARGET_USER,
    type=ArtifactType.EMAIL_ADDRESS,
    role=ArtifactRole.TARGET,
    value="dbadmin@example.com",
    owner="Database Team"
)
