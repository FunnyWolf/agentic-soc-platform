from PLUGINS.SIRP.grouprule import GroupRule

rule_list = [
    GroupRule(
        rule_id="EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        rule_name="Suspicious process spawned by Office application",
        deduplication_fields=["hostname", "process_name"],
        source="EDR"
    ),
    GroupRule(
        rule_id="EDR-Rule-21-CobaltStrike-Beacon-Detected",
        rule_name="Cobalt Strike C2 beacon detected",
        deduplication_fields=["hostname"],
        deduplication_window="1h",
        source="EDR"
    ),
    GroupRule(
        rule_id="EDR-Rule-07-Credential-Dumping-LSASS",
        rule_name="LSASS memory credential dump",
        deduplication_fields=["hostname", "target_process"],
        source="EDR"
    ),
    GroupRule(
        rule_id="EDR-Rule-01-Suspicious-PowerShell-Execution",
        rule_name="Suspicious PowerShell command execution",
        deduplication_fields=["hostname"],
        deduplication_window="1h",
        source="EDR"
    ),
    GroupRule(
        rule_id="EDR-Rule-02-Unusual-Network-Connection-to-External",
        rule_name="Unusual outbound network connection",
        deduplication_fields=["hostname", "destination_ip"],
        source="EDR"
    ),
    GroupRule(
        rule_id="NDR-Rule-05-Suspect-C2-Communication",
        rule_name="Suspicious command and control (C2) communication",
        deduplication_fields=["hostname"],
        source="NDR"
    ),
    GroupRule(
        rule_id="NDR-Rule-12-Lateral-Movement-Attempt",
        rule_name="Host-to-host lateral movement attempt",
        deduplication_fields=["hostname", "destination_ip"],
        deduplication_window="1h",
        source="NDR"
    ),
    GroupRule(
        rule_id="NDR-Rule-15-Unauthorized-Data-Exfiltration",
        rule_name="Anomalous data exfiltration",
        deduplication_fields=["hostname", "data_volume"],
        source="NDR"
    ),
    GroupRule(
        rule_id="NDR-Rule-01-C2-Beaconing",
        rule_name="C2 beaconing traffic",
        deduplication_fields=["hostname", "destination_ip"],
        deduplication_window="1h",
        source="NDR"
    ),
    GroupRule(
        rule_id="NDR-Rule-02-Internal-Port-Scan",
        rule_name="Internal port scan",
        deduplication_fields=["source_ip", "scan_type"],
        source="NDR"
    ),
    GroupRule(
        rule_id="DLP-Rule-08-Financial-Record-Transfer-to-USB",
        rule_name="Financial records transferred to removable device",
        deduplication_fields=["hostname", "username"],
        source="DLP"
    ),
    GroupRule(
        rule_id="DLP-Rule-09-Source-Code-Upload-to-Pastebin",
        rule_name="Source code uploaded to public site",
        deduplication_fields=["hostname", "username"],
        deduplication_window="1h",
        source="DLP"
    ),
    GroupRule(
        rule_id="DLP-Rule-10-Health-Information-Transfer",
        rule_name="Protected health information (PHI) transfer",
        deduplication_fields=["hostname", "username", "data_classification"],
        source="DLP"
    ),
    GroupRule(
        rule_id="DLP-Rule-11-Leaked-API-Key-in-Code",
        rule_name="API key leaked",
        deduplication_fields=["hostname", "username", "repository"],
        source="DLP"
    ),
    GroupRule(
        rule_id="DLP-Rule-12-Internal-SSN-Transfer",
        rule_name="",
        deduplication_fields=["hostname", "username"],
        deduplication_window="1h",
        source="DLP"
    ),
    GroupRule(
        rule_id="ES-Rule-01-Phishing-URL-Detected",
        rule_name="Phishing URL detected in email",
        deduplication_fields=["sender_email"],
        source="Email"
    ),
    GroupRule(
        rule_id="ES-Rule-02-Malicious-Attachment-Detected",
        rule_name="Malicious attachment detected in email",
        deduplication_fields=["sender_email"],
        source="Email"
    ),
    GroupRule(
        rule_id="ES-Rule-03-BEC-Spoofing-CEO",
        rule_name="Business Email Compromise (BEC) - CEO impersonation",
        deduplication_fields=["sender_email", "subject"],
        source="Email"
    ),
    GroupRule(
        rule_id="ES-Rule-04-Credential-Phishing-Page",
        rule_name="Credential phishing page link",
        deduplication_fields=["sender_email", "subject"],
        deduplication_window="10m",
        source="Email"
    ),
    GroupRule(
        rule_id="ES-Rule-05-Fileless-Malware-Detected",
        rule_name="Fileless malware detected in email",
        deduplication_fields=["sender_email"],
        source="Email"
    ),
    GroupRule(
        rule_id="OT-Rule-01-PLC-Configuration-Change",
        rule_name="Unauthorized PLC configuration change",
        deduplication_fields=["device_id"],
        source="OT"
    ),
    GroupRule(
        rule_id="OT-Rule-02-Unusual-Protocol-Activity",
        rule_name="Suspicious protocol activity in SCADA network",
        deduplication_fields=["source_device"],
        source="OT"
    ),
    GroupRule(
        rule_id="OT-Rule-03-Controller-Stop-Command",
        rule_name="Controller received stop command",
        deduplication_fields=["device_id"],
        source="OT"
    ),
    GroupRule(
        rule_id="PROXY-Rule-01-Malware-Download-Blocked",
        rule_name="Malicious download blocked",
        deduplication_fields=["source_ip"],
        source="Proxy"
    ),
    GroupRule(
        rule_id="PROXY-Rule-02-C2-Communication-Blocked",
        rule_name="C2 communication blocked",
        deduplication_fields=["source_ip"],
        source="Proxy"
    ),
    GroupRule(
        rule_id="PROXY-Rule-03-Phishing-URL-Detected",
        rule_name="Access to phishing site blocked",
        deduplication_fields=["source_ip"],
        source="Proxy"
    ),
    GroupRule(
        rule_id="UEBA-Rule-01-Lateral-Movement-Spike",
        rule_name="Anomalous nighttime lateral movement",
        deduplication_fields=["username"],
        source="UEBA"
    ),
    GroupRule(
        rule_id="UEBA-Rule-02-Unusual-Data-Volume-Download",
        rule_name="Abnormal data exfiltration volume",
        deduplication_fields=["username", "data_destination"],
        source="UEBA"
    ),
    GroupRule(
        rule_id="UEBA-Rule-03-Account-Brute-Force-Multiple-Sources",
        rule_name="Multi-source account brute force",
        deduplication_fields=["target_username"],
        source="UEBA"
    ),
    GroupRule(
        rule_id="TI-Rule-01-Malicious-IP-Inbound",
        rule_name="Inbound connection from malicious IP",
        deduplication_fields=["destination_ip"],
        source="TI"
    ),
    GroupRule(
        rule_id="TI-Rule-02-C2-Domain-Outbound",
        rule_name="Internal host attempted connection to C2 domain",
        deduplication_fields=["destination_domain"],
        source="TI"
    ),
    GroupRule(
        rule_id="TI-Rule-03-Malicious-File-Hash-Match",
        rule_name="Internal file hash matched threat intelligence",
        deduplication_fields=["hostname"],
        source="TI"
    ),
    GroupRule(
        rule_id="IAM-Rule-01-Excessive-Permission-Grant",
        rule_name="Account permissions escalated abnormally",
        deduplication_fields=["username", "platform"],
        source="IAM"
    ),
    GroupRule(
        rule_id="IAM-Rule-02-Impossible-Travel-Login",
        rule_name="Impossible travel login",
        deduplication_fields=["username"],
        source="IAM"
    ),
    GroupRule(
        rule_id="IAM-Rule-03-Brute-Force-Attack-Password-Spraying",
        rule_name="Password spraying across multiple accounts",
        deduplication_fields=["source_ip"],
        source="IAM"
    ),
    GroupRule(
        rule_id="CLOUD-AWS-IAM-01-Root-User-Activity",
        rule_name="Root account activity",
        deduplication_fields=["platform", "service"],
        source="Cloud"
    ),
    GroupRule(
        rule_id="CLOUD-AZ-COMPUTE-02-VM-Reconnaissance",
        rule_name="Virtual machine internal reconnaissance",
        deduplication_fields=["vm_name", "vm_ip"],
        source="Cloud"
    ),
    GroupRule(
        rule_id="CLOUD-GCP-STORAGE-03-Public-Bucket-Access",
        rule_name="Public bucket access",
        deduplication_fields=["bucket_name"],
        source="Cloud"
    ),
]
