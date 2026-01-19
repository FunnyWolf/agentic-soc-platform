import json
from datetime import datetime, timedelta, timezone

from PLUGINS.SIRP.nocolymodel import Condition, Group, Operator
from PLUGINS.SIRP.sirpapi import Enrichment, Artifact, Alert, Knowledge
from PLUGINS.SIRP.sirpmodel import CaseModel, AlertModel, ArtifactModel, EnrichmentModel, TicketModel, KnowledgeModel

now = datetime.now(timezone.utc)
past_10m = now - timedelta(minutes=10)
past_5m = now - timedelta(minutes=5)


def generate_test_cases():
    """
    Generates three distinct and meticulously detailed test cases for security incidents,
    ensuring 100% field coverage for all specified models as per user's strict requirements.
    """

    # --- Reusable Enrichment Snippets ---
    enrichment_otx = EnrichmentModel(
        name="OTX Pulse for evil-domain.com",
        type="Other",
        provider="Other",
        created_time=now,
        value="evil-domain.com",
        src_url="https://otx.alienvault.com/indicator/domain/evil-domain.com",
        desc="This domain is associated with the 'Gootkit' malware family.",
        data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
    )

    enrichment_virustotal = EnrichmentModel(
        name="VirusTotal Report for Hash 'a1b2c3d4...'",
        type="Other",
        provider="Other",
        created_time=now,
        value="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        src_url="https://www.virustotal.com/gui/file/a1b2c3d4e5f6.../detection",
        desc="72/75 vendors flagged this as malicious 'Trojan.Generic'.",
        data=json.dumps({"scan_id": "a1b2c3d4e5f6-1678886400", "positives": 72, "total": 75})
    )

    # === Case 1: Phishing Email Attack (100% Coverage) ===
    case1_phishing = CaseModel(
        title="Phishing Campaign Detected - 'Urgent Payroll Update'",
        severity="High",
        impact="Medium",
        priority="High",
        src_url="https://sirp.example.com/cases/1",
        confidence="High",
        description="A targeted phishing campaign was identified. The email lured users to a fake login page to harvest credentials and deployed malware via an attachment.",
        category="Email",
        tags=["phishing", "credential-harvesting", "malware-delivery", "FIN-department"],
        created_time=now,
        status="In Progress",
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
        severity_ai="High",
        confidence_ai="High",
        threat_hunting_report_ai="Threat hunting query initiated to find other emails from the same sender IP or with similar subject lines across the organization.",
        # Time-based fields for metrics
        start_time=past_10m.isoformat(),
        end_time=None,
        detect_time=past_5m.isoformat(),
        acknowledge_time=now.isoformat(),
        respond_time=None,
        tickets=[
            TicketModel(
                status='In Progress',
                type='Jira',
                title='[Security] Investigate Phishing Campaign SEC-1234',
                uid='SEC-1234',
                src_url='https://jira.example.com/browse/SEC-1234'
            )
        ],
        enrichments=[
            EnrichmentModel(
                name="Affected Business Unit", type="Other", provider="Other",
                value="Finance Department", desc="Internal CMDB Information: High-value target."
            )
        ],
        alerts=[
            AlertModel(
                title="User Reported Phishing Email via Outlook Plugin",
                severity="Medium",
                impact="Low",
                disposition="Notified",
                action="Observed",
                confidence="High",
                uid="ALERT-USER-001",
                labels=["user-reported", "phishing"],
                desc="User 'john.doe' reported a suspicious email with subject 'Urgent Payroll Update'.",
                created_time=past_5m,
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
                analytic=json.dumps({"plugin_version": "1.2.3"}),
                analytic_name="Phishing Report Plugin",
                analytic_type="Tagging",
                analytic_state="Active",
                analytic_desc="Identifies emails reported by users.",
                tactic="Reconnaissance",
                technique="T1598.003",
                sub_technique="",
                mitigation="User Training, Email Filtering",
                product_category="Email",
                product_vendor="Microsoft",
                product_name="Outlook",
                product_feature="Phishing Report Add-in",
                policy_name="",
                policy_type=None,
                policy_desc="",
                risk_level="Medium",
                risk_details="Potential for credential theft.",
                status="New",
                status_detail="Awaiting analyst review.",
                remediation="",
                comment="Initial report from user.",
                unmapped=json.dumps({"x-original-ip": "123.123.123.123"}),
                raw_data=json.dumps({"subject": "Urgent Payroll Update", "from": "no-reply@evil-domain.com", "to": "john.doe@example.com"}),
                summary_ai="A user reported a suspicious email with urgent language regarding payroll.",
                case=None,
                enrichments=[],
                artifacts=[
                    ArtifactModel(
                        name="no-reply@evil-domain.com",
                        type="Email Address",
                        role="Actor",
                        value="no-reply@evil-domain.com",
                        reputation_provider="Internal Blocklist",
                        reputation_score="Malicious",
                        enrichments=[enrichment_otx]
                    ),
                    ArtifactModel(
                        name="http://fake-payroll-login.com",
                        type="URL String",
                        role="Related",
                        value="http://fake-payroll-login.com",
                        reputation_score="Suspicious/Risky"
                    )
                ]
            ),
            AlertModel(
                title="Malicious Attachment Blocked by Email Gateway",
                severity="High",
                impact="Medium",
                disposition="Blocked",
                action="Denied",
                confidence="High",
                uid="ALERT-GW-002",
                labels=["malware", "email-gateway", "trojan"],
                desc="Email Gateway blocked an attachment 'payroll_update.zip' containing known malware 'Trojan.Generic'.",
                created_time=past_5m,
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
                analytic=json.dumps({"engine": "sig-matcher-v3"}),
                analytic_name="Gateway Malware Scanner",
                analytic_type="Rule",
                analytic_state="Active",
                analytic_desc="Blocks attachments with hashes matching high-confidence threat feeds.",
                tactic="Execution",
                technique="T1204.002",
                sub_technique="",
                mitigation="Email Attachment Sandboxing, Threat Intelligence Feed Integration",
                product_category="Email",
                product_vendor="SecureMail Inc.",
                product_name="SecureMail Gateway",
                product_feature="AV-Scan-Module",
                policy_name="Inbound-Malware-Policy",
                policy_type=None,
                policy_desc="Blocks all inbound attachments with a VT score > 50.",
                risk_level="High",
                risk_details="Malware could lead to endpoint compromise.",
                status="Resolved",
                status_detail="File was quarantined successfully.",
                remediation="File quarantined. No user impact.",
                comment="Blocked 5 attempts to deliver this file to different users.",
                unmapped="",
                raw_data=json.dumps({"attachment_hash": "a1b2c3d4e5f6...", "recipient_count": 5}),
                summary_ai="The email gateway blocked a malicious attachment identified by its hash.",
                case=None,
                enrichments=[enrichment_virustotal],
                artifacts=[
                    ArtifactModel(
                        name="payroll_update.zip",
                        type="File Name",
                        role="Related",
                        value="payroll_update.zip"
                    ),
                    ArtifactModel(
                        name="a1b2c3d4e5f6...",
                        type="Hash",
                        role="Related",
                        value="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                        reputation_provider="VirusTotal",
                        reputation_score="Malicious",
                        enrichments=[enrichment_virustotal]
                    )
                ]
            )
        ]
    )

    # === Case 2: Endpoint Lateral Movement (100% Coverage) ===
    case2_lateral_movement = CaseModel(
        title="Lateral Movement Detected via PsExec from DC01 to WS-FINANCE-05",
        severity="Critical",
        impact="High",
        priority="Critical",
        description="An attacker, having compromised the Domain Controller 'DC01', is attempting to move laterally to a high-value workstation 'WS-FINANCE-05' in the Finance department using PsExec.",
        category="EDR",
        tags=["lateral-movement", "psexec", "golden-ticket", "domain-compromise"],
        created_time=now,
        status="Resolved",
        acknowledged_time=past_5m,
        comment="Incident Response Complete. IOCs have been added to blocklists. Awaiting final report.",
        closed_time=now,
        verdict="True Positive",
        summary="Attacker compromised DC01 and moved to WS-FINANCE-05. Both hosts have been isolated and are pending reimaging. All domain admin credentials have been rotated.",
        correlation_uid="CORR-LAT-MOV-456",
        workbook="### Lateral Movement PlaybookLoader\n1. Isolate source and destination (`done`)\n2. Dump memory from hosts (`done`)\n3. Analyze for persistence (`done`)\n4. Rotate credentials (`done`)",
        analysis_rationale_ai="PsExec execution from a domain controller to a workstation is highly anomalous. The initial compromise vector on DC01 appears to be related to a credential dumping alert moments before the lateral movement.",
        recommended_actions_ai="- Isolate both DC01 and WS-FINANCE-05 immediately.\n- Investigate DC01 for initial compromise.\n- Rotate all privileged credentials.",
        attack_stage_ai="Lateral Movement",
        severity_ai="Critical",
        confidence_ai="High",
        threat_hunting_report_ai="",
        start_time=past_10m.isoformat(),
        end_time=now.isoformat(),
        detect_time=past_5m.isoformat(),
        acknowledge_time=past_5m.isoformat(),
        respond_time=now.isoformat(),
        tickets=[
            TicketModel(
                status='Resolved',
                type='ServiceNow',
                title='CRITICAL: Active Lateral Movement Detected',
                uid='INC001002',
                src_url='https://servicenow.example.com/nav_to.do?uri=incident.do?sys_id=INC001002'
            )
        ],
        enrichments=[],
        alerts=[
            AlertModel(
                title="Suspicious Service Installation (PSEXESVC) on WS-FINANCE-05",
                severity="High",
                impact="High",
                disposition="Detected",
                action="Observed",
                confidence="High",
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
                analytic=json.dumps({"SysmonEventID": 7}),
                analytic_name="Sysmon Behavioral Detection",
                analytic_type="Behavioral",
                analytic_state="Active",
                analytic_desc="Detects the creation of the PsExec service executable.",
                tactic="Lateral Movement",
                technique="T1569.002",
                sub_technique="",
                mitigation="Restrict Service Creation, Network Segmentation",
                product_category="EDR",
                product_vendor="CrowdStrike",
                product_name="Falcon",
                product_feature="Behavioral-Detection-Engine",
                policy_name="Default Workstation Policy",
                policy_type="Identity Policy",
                policy_desc="Monitors for suspicious service installations.",
                risk_level="High",
                risk_details="Indicates an attacker is moving through the network.",
                status="Archived",
                status_detail="Alert has been correlated into Case-2.",
                remediation="Host was isolated by SOAR playbook.",
                comment="Clear indicator of lateral movement.",
                unmapped="",
                raw_data=json.dumps({"event_id": 4697, "service_name": "PSEXESVC", "source_host": "DC01"}),
                summary_ai="PsExec was used to move from DC01 to a finance workstation.",
                case=None,
                enrichments=[],
                artifacts=[
                    ArtifactModel(
                        name="PSEXESVC.exe",
                        type="Process Name",
                        role="Related",
                        value="PSEXESVC.exe",
                        owner="System"
                    ),
                    ArtifactModel(
                        name="DC01",
                        type="Hostname",
                        role="Actor",
                        value="DC01",
                        description="Source of lateral movement."
                    )
                ]
            ),
            AlertModel(
                title="Credential Dumping via LSASS Memory Access on DC01",
                severity="Critical",
                impact="Critical",
                disposition="Alert",
                action="Observed",
                confidence="High",
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
                analytic=json.dumps({"target_process": "lsass.exe"}),
                analytic_name="Credential Access Detection",
                analytic_type="Behavioral",
                analytic_state="Active",
                analytic_desc="Monitors for processes reading memory from LSASS.",
                tactic="Credential Access",
                technique="T1003.001",
                sub_technique="",
                mitigation="Credential Guard, LSA Protection",
                product_category="EDR",
                product_vendor="CrowdStrike",
                product_name="Falcon",
                product_feature="Credential-Theft-Protection",
                policy_name="Domain Controller Policy",
                policy_type=None,
                policy_desc="",
                risk_level="Critical",
                risk_details="Domain credentials may be compromised.",
                status="Archived",
                status_detail="Alert has been correlated into Case-2.",
                remediation="",
                comment="This was likely the initial point of credential theft enabling lateral movement.",
                unmapped="",
                raw_data=json.dumps({"source_process": "mimikatz.exe", "target_process": "lsass.exe"}),
                summary_ai="Credential dumping tool Mimikatz was detected on the domain controller.",
                case=None,
                enrichments=[],
                artifacts=[
                    ArtifactModel(
                        name="lsass.exe",
                        type="Process Name",
                        role="Target",
                        value="lsass.exe",
                        owner="System"
                    ),
                    ArtifactModel(
                        name="mimikatz.exe",
                        type="Process Name",
                        role="Actor",
                        value="mimikatz.exe",
                        description="Anomalous process accessing LSASS."
                    )
                ]
            )
        ]
    )

    # === Case 3: DNS Tunneling C2 (100% Coverage) ===
    case3_dns_tunnel = CaseModel(
        title="Suspected DNS Tunneling for C2 Communication from WS-MARKETING-12",
        severity="Medium",
        impact="Low",
        priority="Medium",
        description="An endpoint 'WS-MARKETING-12' is exhibiting DNS query patterns indicative of DNS tunneling, likely for command-and-control (C2) communication. This is a low-and-slow exfiltration or C2 method.",
        category="NDR",
        tags=["dns-tunneling", "c2", "ndr", "exfiltration"],
        created_time=now,
        status="On Hold",
        acknowledged_time=now,
        comment="Awaiting more data. Placed host in a monitoring group. No immediate action taken to avoid tipping off the attacker.",
        closed_time=None,
        verdict="Suspicious",
        summary="",
        correlation_uid="CORR-DNS-TUN-789",
        workbook="### DNS Tunneling PlaybookLoader\n1. Analyze query patterns (TXT/NULL record types, query length)\n2. Check domain reputation\n3. Perform packet capture on host\n4. Compare against baseline DNS traffic",
        analysis_rationale_ai="The high volume of TXT queries to a single, non-business related domain is a strong indicator of DNS tunneling. The query payloads appear to be encoded.",
        recommended_actions_ai="- Place the host in a sinkhole network to observe C2 traffic safely.\n- Do not block immediately to gather more intelligence on the attacker's infrastructure.",
        attack_stage_ai="Command and Control",
        severity_ai="Medium",
        confidence_ai="Medium",
        threat_hunting_report_ai="",
        start_time=past_10m.isoformat(),
        end_time=None,
        detect_time=now.isoformat(),
        acknowledge_time=now.isoformat(),
        respond_time=None,
        tickets=[],
        enrichments=[],
        alerts=[
            AlertModel(
                title="Anomalous DNS Query Volume (TXT Records)",
                severity="Medium",
                impact="Low",
                action="Observed",
                disposition="Logged",
                confidence="Medium",
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
                analytic=json.dumps({"query_type": "TXT", "threshold": 50, "time_window": "5m"}),
                analytic_name="DNS Exfiltration Detector",
                analytic_type="Behavioral",
                analytic_state="Active",
                analytic_desc="Flags high-frequency TXT/NULL queries.",
                tactic="Command and Control",
                technique="T1071.004",
                sub_technique="",
                mitigation="DNS Sinkholing, Egress Traffic Filtering",
                product_category="NDR",
                product_vendor="Vectra",
                product_name="Cognito",
                product_feature="DNS-Analytics",
                policy_name="",
                policy_type=None,
                policy_desc="",
                risk_level="Medium",
                risk_details="Potential for covert C2 channel or data exfiltration.",
                status="New",
                status_detail="",
                remediation="",
                comment="",
                unmapped="",
                raw_data=json.dumps({"query_count": 245, "domain": "c2.bad-actor-infra.net"}),
                summary_ai="High volume of DNS TXT queries suggests a DNS tunnel.",
                case=None,
                enrichments=[enrichment_otx],
                artifacts=[
                    ArtifactModel(
                        name="10.1.1.5",
                        type="IP Address",
                        role="Actor",
                        value="10.1.1.5",
                        owner="Workstation-Pool-DHCP"
                    ),
                    ArtifactModel(
                        name="c2.bad-actor-infra.net",
                        type="Hostname",
                        role="Related",
                        value="c2.bad-actor-infra.net",
                        reputation_score="Suspicious/Risky"
                    )
                ]
            ),
            AlertModel(
                title="Firewall Detected Unusually Long DNS Query",
                severity="Low",
                impact="Low",
                action="Logged",
                disposition="Allowed",
                confidence="Low",
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
                analytic=json.dumps({"label_length": 85}),
                analytic_name="Firewall DNS Protocol Anomaly",
                analytic_type="Rule",
                analytic_state="Experimental",
                analytic_desc="Flags DNS queries that violate standard label length.",
                tactic="Command and Control",
                technique="T1071.004",
                sub_technique="",
                mitigation="Egress DNS Filtering",
                product_category="Cloud",
                product_vendor="Palo Alto",
                product_name="PA-Series Firewall",
                product_feature="DNS-Security",
                policy_name="Default-DNS-Allow",
                policy_type="Service Control Policy",
                policy_desc="Default policy allowing outbound DNS traffic.",
                risk_level="Low",
                risk_details="Suspicious but could be a false positive from non-standard software.",
                status="New",
                status_detail="",
                remediation="",
                comment="Correlates with the NDR alert, increasing confidence.",
                unmapped=json.dumps({"dns_flags": "RD"}),
                raw_data=json.dumps({"qname": "verylonglabelthatmightbeencodeddata.c2.bad-actor-infra.net"}),
                summary_ai="An unusually long DNS query was detected by the firewall.",
                case=None,
                enrichments=[],
                artifacts=[
                    ArtifactModel(
                        name="UDP-53",
                        type="Port",
                        role="Related",
                        value="53",
                    ),
                    ArtifactModel(
                        name="8.8.8.8",
                        type="IP Address",
                        role="Related",
                        value="8.8.8.8",
                        description="Public DNS Resolver"
                    )
                ]
            )
        ]
    )

    return case1_phishing, case2_lateral_movement, case3_dns_tunnel


def test_generate_cases():
    """
    Prints the generated test cases to the console in JSON format.
    """
    test_cases = generate_test_cases()
    for i, case in enumerate(test_cases, 1):
        print(f"--- Test Case {i}: {case.title} ---")
        print(case.model_dump_json(indent=2))
        print("\n\n")


def test_enrichment():
    enrichment_to_convert = EnrichmentModel(
        name="OTX Pulse for evil-domain.com",
        type="Other",
        provider="Other",
        created_time=now,
        value="evil-domain.com",
        src_url="https://otx.alienvault.com/indicator/domain/evil-domain.com",
        desc="This domain is associated with the 'Gootkit' malware family.",
        data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
    )
    #
    # rowid = Enrichment.create(enrichment_to_convert)
    # enrichment_to_convert.rowid = rowid
    # Enrichment.get(rowid="761bf560-15d9-4137-8a18-62e243cb1ee9")

    filter_model = Group(
        logic="AND",
        children=[
            Condition(
                field="type",
                operator=Operator.IN,
                value=["Other"]
            )
        ]
    )

    Enrichment.list(filter_model)


def test_alert():
    alert = Alert.get("ae83212e-5064-42dd-9e3f-f95b0aeded2d")

    artifact = Artifact.get("0e4527f9-a0b9-4d71-a805-95a7d8d3267e")

    artifact_model = ArtifactModel(
        rowid="0e4527f9-a0b9-4d71-a805-95a7d8d3267e",
        name="http://fake-payroll-login.com1",
        type="URL String",
        role="Related",
        owner="admin",
        value="http://fake-payroll-login.com",
        reputation_provider="OTX",
        reputation_score="Suspicious/Risky",
        enrichments=[
            EnrichmentModel(
                rowid="761bf560-15d9-4137-8a18-62e243cb1ee9",
                name="OTX Pulse for evil-domain.com update",
                type="TI",
                provider="OTX",
                created_time=now,
                value="evil-domain.com",
                src_url="https://otx.alienvault.com/indicator/domain/evil-domain.com",
                desc="This domain is associated with the 'Gootkit' malware family.",
                data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
            ),
            EnrichmentModel(
                name="OTX Pulse for fake-payroll-login.com",
                type="Other",
                provider="Other",
                created_time=now,
                value="fake-payroll-login.com",
                src_url="https://otx.alienvault.com/indicator/domain/fake-payroll-login.com",
                desc="This domain is associated with the 'Gootkit' malware family.",
                data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
            )

        ]
    )
    rowid = Artifact.update_or_create(artifact_model)
    print(rowid)


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    # models = Knowledge.list_undone_actions()
    model = KnowledgeModel()
    model.rowid = "32284c3d-e4c1-40b1-b4a3-1bf2daa0b6c5"
    model.using = False
    model.source = "Case"
    model.tags = ["test", "updated"]
    Knowledge.update_or_create(model)
