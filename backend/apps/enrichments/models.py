from django.db import models

from apps.common.models import BaseModel
from apps.common.readable_ids import save_with_readable_id


def value_labeled(choice_class):
    for member in choice_class:
        member._label_ = member.value
    return choice_class


@value_labeled
class EnrichmentType(models.TextChoices):
    UNKNOWN = "Unknown"
    OTHER = "Other"
    THREAT_INTELLIGENCE = "Threat Intelligence"
    REPUTATION = "Reputation"
    GEO_LOCATION = "Geo Location"
    WHOIS = "WHOIS"
    DNS = "DNS"
    PASSIVE_DNS = "Passive DNS"
    CERTIFICATE = "Certificate"
    SANDBOX = "Sandbox"
    MALWARE_ANALYSIS = "Malware Analysis"
    VULNERABILITY = "Vulnerability"
    EXPOSURE = "Exposure"
    ASSET = "Asset"
    CMDB = "CMDB"
    IDENTITY = "Identity"
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    BEHAVIOR = "Behavior"
    DETECTION = "Detection"
    CORRELATION = "Correlation"
    HISTORY = "History"
    REMEDIATION = "Remediation"
    OBSERVATION = "Observation"
    EXTERNAL_TICKET = "External Ticket"


@value_labeled
class EnrichmentProvider(models.TextChoices):
    UNKNOWN = "Unknown"
    OTHER = "Other"

    JIRA = "Jira"
    SERVICENOW = "ServiceNow"
    PAGERDUTY = "PagerDuty"
    SLACK = "Slack"
    ASP = "ASP"
    INTERNAL = "Internal"
    INTERNAL_CMDB = "Internal CMDB"
    INTERNAL_KNOWLEDGE_BASE = "Internal Knowledge Base"
    INTERNAL_SIRP = "Internal SIRP"
    MOCK = "Mock"
    MOCK_TI_PROVIDER = "MockTIProvider"
    ALIENVAULT_OTX = "AlienVaultOTX"
    VIRUSTOTAL = "VirusTotal"
    ABUSEIPDB = "AbuseIPDB"
    URLSCAN_IO = "urlscan.io"
    SHODAN = "Shodan"
    CENSYS = "Censys"
    GREYNOISE = "GreyNoise"
    MISP = "MISP"
    OPENCTI = "OpenCTI"
    RECORDED_FUTURE = "Recorded Future"
    MANDIANT = "Mandiant"
    CROWDSTRIKE_INTELLIGENCE = "CrowdStrike Intelligence"
    MICROSOFT_DEFENDER_THREAT_INTELLIGENCE = "Microsoft Defender Threat Intelligence"
    IBM_X_FORCE = "IBM X-Force"
    CISCO_TALOS = "Cisco Talos"
    PALO_ALTO_UNIT42 = "Palo Alto Unit 42"
    FORTIGUARD = "FortiGuard"
    CHECK_POINT_THREATCLOUD = "Check Point ThreatCloud"
    KASPERSKY = "Kaspersky"
    ESET = "ESET"
    TREND_MICRO = "Trend Micro"
    PROOFPOINT = "Proofpoint"
    FLASHPOINT = "Flashpoint"
    URLHAUS = "URLhaus"
    NVD = "NVD"
    ZEROFOX = "ZeroFox"
    DARKTRACE = "Darktrace"
    CUSTOM_YARA = "Custom YARA"
    MAXMIND = "MaxMind"
    IPINFO = "IPinfo"
    IP2LOCATION = "IP2Location"
    WHOISXMLAPI = "WhoisXML API"
    SECURITYTRAILS = "SecurityTrails"
    DOMAINTOOLS = "DomainTools"
    GOOGLE_DNS = "Google DNS"
    CLOUDFLARE_DNS = "Cloudflare DNS"
    QUAD9 = "Quad9"
    SPLUNK = "Splunk"
    ELASTIC = "Elastic"
    MICROSOFT_SENTINEL = "Microsoft Sentinel"
    IBM_QRADAR = "IBM QRadar"
    GOOGLE_CHRONICLE = "Google Chronicle"
    SUMO_LOGIC = "Sumo Logic"
    LOGRHYTHM = "LogRhythm"
    ARCSIGHT = "ArcSight"
    MICROSOFT_DEFENDER_XDR = "Microsoft Defender XDR"
    MICROSOFT_DEFENDER_FOR_ENDPOINT = "Microsoft Defender for Endpoint"
    CROWDSTRIKE = "CrowdStrike"
    CROWDSTRIKE_FALCON = "CrowdStrike Falcon"
    SENTINELONE = "SentinelOne"
    PALO_ALTO_CORTEX_XDR = "Palo Alto Cortex XDR"
    TRELLIX = "Trellix"
    CARBON_BLACK = "Carbon Black"
    VMWARE_CARBON_BLACK = "VMware Carbon Black"
    CYBEREASON = "Cybereason"
    SOPHOS = "Sophos"
    TREND_MICRO_VISION_ONE = "Trend Micro Vision One"
    MICROSOFT_ENTRA_ID = "Microsoft Entra ID"
    MICROSOFT_GRAPH = "Microsoft Graph"
    OKTA = "Okta"
    PING_IDENTITY = "Ping Identity"
    DUO = "Duo"
    CYBERARK = "CyberArk"
    SAILPOINT = "SailPoint"
    AWS_IAM = "AWS IAM"
    AZURE_IAM = "Azure IAM"
    GOOGLE_CLOUD_IAM = "Google Cloud IAM"
    KUBERNETES_API = "Kubernetes API"
    AWS = "AWS"
    AWS_CLOUDTRAIL = "AWS CloudTrail"
    AWS_GUARDDUTY = "AWS GuardDuty"
    AWS_SECURITY_HUB = "AWS Security Hub"
    AWS_INSPECTOR = "AWS Inspector"
    AZURE = "Azure"
    AZURE_ACTIVITY_LOG = "Azure Activity Log"
    MICROSOFT_DEFENDER_FOR_CLOUD = "Microsoft Defender for Cloud"
    GOOGLE_CLOUD = "Google Cloud"
    GOOGLE_SECURITY_COMMAND_CENTER = "Google Security Command Center"
    GCP_AUDIT_LOG = "GCP Audit Log"
    ORACLE_CLOUD = "Oracle Cloud"
    ALIBABA_CLOUD = "Alibaba Cloud"
    TENCENT_CLOUD = "Tencent Cloud"
    PALO_ALTO = "Palo Alto"
    FORTINET = "Fortinet"
    CHECK_POINT = "Check Point"
    CISCO = "Cisco"
    JUNIPER = "Juniper"
    ZSCALER = "Zscaler"
    CLOUDFLARE = "Cloudflare"
    AKAMAI = "Akamai"
    F5 = "F5"
    BLUECOAT = "Blue Coat"
    FORCEPOINT = "Forcepoint"
    PROOFPOINT_EMAIL_SECURITY = "Proofpoint Email Security"
    MIMECAST = "Mimecast"
    QUALYS = "Qualys"
    TENABLE = "Tenable"
    RAPID7 = "Rapid7"
    NESSUS = "Nessus"
    NEXPOSE = "Nexpose"
    WIZ = "Wiz"
    ORCA_SECURITY = "Orca Security"
    PRISMA_CLOUD = "Prisma Cloud"
    LACEWORK = "Lacework"
    CUCKOO = "Cuckoo"
    JOES_SANDBOX = "Joe Sandbox"
    ANY_RUN = "ANY.RUN"
    HYBRID_ANALYSIS = "Hybrid Analysis"
    TRIAGE = "Triage"
    CAPE = "CAPE"
    MANUAL = "MANUAL"


class Enrichment(BaseModel):
    enrichment_id = models.CharField(max_length=32, unique=True, editable=False, db_index=True, blank=True, default="", help_text="Record ID e.g. enrichment_000001 (记录 ID e.g. enrichment_000001)")
    name = models.CharField(max_length=255, blank=True, default="", help_text="Enrichment name (富化名称)")
    type = models.CharField(max_length=50, choices=EnrichmentType, default=EnrichmentType.OTHER, help_text="Enrichment type (富化类型)")
    provider = models.CharField(max_length=50, choices=EnrichmentProvider, default=EnrichmentProvider.OTHER, help_text="Enrichment provider (富化提供商)")
    uid = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Externally computed stable identifier for deduplication (外部计算的稳定唯一标识,用于去重)")
    value = models.CharField(max_length=500, blank=True, default="", help_text="Enrichment value (富化值)")
    desc = models.TextField(blank=True, default="", help_text="Enrichment summary (富化摘要)")
    data = models.JSONField(default=dict, blank=True, help_text="Detailed enrichment JSON Format (详细富化 JSON 格式)")

    case = models.ForeignKey("cases.Case", on_delete=models.CASCADE, null=True, blank=True, related_name="enrichments")
    alert = models.ForeignKey("alerts.Alert", on_delete=models.CASCADE, null=True, blank=True, related_name="enrichments")
    artifact = models.ForeignKey("artifacts.Artifact", on_delete=models.CASCADE, null=True, blank=True, related_name="enrichments")

    class Meta:
        db_table = "enrichments"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        return save_with_readable_id(self, "enrichment_id", "enrichment", *args, **kwargs)

    def __str__(self):
        return self.name or str(self.id)
