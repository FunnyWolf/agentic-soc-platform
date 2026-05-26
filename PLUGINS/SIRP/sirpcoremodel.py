from __future__ import annotations

from enum import StrEnum
from typing import Optional, List, Union, Any

from pydantic import Field

from PLUGINS.SIRP.sirpbasemodel import (
    BaseSystemModel,
    AutoDatetime,
    AutoAccount,
    AI_PROFILE_INVESTIGATION,
    AI_PROFILE_MCP,
)


class ArtifactType(StrEnum):
    UNKNOWN = 'Unknown'
    HOSTNAME = 'Hostname'
    IP_ADDRESS = 'IP Address'
    MAC_ADDRESS = 'MAC Address'
    USER_NAME = 'User Name'
    EMAIL_ADDRESS = 'Email Address'
    URL_STRING = 'URL String'
    FILE_NAME = 'File Name'
    HASH = 'Hash'
    PROCESS_NAME = 'Process Name'
    RESOURCE_UID = 'Resource UID'
    PORT = 'Port'
    SUBNET = 'Subnet'
    COMMAND_LINE = 'Command Line'
    COUNTRY = 'Country'
    PROCESS_ID = 'Process ID'
    HTTP_USER_AGENT = 'HTTP User-Agent'
    CWE = 'CWE'
    CVE = 'CVE'
    USER_CREDENTIAL_ID = 'User Credential ID'
    ENDPOINT = 'Endpoint'
    USER = 'User'
    EMAIL = 'Email'
    UNIFORM_RESOURCE_LOCATOR = 'Uniform Resource Locator'
    FILE = 'File'
    PROCESS = 'Process'
    GEO_LOCATION = 'Geo Location'
    CONTAINER = 'Container'
    REGISTRY = 'Registry'
    FINGERPRINT = 'Fingerprint'
    GROUP = 'Group'
    ACCOUNT = 'Account'
    SCRIPT_CONTENT = 'Script Content'
    SERIAL_NUMBER = 'Serial Number'
    RESOURCE = 'Resource'
    MESSAGE = 'Message'
    ADVISORY = 'Advisory'
    FILE_PATH = 'File Path'
    DEVICE = 'Device'
    REGISTRY_PATH = "Registry Path"
    OTHER = 'Other'


class ArtifactName(StrEnum):
    UNKNOWN = "Unknown"
    OTHER = "Other"

    # Generic relationship names, aligned with OCSF/ECS/CIM/ASIM semantics.
    SOURCE = "Source"
    DESTINATION = "Destination"
    CLIENT = "Client"
    SERVER = "Server"
    ACTOR = "Actor"
    TARGET = "Target"
    AFFECTED = "Affected"
    RELATED = "Related"
    OBSERVED = "Observed"
    REQUEST = "Request"
    RESPONSE = "Response"

    # Network / HTTP / DNS.
    SOURCE_IP = "Source IP"
    DESTINATION_IP = "Destination IP"
    CLIENT_IP = "Client IP"
    SERVER_IP = "Server IP"
    REMOTE_IP = "Remote IP"
    LOCAL_IP = "Local IP"
    NAT_IP = "NAT IP"
    PROXY_IP = "Proxy IP"
    FORWARDED_IP = "Forwarded IP"
    DNS_SERVER_IP = "DNS Server IP"
    DHCP_SERVER_IP = "DHCP Server IP"
    VPN_IP = "VPN IP"
    SOURCE_PORT = "Source Port"
    DESTINATION_PORT = "Destination Port"
    CLIENT_PORT = "Client Port"
    SERVER_PORT = "Server Port"
    SOURCE_MAC = "Source MAC"
    DESTINATION_MAC = "Destination MAC"
    DEVICE_MAC = "Device MAC"
    DOMAIN = "Domain"
    SOURCE_DOMAIN = "Source Domain"
    DESTINATION_DOMAIN = "Destination Domain"
    REQUEST_DOMAIN = "Request Domain"
    DNS_QUERY_NAME = "DNS Query Name"
    DNS_ANSWER = "DNS Answer"
    DNS_RECORD = "DNS Record"
    URL = "URL"
    REQUEST_URL = "Request URL"
    REFERRER_URL = "Referrer URL"
    REDIRECT_URL = "Redirect URL"
    LANDING_URL = "Landing URL"
    PHISHING_URL = "Phishing URL"
    CALLBACK_URL = "Callback URL"
    DOWNLOAD_URL = "Download URL"
    HTTP_METHOD = "HTTP Method"
    HTTP_USER_AGENT = "HTTP User-Agent"
    HTTP_HOST = "HTTP Host"
    HTTP_PATH = "HTTP Path"
    HTTP_QUERY = "HTTP Query"
    HTTP_STATUS_CODE = "HTTP Status Code"
    HTTP_REQUEST_BODY = "HTTP Request Body"
    HTTP_RESPONSE_BODY = "HTTP Response Body"

    # Identity / account.
    USER = "User"
    USER_NAME = "User Name"
    USER_ID = "User ID"
    USER_SID = "User SID"
    USER_UPN = "User UPN"
    USER_EMAIL = "User Email"
    SOURCE_USER = "Source User"
    DESTINATION_USER = "Destination User"
    ACTOR_USER = "Actor User"
    TARGET_USER = "Target User"
    AFFECTED_USER = "Affected User"
    EXECUTING_USER = "Executing User"
    LOGON_USER = "Logon User"
    LOGIN_USER = "Login User"
    PRINCIPAL_USER = "Principal User"
    INITIATING_USER = "Initiating User"
    REQUESTING_USER = "Requesting User"
    OWNER_USER = "Owner User"
    ACCOUNT = "Account"
    ACCOUNT_ID = "Account ID"
    ACCOUNT_NAME = "Account Name"
    SERVICE_ACCOUNT = "Service Account"
    ADMIN_ACCOUNT = "Admin Account"
    CLOUD_ACCOUNT = "Cloud Account"
    AWS_ACCOUNT_ID = "AWS Account ID"
    AZURE_TENANT_ID = "Azure Tenant ID"
    AZURE_SUBSCRIPTION_ID = "Azure Subscription ID"
    GCP_PROJECT_ID = "GCP Project ID"
    CREDENTIAL_ID = "Credential ID"
    ACCESS_KEY_ID = "Access Key ID"
    API_KEY_ID = "API Key ID"
    TOKEN_ID = "Token ID"
    SESSION_ID = "Session ID"

    # Host / device / asset.
    HOST = "Host"
    HOSTNAME = "Hostname"
    HOST_ID = "Host ID"
    SOURCE_HOST = "Source Host"
    DESTINATION_HOST = "Destination Host"
    AFFECTED_HOST = "Affected Host"
    TARGET_HOST = "Target Host"
    DEVICE = "Device"
    DEVICE_ID = "Device ID"
    DEVICE_NAME = "Device Name"
    ENDPOINT = "Endpoint"
    ENDPOINT_ID = "Endpoint ID"
    ASSET_ID = "Asset ID"
    AGENT_ID = "Agent ID"
    SENSOR_ID = "Sensor ID"
    OPERATING_SYSTEM = "Operating System"
    HOST_OS = "Host OS"
    HOST_IP = "Host IP"
    HOST_MAC = "Host MAC"
    HOST_SERIAL_NUMBER = "Host Serial Number"

    # Process.
    PROCESS = "Process"
    PROCESS_NAME = "Process Name"
    PROCESS_ID = "Process ID"
    PROCESS_PATH = "Process Path"
    PROCESS_EXECUTABLE = "Process Executable"
    PROCESS_COMMAND_LINE = "Process Command Line"
    PROCESS_HASH = "Process Hash"
    PARENT_PROCESS = "Parent Process"
    PARENT_PROCESS_NAME = "Parent Process Name"
    PARENT_PROCESS_ID = "Parent Process ID"
    PARENT_PROCESS_PATH = "Parent Process Path"
    PARENT_PROCESS_COMMAND_LINE = "Parent Process Command Line"
    PARENT_PROCESS_HASH = "Parent Process Hash"
    CHILD_PROCESS = "Child Process"
    CHILD_PROCESS_NAME = "Child Process Name"
    CHILD_PROCESS_ID = "Child Process ID"
    CHILD_PROCESS_COMMAND_LINE = "Child Process Command Line"
    ACTING_PROCESS = "Acting Process"
    TARGET_PROCESS = "Target Process"
    INJECTED_PROCESS = "Injected Process"

    # File.
    FILE = "File"
    FILE_NAME = "File Name"
    FILE_PATH = "File Path"
    FILE_EXTENSION = "File Extension"
    FILE_DIRECTORY = "File Directory"
    FILE_SIZE = "File Size"
    FILE_HASH = "File Hash"
    FILE_MD5 = "File MD5"
    FILE_SHA1 = "File SHA1"
    FILE_SHA256 = "File SHA256"
    FILE_SHA512 = "File SHA512"
    FILE_IMPHASH = "File Imphash"
    FILE_SIGNATURE = "File Signature"
    FILE_PUBLISHER = "File Publisher"
    FILE_OWNER = "File Owner"
    DOWNLOAD_FILE = "Download File"
    ATTACHMENT_FILE = "Attachment File"
    DROPPED_FILE = "Dropped File"
    TARGET_FILE = "Target File"

    # Email.
    EMAIL = "Email"
    SENDER_EMAIL = "Sender Email"
    RECIPIENT_EMAIL = "Recipient Email"
    CC_EMAIL = "CC Email"
    BCC_EMAIL = "BCC Email"
    REPLY_TO_EMAIL = "Reply-To Email"
    RETURN_PATH_EMAIL = "Return-Path Email"
    MAIL_FROM = "Mail From"
    MAIL_TO = "Mail To"
    MAIL_SUBJECT = "Mail Subject"
    MAIL_MESSAGE_ID = "Mail Message ID"
    MAIL_ATTACHMENT = "Mail Attachment"
    MAIL_URL = "Mail URL"
    MAIL_DOMAIN = "Mail Domain"
    SENDER_DOMAIN = "Sender Domain"
    RECIPIENT_DOMAIN = "Recipient Domain"

    # Cloud / IAM.
    CLOUD_RESOURCE = "Cloud Resource"
    CLOUD_RESOURCE_ID = "Cloud Resource ID"
    CLOUD_RESOURCE_NAME = "Cloud Resource Name"
    CLOUD_RESOURCE_ARN = "Cloud Resource ARN"
    CLOUD_REGION = "Cloud Region"
    CLOUD_ZONE = "Cloud Zone"
    CLOUD_SERVICE = "Cloud Service"
    CLOUD_ROLE = "Cloud Role"
    CLOUD_POLICY = "Cloud Policy"
    CLOUD_POLICY_ARN = "Cloud Policy ARN"
    CLOUD_INSTANCE_ID = "Cloud Instance ID"
    CLOUD_BUCKET = "Cloud Bucket"
    CLOUD_STORAGE_OBJECT = "Cloud Storage Object"
    CLOUD_FUNCTION = "Cloud Function"
    CLOUD_TRAIL_EVENT_ID = "CloudTrail Event ID"
    CLOUD_REQUEST_ID = "Cloud Request ID"
    IAM_USER = "IAM User"
    IAM_ROLE = "IAM Role"
    IAM_GROUP = "IAM Group"
    IAM_POLICY = "IAM Policy"
    IAM_POLICY_ARN = "IAM Policy ARN"
    IAM_PERMISSION = "IAM Permission"
    IAM_ACTION = "IAM Action"
    IAM_RESOURCE = "IAM Resource"
    ASSUMED_ROLE = "Assumed Role"
    ACCESS_KEY = "Access Key"
    SECRET_KEY_ID = "Secret Key ID"
    PERMISSION_SET = "Permission Set"

    # Windows / registry.
    REGISTRY_KEY = "Registry Key"
    REGISTRY_VALUE = "Registry Value"
    REGISTRY_PATH = "Registry Path"
    REGISTRY_DATA = "Registry Data"
    WINDOWS_SERVICE = "Windows Service"
    SCHEDULED_TASK = "Scheduled Task"
    WMI_OBJECT = "WMI Object"
    COM_OBJECT = "COM Object"
    NAMED_PIPE = "Named Pipe"
    MUTEX = "Mutex"

    # Container / Kubernetes.
    CONTAINER = "Container"
    CONTAINER_ID = "Container ID"
    CONTAINER_NAME = "Container Name"
    CONTAINER_IMAGE = "Container Image"
    CONTAINER_IMAGE_ID = "Container Image ID"
    POD = "Pod"
    POD_NAME = "Pod Name"
    NAMESPACE = "Namespace"
    KUBERNETES_CLUSTER = "Kubernetes Cluster"
    KUBERNETES_NODE = "Kubernetes Node"
    KUBERNETES_SERVICE_ACCOUNT = "Kubernetes Service Account"

    # Vulnerability / threat intelligence.
    CVE = "CVE"
    CWE = "CWE"
    CPE = "CPE"
    CVSS_SCORE = "CVSS Score"
    VULNERABLE_PRODUCT = "Vulnerable Product"
    MALWARE_NAME = "Malware Name"
    MALWARE_FAMILY = "Malware Family"
    THREAT_ACTOR = "Threat Actor"
    THREAT_CAMPAIGN = "Threat Campaign"
    ATTACK_TECHNIQUE = "Attack Technique"
    ATTACK_TACTIC = "Attack Tactic"
    IOC = "IOC"
    YARA_RULE = "YARA Rule"
    SIGMA_RULE = "Sigma Rule"


class ArtifactRole(StrEnum):
    UNKNOWN = 'Unknown'
    TARGET = 'Target'
    ACTOR = 'Actor'
    AFFECTED = 'Affected'
    RELATED = 'Related'
    OTHER = 'Other'


class Severity(StrEnum):
    UNKNOWN = "Unknown"
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AttackStage(StrEnum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class Impact(StrEnum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Disposition(StrEnum):
    UNKNOWN = "Unknown"
    ALLOWED = "Allowed"
    BLOCKED = "Blocked"
    QUARANTINED = "Quarantined"
    ISOLATED = "Isolated"
    DELETED = "Deleted"
    DROPPED = "Dropped"
    CUSTOM_ACTION = "Custom Action"
    APPROVED = "Approved"
    RESTORED = "Restored"
    EXONERATED = "Exonerated"
    CORRECTED = "Corrected"
    PARTIALLY_CORRECTED = "Partially Corrected"
    UNCORRECTED = "Uncorrected"
    DELAYED = "Delayed"
    DETECTED = "Detected"
    NO_ACTION = "No Action"
    LOGGED = "Logged"
    TAGGED = "Tagged"
    ALERT = "Alert"
    COUNT = "Count"
    RESET = "Reset"
    CAPTCHA = "Captcha"
    CHALLENGE = "Challenge"
    ACCESS_REVOKED = "Access Revoked"
    REJECTED = "Rejected"
    UNAUTHORIZED = "Unauthorized"
    ERROR = "Error"
    OTHER = "Other"


class AlertAction(StrEnum):
    UNKNOWN = "Unknown"
    ALLOWED = "Allowed"
    DENIED = "Denied"
    OBSERVED = "Observed"
    MODIFIED = "Modified"
    OTHER = "Other"


class Confidence(StrEnum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class AlertAnalyticType(StrEnum):
    UNKNOWN = "Unknown"
    RULE = "Rule"
    BEHAVIORAL = "Behavioral"
    STATISTICAL = "Statistical"
    LEARNING = "Learning (ML/DL)"
    FINGERPRINTING = "Fingerprinting"
    TAGGING = "Tagging"
    KEYWORD_MATCH = "Keyword Match"
    REGULAR_EXPRESSIONS = "Regular Expressions"
    EXACT_DATA_MATCH = "Exact Data Match"
    PARTIAL_DATA_MATCH = "Partial Data Match"
    INDEXED_DATA_MATCH = "Indexed Data Match"
    OTHER = "Other"


class AlertAnalyticState(StrEnum):
    UNKNOWN = "Unknown"
    ACTIVE = "Active"
    SUPPRESSED = "Suppressed"
    EXPERIMENTAL = "Experimental"
    OTHER = "Other"


class ProductCategory(StrEnum):
    DLP = "DLP"
    EMAIL = "Email"
    OT = "OT"
    PROXY = "Proxy"
    UEBA = "UEBA"
    TI = "ThreatIntelligence"
    IAM = "IAM"
    EDR = "EDR"
    NDR = "NDR"
    CLOUD = "Cloud"
    SIEM = "SIEM"
    WAF = "WAF"
    OTHER = "Other"


class AlertPolicyType(StrEnum):
    IDENTITY_POLICY = "Identity Policy"
    RESOURCE_POLICY = "Resource Policy"
    SERVICE_CONTROL_POLICY = "Service Control Policy"
    ACCESS_CONTROL_POLICY = "Access Control Policy"
    OTHER = "Other"


class AlertRiskLevel(StrEnum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    OTHER = "Other"


class AlertStatus(StrEnum):
    UNKNOWN = "Unknown"
    NEW = "New"
    IN_PROGRESS = "In Progress"
    SUPPRESSED = "Suppressed"
    RESOLVED = "Resolved"
    ARCHIVED = "Archived"
    DELETED = "Deleted"
    OTHER = "Other"


class CasePriority(StrEnum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    OTHER = "Other"


class CaseStatus(StrEnum):
    NEW = "New"
    IN_PROGRESS = "In Progress"
    ON_HOLD = "On Hold"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


class CaseVerdict(StrEnum):
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


class EnrichmentType(StrEnum):
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


class EnrichmentProvider(StrEnum):
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
    MCP = "MCP"

class EnrichmentModel(BaseSystemModel):
    """结构化的内联增强数据,通过添加更多相关细节或上下文来增强或补充与 Artifact/Alert/Case 关联的信息。"""
    id: Optional[str] = Field(default=None,
                              init=False,
                              description="Record ID e.g. enrichment_000001 (记录 ID e.g. enrichment_000001)",
                              json_schema_extra={"ai": [AI_PROFILE_MCP]})
    name: Optional[str] = Field(default="",
                                description="Enrichment name (富化名称)",
                                json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    type: Optional[EnrichmentType] = Field(default=EnrichmentType.OTHER,
                                           description="Enrichment type (富化类型)",
                                           json_schema_extra={"type": 2, "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    provider: Optional[EnrichmentProvider] = Field(default=EnrichmentProvider.OTHER,
                                                   description="Enrichment provider (富化提供商)",
                                                   json_schema_extra={"type": 2, "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    # uid: 开发者按需赋值的外部稳定标识,用于去重和查找.
    #   计算方式: 根据外部数据自行计算,如 'cmdb:{record_id}', 或工单名+类型+ID的 hash.
    #   去重逻辑: Enrichment.create() 优先按 uid 去重,未赋值时回退到 type+provider+value.
    #   查找方式: Enrichment.get_by_uid(uid)
    uid: Optional[str] = Field(default="",
                                description="Externally computed stable identifier for deduplication (外部计算的稳定唯一标识,用于去重)")

    value: Optional[str] = Field(default="",
                                 description="Enrichment value (富化值)",
                                 json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    desc: Optional[str] = Field(default="",
                                description="Enrichment summary (富化摘要)",
                                json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    data: Optional[str] = Field(default="",
                                description="Detailed enrichment JSON Format (详细富化 JSON 格式)")


class ArtifactModel(BaseSystemModel):
    """Entity information extracted from alerts, the minimum investigate unit"""
    # 系统自动生成字段
    id: Optional[str] = Field(default=None,
                              init=False,
                              description="Record ID e.g. artifact_000001 (记录 ID e.g. artifact_000001)",
                              json_schema_extra={"ai": [AI_PROFILE_MCP]})

    # 创建记录填写字段
    name: Optional[ArtifactName] = Field(default=ArtifactName.UNKNOWN,
                                         description="Artifact name (实体名称)",
                                         json_schema_extra={"type": 2, "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    type: Optional[ArtifactType] = Field(default=None,
                                         description="Artifact type (实体类型)",
                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    role: Optional[ArtifactRole] = Field(default=None,
                                         description="Artifact role in event (实体在事件中的角色)",
                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    value: Optional[str] = Field(default="",
                                 description="Artifact value (实体值)",
                                 json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    owner: Optional[str] = Field(default="",
                                 description="Owning system or user (所属系统或用户)",
                                 json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})



    # 反向关联,无需手动处理
    alerts: Optional[List[Union[AlertModel, str]]] = Field(default=None, init=False, description="Linked alert row_ids (关联告警行 IDs)")

    # 关联表
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None,
                                                                     description="Enrichments information (富化信息)",
                                                                     json_schema_extra={
                                                                         "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})  # None 时表示无需处理,[] 时表示要将 link 清空


class AlertModel(BaseSystemModel):
    """基础告警信息,通常与SIEM Rule 产生的告警进行映射, 是连接 SIEM 告警与 SIRP 案件的核心数据模型"""
    # 系统自动生成字段
    id: Optional[str] = Field(default=None, init=False,
                              description="Record ID e.g. alert_000001, auto-generated, no manual input needed (记录 ID e.g. alert_000001, 系统自动生成,无需手动赋值)",
                              json_schema_extra={"ai": [AI_PROFILE_MCP]})

    # 创建记录填写字段
    title: Optional[str] = Field(default="",
                                 description="Alert title (告警标题)",
                                 json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    severity: Optional[Severity] = Field(default=Severity.UNKNOWN,
                                         description="Source-defined severity (告警来源定义的严重程度)",
                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    confidence: Optional[Confidence] = Field(default=Confidence.UNKNOWN,
                                             description="True-positive confidence (真阳性置信度)",
                                             json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    impact: Optional[Impact] = Field(default=Impact.UNKNOWN,
                                     description="Potential impact (告警潜在影响)",
                                     json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    disposition: Optional[Disposition] = Field(default=Disposition.UNKNOWN,
                                               description="Source disposition (告警源处置结果)",
                                               json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    action: Optional[AlertAction] = Field(default=AlertAction.UNKNOWN,
                                          description="Observed action (告警源的动作)",
                                          json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    labels: Optional[List[str]] = Field(default=[],
                                        description="Alert labels (告警标签)",
                                        json_schema_extra={"type": 2, "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    desc: Optional[str] = Field(default="",
                                description="Alert description (告警描述)",
                                json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    first_seen_time: Optional[AutoDatetime] = Field(default=None,
                                                    description="First observed time (首次观测时间)",
                                                    json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    last_seen_time: Optional[AutoDatetime] = Field(default=None,
                                                   description="Last observed time (最后观测时间)",
                                                   json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    rule_id: Optional[str] = Field(default="",
                                   description="SIEM rule ID (SIEM 规则 ID)",
                                   json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    rule_name: Optional[str] = Field(default="",
                                     description="SIEM rule name (SIEM 规则名称)",
                                     json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    correlation_uid: Optional[str] = Field(default="",
                                           description="Case correlation ID, alerts with the same correlation_uid are linked to the same event (事件关联 ID,相同 correlation_uid 告警关联到同一个事件)",
                                           json_schema_extra={"ai": [AI_PROFILE_MCP]})

    src_url: Optional[str] = Field(default="",
                                   description="Source alert URL (原始告警 URL)",
                                   json_schema_extra={"ai": [AI_PROFILE_MCP]})
    source_uid: Optional[str] = Field(default="",
                                      description="Source product ID, can be used to locate the unique alert in the source system (原始告警 唯一ID, 可通过该 ID 在原始来源中定位唯一告警)",
                                      json_schema_extra={"ai": [AI_PROFILE_MCP]})
    data_sources: Optional[List[str]] = Field(default=[],
                                              description="Underlying data sources (告警源生成告警的数据来源列表)",
                                              json_schema_extra={"ai": [AI_PROFILE_MCP]})

    analytic_name: Optional[str] = Field(default="",
                                         description="Analytic engine name (分析引擎名称)",
                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    analytic_type: Optional[AlertAnalyticType] = Field(default=AlertAnalyticType.UNKNOWN,
                                                       description="Analytic engine type (分析引擎类型)",
                                                       json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    analytic_state: Optional[AlertAnalyticState] = Field(default=None,
                                                         description="Analytic rule state (分析规则状态)",
                                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    analytic_desc: Optional[str] = Field(default="",
                                         description="Analytic rule description (分析规则描述)",
                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    tactic: Optional[str] = Field(default="",
                                  description="Mapped MITRE tactic (映射的 MITRE 战术)",
                                  json_schema_extra={"ai": [AI_PROFILE_MCP]})
    technique: Optional[str] = Field(default="",
                                     description="Mapped MITRE technique (映射的 MITRE 技术)",
                                     json_schema_extra={"ai": [AI_PROFILE_MCP]})
    sub_technique: Optional[str] = Field(default="",
                                         description="Mapped MITRE sub-technique (映射的 MITRE 子技术)",
                                         json_schema_extra={"ai": [AI_PROFILE_MCP]})
    mitigation: Optional[str] = Field(default="",
                                      description="Suggested mitigation (建议的缓解措施)",
                                      json_schema_extra={"ai": [AI_PROFILE_MCP]})

    product_category: Optional[ProductCategory] = Field(default=None,
                                                        description="Source product category (原始产品类别)",
                                                        json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    product_vendor: Optional[str] = Field(default=None,
                                          description="Source vendor (原始厂商)",
                                          json_schema_extra={"type": 2, "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    product_name: Optional[str] = Field(default=None,
                                        description="Source product name (原始产品名称)",
                                        json_schema_extra={"type": 2, "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    product_feature: Optional[str] = Field(default=None,
                                           description="Source product feature (原始产品功能)",
                                           json_schema_extra={"type": 2, "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    policy_name: Optional[str] = Field(default="",
                                       description="Trigger policy name (触发策略名称)",
                                       json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    policy_type: Optional[AlertPolicyType] = Field(default=None,
                                                   description="Trigger policy type (触发策略类型)",
                                                   json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    policy_desc: Optional[str] = Field(default="",
                                       description="Trigger policy description (触发策略描述)",
                                       json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    risk_level: Optional[AlertRiskLevel] = Field(default=None,
                                                 description="Assessed risk level (评估的风险等级)",
                                                 json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    status: Optional[AlertStatus] = Field(default=None,
                                          description="Alert handling status (告警处理状态)",
                                          json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    status_detail: Optional[str] = Field(default="",
                                         description="Handling status details (处理状态详情)",
                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    remediation: Optional[str] = Field(default="",
                                       description="Remediation advice or record (处置建议或记录)",
                                       json_schema_extra={"ai": [AI_PROFILE_MCP]})

    unmapped: Optional[str] = Field(default="",
                                    description="Raw unmapped fields, JSON Format (原始未映射字段 JSON 格式)")

    raw_data: Optional[str] = Field(default="",
                                    description="Raw alert log JSON (原始告警日志 JSON)")

    # 反向关联,无需手动处理
    case: Optional[List[Union[CaseModel, str]]] = Field(default=None,
                                                        init=False,
                                                        description="Linked case row_id, reverse association, auto-linked, no manual setting needed (关联案件行 ID,反向关联,自动化关联,无需手动设置)")
    # 关联表
    artifacts: Optional[List[Union[ArtifactModel, str]]] = Field(default=None,
                                                                 description="Extracted artifacts (关联表, 提取的实体列表)",
                                                                 json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None,
                                                                     description="Alert enrichments (关联表, 告警富化)",
                                                                     json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})


DEFAULT_ANALYSIS_COOLDOWN_MINUTES = 10


class CaseModel(BaseSystemModel):
    """安全案件,多个告警聚合而成,安全人员与AI分析处理的核心对象"""
    # 系统自动生成字段
    id: Optional[str] = Field(default=None,
                              init=False,
                              description="Record ID e.g. case_000001 (记录 ID e.g. case_000001,系统自动生成,无需手动赋值)",
                              json_schema_extra={"ai": [AI_PROFILE_MCP]})

    # 创建记录填写字段
    title: Optional[str] = Field(default="",
                                 description="Case title (案件标题)",
                                 json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    severity: Optional[Severity] = Field(default=None,
                                         description="Analyst-assessed severity (严重程度)",
                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    impact: Optional[Impact] = Field(default=None,
                                     description="Analyst-assessed impact (影响)",
                                     json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    priority: Optional[CasePriority] = Field(default=None,
                                             description="Response priority (响应优先级)",
                                             json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    confidence: Optional[Confidence] = Field(default=None,
                                             description="Analyst-assessed confidence (分析师评估置信度)",
                                             json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    description: Optional[str] = Field(default="",
                                       description="Case description (案件描述)",
                                       json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    category: Optional[ProductCategory] = Field(default=None,
                                                description="Case category (案件类别)",
                                                json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    tags: Optional[List[str]] = Field(default=[],
                                      description="Case tags (案件标签)",
                                      json_schema_extra={"type": 2, "ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    correlation_uid: Optional[str] = Field(default="",
                                           description="Case correlation ID (案件关联 ID)",
                                           json_schema_extra={"ai": [AI_PROFILE_MCP]})

    # 用户手动输入字段
    status: Optional[CaseStatus] = Field(default=CaseStatus.NEW,
                                         description="Case handling status (案件处理状态)",
                                         json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    acknowledged_time: Optional[AutoDatetime] = Field(default=None,
                                                      description="L1 first acknowledged time (L1 首次接手时间)",
                                                      json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    assignee_l1: Optional[AutoAccount] = Field(default=None,
                                               description="Assigned L1 analyst (分配的 L1 分析师)",
                                               json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    comment: Optional[str] = Field(default="", description="Case analyst comment (案件分析师注释)",
                                   json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    assignee_l2: Optional[AutoAccount] = Field(default=None,
                                               description="Assigned or escalated L2 analyst (分配或升级的 L2 分析师)",
                                               json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]}
                                               )
    assignee_l3: Optional[AutoAccount] = Field(default=None,
                                               description="Assigned or escalated L3 analyst (分配或升级的 L3 分析师)",
                                               json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]}
                                               )

    closed_time: Optional[AutoDatetime] = Field(default=None,
                                                description="case close time (事件关闭时间)",
                                                json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    verdict: Optional[CaseVerdict] = Field(default=None, description="Final verdict (最终判定结果)",
                                           json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    summary: Optional[str] = Field(default="", description="Closure summary (结案摘要)",
                                   json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    # 自动计算字段,无需手动赋值
    start_time_calc: Optional[AutoDatetime] = Field(default=None, description="Calculated start time (计算的开始时间)")
    end_time_calc: Optional[AutoDatetime] = Field(default=None, description="Calculated end time (计算的结束时间)")
    detect_time_calc: Optional[Any] = Field(default=None, description="Calculated detect time (计算的检测时间)")
    acknowledge_time_calc: Optional[Any] = Field(default=None, description="Calculated acknowledge time (计算的接手时间)")
    respond_time_calc: Optional[Any] = Field(default=None, description="Calculated response time (计算的响应时间)")

    # 关联表
    enrichments: Optional[List[Union[EnrichmentModel, str]]] = Field(default=None, description="Case enrichments (案件富化)",
                                                                     json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})
    alerts: Optional[List[Union[AlertModel, str]]] = Field(default=None, description="Linked alerts (关联的告警)",
                                                           json_schema_extra={"ai": [AI_PROFILE_INVESTIGATION, AI_PROFILE_MCP]})

    # 内部分析调度字段
    analysis_queue_message_id: Optional[str] = Field(default="",
                                                     description="Latest queued case analysis Redis stream message ID (最近一次案件分析队列消息 ID)")
    analysis_next_run_at: Optional[AutoDatetime] = Field(default=None,
                                                         description="Next eligible analysis time after cooldown (冷静期结束后的下一次可运行时间)")
    analysis_last_started_at: Optional[AutoDatetime] = Field(default=None,
                                                             description="Last analysis start time (最近一次分析开始时间)")
    analysis_last_completed_at: Optional[AutoDatetime] = Field(default=None,
                                                               description="Last analysis completion time (最近一次分析完成时间)")

    # ai 字段
    severity_ai: Optional[Severity] = Field(default=None, description="AI-assessed severity (AI 评估严重程度)")
    confidence_ai: Optional[Confidence] = Field(default=None, description="AI-assessed confidence (AI 评估置信度)")
    impact_ai: Optional[Impact] = Field(default=None, description="AI-assessed impact (AI 评估影响)")
    priority_ai: Optional[CasePriority] = Field(default=None, description="AI-assessed response priority (AI 评估响应优先级)")

    investigation_report_ai_json: Optional[str] = Field(default="", description="AI-generated investigation report JSON Format (AI 生成的调查报告 JSON 格式)")
    verdict_ai: Optional[CaseVerdict] = Field(default=None, description="AI-generated final verdict (AI 生成的最终判定结果)")
