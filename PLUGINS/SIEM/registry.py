from __future__ import annotations

from typing import List, Dict, Literal

from pydantic import BaseModel


# --- Schema Definition Models ---
class FieldInfo(BaseModel):
    name: str
    type: str
    description: str
    is_key_field: bool = False


class IndexInfo(BaseModel):
    name: str
    backend: Literal["ELK", "Splunk"]  # 新增：用于路由判断
    description: str
    fields: List[FieldInfo]


def get_default_agg_fields(index_name: str) -> List[str]:
    if index_name not in STATIC_SCHEMA_REGISTRY:
        return []
    return [f.name for f in STATIC_SCHEMA_REGISTRY[index_name].fields if f.is_key_field]


def get_backend_type(index_name: str) -> str:
    """Helper to determine backend"""
    if index_name in STATIC_SCHEMA_REGISTRY:
        return STATIC_SCHEMA_REGISTRY[index_name].backend
    return "ELK"  # Fallback


# --- Static Registry Data ---
STATIC_SCHEMA_REGISTRY: Dict[str, IndexInfo] = {
    # 1. AWS CloudTrail Index (ELK)
    "siem-aws-cloudtrail": IndexInfo(
        name="siem-aws-cloudtrail",
        backend="ELK",
        description="AWS CloudTrail logs via ELK.",
        fields=[
            FieldInfo(name="@timestamp", type="date", description="Event time", is_key_field=False),
            FieldInfo(name="event.dataset", type="keyword", description="Dataset (aws.cloudtrail)", is_key_field=False),
            FieldInfo(name="event.module", type="keyword", description="Module (cloudtrail)", is_key_field=False),
            FieldInfo(name="event.action", type="keyword", description="API Action", is_key_field=True),
            FieldInfo(name="event.category", type="keyword", description="Event category (iam/cloud)", is_key_field=True),
            FieldInfo(name="event.outcome", type="keyword", description="Result (success/failure)", is_key_field=True),
            FieldInfo(name="event.duration", type="long", description="Event duration in ms", is_key_field=False),
            FieldInfo(name="event.risk_score", type="long", description="Risk score (20-100)", is_key_field=False),
            FieldInfo(name="cloud.provider", type="keyword", description="Cloud provider (aws)", is_key_field=False),
            FieldInfo(name="cloud.service.name", type="keyword", description="Service name (ec2/iam/s3/lambda/rds)", is_key_field=True),
            FieldInfo(name="cloud.region", type="keyword", description="AWS region", is_key_field=True),
            FieldInfo(name="cloud.account.id", type="keyword", description="AWS Account ID", is_key_field=True),
            FieldInfo(name="cloud.account.name", type="keyword", description="Account name", is_key_field=False),
            FieldInfo(name="user.name", type="keyword", description="IAM user name", is_key_field=True),
            FieldInfo(name="user.id", type="keyword", description="User ID (AIDAI...)", is_key_field=True),
            FieldInfo(name="user.type", type="keyword", description="User type (IAMUser/IAMRole/AssumedRole/RootUser)", is_key_field=False),
            FieldInfo(name="user.access_key_id", type="keyword", description="Access key ID (AKIA...)", is_key_field=False),
            FieldInfo(name="source.ip", type="ip", description="Requester IP", is_key_field=True),
            FieldInfo(name="source.address", type="ip", description="Source address", is_key_field=False),
            FieldInfo(name="source.geo.country_name", type="keyword", description="Country name", is_key_field=False),
            FieldInfo(name="source.geo.country_iso_code", type="keyword", description="Country ISO code", is_key_field=False),
            FieldInfo(name="http.request.method", type="keyword", description="HTTP method (GET/POST/PUT/DELETE/PATCH)", is_key_field=False),
            FieldInfo(name="http.response.status_code", type="long", description="HTTP response status code", is_key_field=True),
            FieldInfo(name="http.request.body.content", type="text", description="Request body content", is_key_field=False),
            FieldInfo(name="user_agent", type="text", description="User agent string", is_key_field=False),
            FieldInfo(name="request_id", type="keyword", description="Request ID (UUID)", is_key_field=True),
            FieldInfo(name="event_id", type="keyword", description="Event ID (UUID)", is_key_field=True),
            FieldInfo(name="aws_service", type="keyword", description="AWS service (cloudtrail/config/guardduty/securityhub)", is_key_field=False),
            FieldInfo(name="aws_request_id", type="keyword", description="AWS request ID", is_key_field=False),
            FieldInfo(name="recipient_account_id", type="keyword", description="Recipient account ID", is_key_field=False),
            FieldInfo(name="additional_event_data", type="object", description="Additional event data (LoginTo/MobileVersion/MFAUsed)", is_key_field=False),
            FieldInfo(name="request_parameters", type="object", description="Request parameters", is_key_field=False),
            FieldInfo(name="response_elements", type="object", description="Response elements", is_key_field=False),
            FieldInfo(name="error_code", type="keyword", description="Error code if failed", is_key_field=False),
            FieldInfo(name="error_message", type="text", description="Error message if failed", is_key_field=False),
            FieldInfo(name="read_only", type="boolean", description="Read-only operation flag", is_key_field=False),
            FieldInfo(name="log.level", type="keyword", description="Log level (info/warning)", is_key_field=False)
        ]
    ),

    # 2. Network Traffic Index (Splunk)
    "siem-network-traffic": IndexInfo(
        name="siem-network-traffic",
        backend="Splunk",
        description="Network traffic logs via Splunk.",
        fields=[
            FieldInfo(name="@timestamp", type="date", description="Event time", is_key_field=False),
            FieldInfo(name="event.dataset", type="keyword", description="Dataset (network)", is_key_field=False),
            FieldInfo(name="event.module", type="keyword", description="Module (firewall)", is_key_field=False),
            FieldInfo(name="event.category", type="keyword", description="Event category (network_traffic)", is_key_field=True),
            FieldInfo(name="event.type", type="keyword", description="Event type (connection)", is_key_field=False),
            FieldInfo(name="event.action", type="keyword", description="Action (allow/deny)", is_key_field=True),
            FieldInfo(name="event.outcome", type="keyword", description="Outcome (success/failure)", is_key_field=True),
            FieldInfo(name="network.protocol", type="keyword", description="Protocol (tcp/udp)", is_key_field=True),
            FieldInfo(name="network.direction", type="keyword", description="Direction (egress/ingress)", is_key_field=False),
            FieldInfo(name="network.bytes_in", type="long", description="Bytes in", is_key_field=False),
            FieldInfo(name="network.bytes_out", type="long", description="Bytes out", is_key_field=False),
            FieldInfo(name="network.packets", type="long", description="Packet count", is_key_field=False),
            FieldInfo(name="network.duration", type="long", description="Duration in ms", is_key_field=False),
            FieldInfo(name="source.ip", type="ip", description="Source IP", is_key_field=True),
            FieldInfo(name="source.port", type="long", description="Source port", is_key_field=False),
            FieldInfo(name="source.mac", type="keyword", description="Source MAC address", is_key_field=False),
            FieldInfo(name="destination.ip", type="ip", description="Destination IP", is_key_field=True),
            FieldInfo(name="destination.port", type="long", description="Destination port", is_key_field=True),
            FieldInfo(name="destination.service", type="keyword", description="Destination service (https/http/ssh/rdp/mysql/postgresql/redis/dns)",
                      is_key_field=True),
            FieldInfo(name="host.name", type="keyword", description="Host name", is_key_field=True),
            FieldInfo(name="host.ip", type="ip", description="Host IP (source IP)", is_key_field=False),
            FieldInfo(name="process.pid", type="long", description="Process ID", is_key_field=False),
            FieldInfo(name="process.name", type="keyword", description="Process name", is_key_field=False),
            FieldInfo(name="user.name", type="keyword", description="User name", is_key_field=True),
            FieldInfo(name="user.id", type="keyword", description="User ID", is_key_field=False),
            FieldInfo(name="firewall.rule_id", type="keyword", description="Firewall rule ID", is_key_field=True),
            FieldInfo(name="firewall.rule_name", type="keyword", description="Firewall rule name", is_key_field=False),
            FieldInfo(name="log.level", type="keyword", description="Log level (info)", is_key_field=False)
        ]
    ),

    # 3. Host Events Index (ELK)
    "siem-host-events": IndexInfo(
        name="siem-host-events",
        backend="ELK",
        description="Host endpoint events including process and file activities.",
        fields=[
            FieldInfo(name="@timestamp", type="date", description="Event time", is_key_field=False),
            FieldInfo(name="event.dataset", type="keyword", description="Dataset type (host)", is_key_field=False),
            FieldInfo(name="event.module", type="keyword", description="Module (endpoint)", is_key_field=False),
            FieldInfo(name="event.category", type="keyword", description="Event category (process/file)", is_key_field=True),
            FieldInfo(name="event.type", type="keyword", description="Event type (process_created/terminated/file_created/deleted/registry_modified)",
                      is_key_field=True),
            FieldInfo(name="event.action", type="keyword", description="Event action", is_key_field=True),
            FieldInfo(name="event.outcome", type="keyword", description="Event outcome (success/failure)", is_key_field=False),
            FieldInfo(name="host.name", type="keyword", description="Host name", is_key_field=True),
            FieldInfo(name="host.id", type="keyword", description="Host ID (UUID)", is_key_field=True),
            FieldInfo(name="host.os.name", type="keyword", description="OS name (Windows/Linux/macOS)", is_key_field=False),
            FieldInfo(name="host.os.version", type="keyword", description="OS version", is_key_field=False),
            FieldInfo(name="host.architecture", type="keyword", description="Host architecture (x86_64/arm64)", is_key_field=False),
            FieldInfo(name="user.name", type="keyword", description="User name", is_key_field=True),
            FieldInfo(name="user.id", type="keyword", description="User ID (SID)", is_key_field=True),
            FieldInfo(name="user.domain", type="keyword", description="User domain (CORP/LOCAL/WORKGROUP)", is_key_field=False),
            FieldInfo(name="process.pid", type="long", description="Process ID", is_key_field=True),
            FieldInfo(name="process.ppid", type="long", description="Parent Process ID", is_key_field=False),
            FieldInfo(name="process.name", type="keyword", description="Process name", is_key_field=True),
            FieldInfo(name="process.executable", type="keyword", description="Process executable path", is_key_field=False),
            FieldInfo(name="process.command_line", type="text", description="Process command line", is_key_field=False),
            FieldInfo(name="process.hash.md5", type="keyword", description="Process MD5 hash", is_key_field=False),
            FieldInfo(name="process.hash.sha256", type="keyword", description="Process SHA256 hash", is_key_field=False),
            FieldInfo(name="process.parent.name", type="keyword", description="Parent process name", is_key_field=False),
            FieldInfo(name="process.parent.pid", type="long", description="Parent process ID", is_key_field=False),
            FieldInfo(name="file.name", type="keyword", description="File name", is_key_field=True),
            FieldInfo(name="file.path", type="keyword", description="File path", is_key_field=False),
            FieldInfo(name="file.size", type="long", description="File size in bytes", is_key_field=False),
            FieldInfo(name="file.hash.md5", type="keyword", description="File MD5 hash", is_key_field=False),
            FieldInfo(name="file.hash.sha256", type="keyword", description="File SHA256 hash", is_key_field=False),
            FieldInfo(name="log.level", type="keyword", description="Log level (info/warning/error)", is_key_field=False),
            FieldInfo(name="message", type="text", description="Log message", is_key_field=False)
        ]
    )
}
