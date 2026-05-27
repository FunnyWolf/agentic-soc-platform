from __future__ import annotations

import hashlib
import ipaddress
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PLUGINS.SIRP.sirpcoremodel import ArtifactType
from Lib.log import logger

SUPPORTED_ARTIFACT_TYPES = {
    ArtifactType.HOSTNAME,
    ArtifactType.IP_ADDRESS,
    ArtifactType.MAC_ADDRESS,
    ArtifactType.USER_NAME,
    ArtifactType.USER,
    ArtifactType.ACCOUNT,
    ArtifactType.EMAIL_ADDRESS,
    ArtifactType.EMAIL,
    ArtifactType.ENDPOINT,
    ArtifactType.DEVICE,
    ArtifactType.RESOURCE_UID,
    ArtifactType.RESOURCE,
    ArtifactType.PORT,
    ArtifactType.SUBNET,
    ArtifactType.SERIAL_NUMBER,
}

BUSINESS_PROFILES = [
    {
        "bucket": "ecommerce-prod",
        "service_id": "SVC-ECOM-001",
        "service_name": "E-Commerce Platform",
        "business_criticality": "Critical",
        "owner_team": "WebOps Team",
        "department": "Online Business",
        "environment": "Production",
        "network_zone": "DMZ",
    },
    {
        "bucket": "database-prod",
        "service_id": "SVC-DATA-002",
        "service_name": "Core Database Service",
        "business_criticality": "Critical",
        "owner_team": "DBA Team",
        "department": "IT Operations",
        "environment": "Production",
        "network_zone": "Internal Prod",
    },
    {
        "bucket": "employee-office",
        "service_id": "SVC-ENDUSER-003",
        "service_name": "Employee Endpoint Service",
        "business_criticality": "Medium",
        "owner_team": "Endpoint Team",
        "department": "Corporate IT",
        "environment": "Office",
        "network_zone": "Office LAN",
    },
    {
        "bucket": "identity-security",
        "service_id": "SVC-IAM-004",
        "service_name": "Identity and Access Management",
        "business_criticality": "High",
        "owner_team": "IAM Team",
        "department": "Security",
        "environment": "Production",
        "network_zone": "Internal Prod",
    },
    {
        "bucket": "cloud-workload",
        "service_id": "SVC-CLOUD-005",
        "service_name": "Cloud Workload Platform",
        "business_criticality": "High",
        "owner_team": "CloudOps Team",
        "department": "Cloud Platform",
        "environment": "Cloud",
        "network_zone": "Cloud VPC",
    },
    {
        "bucket": "network-infra",
        "service_id": "SVC-NET-006",
        "service_name": "Enterprise Network Infrastructure",
        "business_criticality": "High",
        "owner_team": "Network Team",
        "department": "Infrastructure",
        "environment": "Production",
        "network_zone": "Management",
    },
]

USER_PREFIX_PROFILES = {
    "adm": "identity-security",
    "admin": "identity-security",
    "sec": "identity-security",
    "soc": "identity-security",
    "dba": "database-prod",
    "db": "database-prod",
    "fin": "database-prod",
    "hr": "employee-office",
    "user": "employee-office",
    "emp": "employee-office",
    "cloud": "cloud-workload",
    "aws": "cloud-workload",
    "dev": "cloud-workload",
}

HOST_PREFIX_PROFILES = {
    "prod-web": "ecommerce-prod",
    "web": "ecommerce-prod",
    "nginx": "ecommerce-prod",
    "api": "ecommerce-prod",
    "db": "database-prod",
    "mysql": "database-prod",
    "postgres": "database-prod",
    "pc": "employee-office",
    "lap": "employee-office",
    "desktop": "employee-office",
    "iam": "identity-security",
    "ad": "identity-security",
    "ec2": "cloud-workload",
    "aws": "cloud-workload",
    "gce": "cloud-workload",
    "azr": "cloud-workload",
    "fw": "network-infra",
    "rtr": "network-infra",
    "sw": "network-infra",
    "vpn": "network-infra",
    "lb": "network-infra",
}

IP_NETWORK_PROFILES = [
    (ipaddress.ip_network("192.168.10.0/24"), "ecommerce-prod"),
    (ipaddress.ip_network("172.16.0.0/20"), "database-prod"),
    (ipaddress.ip_network("10.0.0.0/16"), "employee-office"),
    (ipaddress.ip_network("10.10.0.0/16"), "ecommerce-prod"),
    (ipaddress.ip_network("10.20.0.0/16"), "database-prod"),
    (ipaddress.ip_network("10.30.0.0/16"), "identity-security"),
    (ipaddress.ip_network("10.40.0.0/16"), "cloud-workload"),
    (ipaddress.ip_network("172.31.0.0/24"), "network-infra"),
    (ipaddress.ip_network("172.31.0.0/16"), "cloud-workload"),
    (ipaddress.ip_network("203.0.113.0/24"), "network-infra"),
]

PROFILE_BY_BUCKET = {profile["bucket"]: profile for profile in BUSINESS_PROFILES}


class MockCMDB:
    """Deterministic medium/small CMDB mock for SOC alert investigation."""

    def lookup(self, artifact_type: ArtifactType | str, artifact_value: str) -> dict[str, Any]:
        try:
            artifact_type = ArtifactType(artifact_type)
        except ValueError:
            return {
                "supported": False,
                "artifact_type": artifact_type,
                "artifact_value": artifact_value,
                "reason": "Unknown ArtifactType value.",
            }

        if artifact_type not in SUPPORTED_ARTIFACT_TYPES:
            return {
                "supported": False,
                "artifact_type": artifact_type,
                "artifact_value": artifact_value,
                "reason": "Artifact type is not CMDB-related in this mock.",
            }

        value = artifact_value.strip()
        if not value:
            return {"supported": False, "artifact_type": artifact_type, "reason": "artifact_value is empty."}

        if artifact_type in {ArtifactType.USER_NAME, ArtifactType.USER, ArtifactType.ACCOUNT}:
            return self._identity_context(artifact_type, value)
        if artifact_type in {ArtifactType.EMAIL_ADDRESS, ArtifactType.EMAIL}:
            return self._email_context(artifact_type, value)
        if artifact_type == ArtifactType.PORT:
            return self._port_context(artifact_type, value)
        if artifact_type == ArtifactType.SUBNET:
            return self._subnet_context(artifact_type, value)
        if artifact_type in {ArtifactType.RESOURCE_UID, ArtifactType.RESOURCE}:
            return self._resource_context(artifact_type, value)
        if artifact_type in {ArtifactType.HOSTNAME, ArtifactType.ENDPOINT, ArtifactType.DEVICE}:
            return self._asset_context(artifact_type, value, self._profile_for_hostname(value), hostname=value)
        if artifact_type == ArtifactType.IP_ADDRESS:
            return self._asset_context(artifact_type, value, self._profile_for_ip(value), ip_address=value)
        if artifact_type == ArtifactType.MAC_ADDRESS:
            return self._asset_context(artifact_type, value, self._profile_for_mac(value), mac_address=value)
        if artifact_type == ArtifactType.SERIAL_NUMBER:
            return self._asset_context(artifact_type, value, self._profile_for_serial(value), serial_number=value)

        return {"supported": False, "artifact_type": artifact_type, "artifact_value": value}

    def _asset_context(
            self,
            artifact_type: ArtifactType,
            value: str,
            profile: dict[str, str],
            hostname: str | None = None,
            ip_address: str | None = None,
            mac_address: str | None = None,
            serial_number: str | None = None,
    ) -> dict[str, Any]:
        seed = self._seed(artifact_type, value)
        asset_type = self._asset_type_for_profile(profile, value)
        hostname = hostname or self._hostname(seed, asset_type)
        ip_address = ip_address or self._ip(seed, profile)
        mac_address = mac_address or self._mac(seed)
        serial_number = serial_number or f"SN-{self._token(seed, 10)}"
        owner = self._owner(profile, seed)
        exposure = self._exposure(asset_type, profile, seed)
        self._debug_context(artifact_type, value, profile, seed, self._soc_notes(profile, asset_type, exposure))

        return {
            "supported": True,
            "query": {"artifact_type": artifact_type, "artifact_value": value},
            "cmdb_record_type": "asset",
            "asset": {
                "asset_id": f"AST-{self._token(profile['bucket'] + ':' + value, 8)}",
                "asset_type": asset_type,
                "hostname": hostname,
                "ip_addresses": [ip_address],
                "mac_address": mac_address,
                "serial_number": serial_number,
                "status": self._pick(seed + ":status", ["Active", "Active", "Active", "Maintenance", "Retired"]),
                "environment": profile["environment"],
                "network_zone": profile["network_zone"],
                "location": self._pick(seed + ":location", ["Shanghai DC", "Beijing DC", "Cloud", "Office", "Remote"]),
            },
            "business": self._business(profile),
            "owner": owner,
            "exposure": exposure,
            "related": {
                "primary_user": owner["user_id"],
                "nearby_assets": self._nearby_assets(seed, profile, asset_type),
                "service_assets_hint": f"Assets in {profile['service_id']} usually share owner_team={profile['owner_team']} and zone={profile['network_zone']}.",
            },
        }

    def _identity_context(self, artifact_type: ArtifactType, value: str) -> dict[str, Any]:
        profile = self._profile_for_user(value)
        seed = self._seed(artifact_type, value)
        user_id = value
        workstation = self._asset_context(ArtifactType.HOSTNAME, f"pc-{self._safe_name(value)}", profile)
        self._debug_context(artifact_type, value, profile, seed, [
            "Check recent authentication, VPN and endpoint activity for this identity.",
            "If privilege_level is Privileged or High/Critical, prioritize containment and credential review.",
        ])
        return {
            "supported": True,
            "query": {"artifact_type": artifact_type, "artifact_value": value},
            "cmdb_record_type": "identity",
            "identity": {
                "user_id": user_id,
                "display_name": self._display_name(value),
                "department": profile["department"],
                "job_title": self._pick(seed + ":title", ["Engineer", "Analyst", "Administrator", "Manager", "Operator"]),
                "employment_status": "Active",
                "privilege_level": self._pick(seed + ":priv", ["Standard", "Standard", "Privileged", "High/Critical"]),
            },
            "business": self._business(profile),
            "owner": self._owner(profile, seed),
            "related": {
                "primary_endpoint": workstation["asset"],
                "accounts": [user_id, f"{user_id}@corp.example"],
                "common_services": [profile["service_id"]],
            },
        }

    def _email_context(self, artifact_type: ArtifactType, value: str) -> dict[str, Any]:
        local_part = value.split("@", 1)[0] if "@" in value else value
        profile = self._profile_for_user(local_part)
        identity = self._identity_context(ArtifactType.USER_NAME, local_part)
        domain = value.split("@", 1)[1] if "@" in value else "corp.example"
        self._debug_context(artifact_type, value, profile, self._seed(artifact_type, value), [
            "For phishing alerts, pivot from this mailbox to recent login IPs, forwarding rules and OAuth grants.",
            "For suspicious sender/recipient alerts, compare mailbox owner department with alert target scope.",
        ])
        return {
            "supported": True,
            "query": {"artifact_type": artifact_type, "artifact_value": value},
            "cmdb_record_type": "email_identity",
            "mailbox": {
                "email_address": value,
                "mail_domain": domain,
                "mail_platform": self._pick(domain, ["Microsoft 365", "Google Workspace", "Exchange Online"]),
                "mailbox_status": "Active",
            },
            "identity": identity["identity"],
            "business": self._business(profile),
            "related": identity["related"],
        }

    def _port_context(self, artifact_type: ArtifactType, value: str) -> dict[str, Any]:
        if not value.isdigit() or not 1 <= int(value) <= 65535:
            return {"supported": False, "artifact_type": artifact_type, "artifact_value": value, "reason": "Invalid TCP/UDP port."}

        port = int(value)
        profile = self._profile_for_port(port)
        seed = self._seed(artifact_type, value)
        protocol = self._pick(seed + ":proto", ["TCP", "TCP", "UDP"])
        self._debug_context(artifact_type, value, profile, seed, [
            "Use this result as exposure context, not as proof that every related asset has this port open.",
            "Prioritize internet-facing or management ports during incident scoping.",
        ])
        return {
            "supported": True,
            "query": {"artifact_type": artifact_type, "artifact_value": value},
            "cmdb_record_type": "network_exposure",
            "port": {
                "port": port,
                "protocol": protocol,
                "common_service": self._service_name_for_port(port),
                "exposure_level": self._pick(seed + ":exposure", ["Internal", "Internal", "Internet-facing", "Management-only"]),
            },
            "business": self._business(profile),
            "related_assets": self._nearby_assets(seed, profile, self._asset_type_for_profile(profile, value)),
        }

    def _subnet_context(self, artifact_type: ArtifactType, value: str) -> dict[str, Any]:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return {"supported": False, "artifact_type": artifact_type, "artifact_value": value, "reason": "Invalid subnet."}

        profile = self._profile_for_ip(str(network.network_address))
        seed = self._seed(artifact_type, value)
        self._debug_context(artifact_type, value, profile, seed, [
            "Use subnet context for blast-radius estimation and network containment planning.",
            "Validate exact membership in a real CMDB/IPAM during production response.",
        ])
        return {
            "supported": True,
            "query": {"artifact_type": artifact_type, "artifact_value": value},
            "cmdb_record_type": "subnet",
            "subnet": {
                "cidr": str(network),
                "network_zone": profile["network_zone"],
                "environment": profile["environment"],
                "estimated_asset_count": self._stable_int(seed + ":count") % 80 + 10,
                "owner_team": profile["owner_team"],
            },
            "business": self._business(profile),
            "related_assets": self._nearby_assets(seed, profile, self._asset_type_for_profile(profile, value), count=5),
        }

    def _resource_context(self, artifact_type: ArtifactType, value: str) -> dict[str, Any]:
        profile = self._profile_for_resource(value)
        seed = self._seed(artifact_type, value)
        resource_type = self._resource_type(value)
        self._debug_context(artifact_type, value, profile, seed, [
            "Cloud resource alerts should be correlated with IAM changes, security group changes and workload logs.",
            "If this is a storage or database resource, review public access and recent policy changes.",
        ])
        return {
            "supported": True,
            "query": {"artifact_type": artifact_type, "artifact_value": value},
            "cmdb_record_type": "resource",
            "resource": {
                "resource_id": value,
                "resource_type": resource_type,
                "provider": self._resource_provider(value),
                "region": self._pick(seed + ":region", ["cn-shanghai", "cn-beijing", "us-east-1", "ap-southeast-1"]),
                "status": self._pick(seed + ":status", ["Running", "Available", "Active", "Stopped"]),
            },
            "business": self._business(profile),
            "owner": self._owner(profile, seed),
            "related_assets": self._nearby_assets(seed, profile, "CloudInstance"),
        }

    def _profile_for_ip(self, value: str) -> dict[str, str]:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return self._profile_by_hash(value)

        for network, bucket in IP_NETWORK_PROFILES:
            if ip in network:
                return PROFILE_BY_BUCKET[bucket]
        if ip.is_private:
            return PROFILE_BY_BUCKET[self._pick(str(ip), ["employee-office", "database-prod", "cloud-workload"])]
        return PROFILE_BY_BUCKET[self._pick(str(ip), ["ecommerce-prod", "network-infra", "cloud-workload"])]

    def _profile_for_hostname(self, value: str) -> dict[str, str]:
        normalized = value.lower()
        for prefix, bucket in HOST_PREFIX_PROFILES.items():
            if normalized.startswith(prefix) or f"-{prefix}" in normalized:
                return PROFILE_BY_BUCKET[bucket]
        return self._profile_by_hash(value)

    def _profile_for_user(self, value: str) -> dict[str, str]:
        normalized = value.lower().split("@", 1)[0]
        for prefix, bucket in USER_PREFIX_PROFILES.items():
            if normalized.startswith(prefix):
                return PROFILE_BY_BUCKET[bucket]
        return PROFILE_BY_BUCKET[self._pick(normalized, ["employee-office", "identity-security", "database-prod", "cloud-workload"])]

    def _profile_for_mac(self, value: str) -> dict[str, str]:
        vendor_hint = value.upper().replace("-", ":")[:8]
        if vendor_hint in {"00:1A:2B", "3C:52:82", "B8:27:EB"}:
            return PROFILE_BY_BUCKET["employee-office"]
        return self._profile_by_hash(value)

    def _profile_for_serial(self, value: str) -> dict[str, str]:
        lower = value.lower()
        if lower.startswith(("fw", "rtr", "sw", "net")):
            return PROFILE_BY_BUCKET["network-infra"]
        if lower.startswith(("ec2", "aws", "gce", "az")):
            return PROFILE_BY_BUCKET["cloud-workload"]
        return self._profile_by_hash(value)

    def _profile_for_port(self, port: int) -> dict[str, str]:
        if port in {80, 443, 8080, 8443}:
            return PROFILE_BY_BUCKET["ecommerce-prod"]
        if port in {1433, 1521, 3306, 5432, 6379, 9200}:
            return PROFILE_BY_BUCKET["database-prod"]
        if port in {22, 23, 161, 3389, 5900}:
            return PROFILE_BY_BUCKET["network-infra"]
        return self._profile_by_hash(str(port))

    def _profile_for_resource(self, value: str) -> dict[str, str]:
        lower = value.lower()
        if lower.startswith(("arn:", "i-", "ec2", "aws", "gcp", "gce", "az", "/subscriptions/")):
            return PROFILE_BY_BUCKET["cloud-workload"]
        if any(word in lower for word in ["policy", "role", "user", "iam"]):
            return PROFILE_BY_BUCKET["identity-security"]
        return self._profile_by_hash(value)

    def _profile_by_hash(self, seed: str) -> dict[str, str]:
        return self._pick(seed, BUSINESS_PROFILES)

    def _asset_type_for_profile(self, profile: dict[str, str], value: str) -> str:
        lower = value.lower()
        if profile["bucket"] == "network-infra":
            return self._pick(value, ["Firewall", "Router", "Switch", "VPN Gateway", "Load Balancer"])
        if profile["bucket"] == "cloud-workload":
            return "CloudInstance"
        if profile["bucket"] == "database-prod" or any(word in lower for word in ["db", "sql", "mysql", "postgres"]):
            return "Database"
        if profile["bucket"] == "employee-office" or lower.startswith(("pc", "lap", "desktop")):
            return "Workstation"
        return "Server"

    def _exposure(self, asset_type: str, profile: dict[str, str], seed: str) -> dict[str, Any]:
        ports = {
            "Server": [22, 80, 443],
            "Database": [22, 3306],
            "Workstation": [3389],
            "CloudInstance": [22, 443, 8080],
            "Firewall": [22, 443],
            "Router": [22, 161],
            "Switch": [22, 161],
            "VPN Gateway": [443, 500, 4500],
            "Load Balancer": [80, 443],
        }.get(asset_type, [443])
        return {
            "internet_exposed": profile["network_zone"] == "DMZ" or asset_type in {"Load Balancer", "VPN Gateway"},
            "open_ports": [{"port": port, "protocol": "TCP" if port not in {500, 4500, 161} else "UDP"} for port in ports],
            "installed_software": self._software(asset_type, seed),
            "edr_installed": asset_type in {"Server", "Database", "Workstation", "CloudInstance"},
            "logging_level": self._pick(seed + ":logging", ["Standard", "Enhanced", "Verbose"]),
        }

    def _software(self, asset_type: str, seed: str) -> list[dict[str, str]]:
        catalog = {
            "Server": [{"name": "nginx", "version": "1.24"}, {"name": "openssh", "version": "9"}],
            "Database": [{"name": "mysql", "version": "8.0"}, {"name": "backup-agent", "version": "3"}],
            "Workstation": [{"name": "office", "version": "2021"}, {"name": "edr-agent", "version": "5"}],
            "CloudInstance": [{"name": "cloud-agent", "version": "2"}, {"name": "container-runtime", "version": "stable"}],
            "Firewall": [{"name": "network-os", "version": "stable"}],
            "Router": [{"name": "network-os", "version": "stable"}],
            "Switch": [{"name": "network-os", "version": "stable"}],
            "VPN Gateway": [{"name": "vpn-service", "version": "stable"}],
            "Load Balancer": [{"name": "load-balancer", "version": "stable"}],
        }
        return catalog.get(asset_type, [{"name": self._pick(seed, ["agent", "service", "daemon"]), "version": "mock-current"}])

    def _business(self, profile: dict[str, str]) -> dict[str, str]:
        return {
            "service_id": profile["service_id"],
            "service_name": profile["service_name"],
            "business_criticality": profile["business_criticality"],
            "department": profile["department"],
            "environment": profile["environment"],
        }

    def _owner(self, profile: dict[str, str], seed: str) -> dict[str, str]:
        user_prefix = {
            "WebOps Team": "webops",
            "DBA Team": "dba",
            "Endpoint Team": "endpoint",
            "IAM Team": "iam",
            "CloudOps Team": "cloudops",
            "Network Team": "netops",
        }.get(profile["owner_team"], "owner")
        return {
            "owner_team": profile["owner_team"],
            "user_id": f"{user_prefix}_{self._token(seed + ':owner', 4).lower()}",
            "oncall": f"{profile['owner_team'].lower().replace(' ', '-')}-oncall",
        }

    def _nearby_assets(self, seed: str, profile: dict[str, str], asset_type: str, count: int = 3) -> list[dict[str, Any]]:
        return [
            {
                "asset_id": f"AST-{self._token(seed + ':nearby:' + str(index), 8)}",
                "asset_type": asset_type,
                "hostname": self._hostname(seed + f":nearby:{index}", asset_type),
                "ip_address": self._ip(seed + f":nearby:{index}", profile),
                "relationship": self._pick(seed + f":rel:{index}", ["same_service", "same_subnet", "same_owner_team", "same_application_tier"]),
            }
            for index in range(1, count + 1)
        ]

    def _soc_notes(self, profile: dict[str, str], asset_type: str, exposure: dict[str, Any]) -> list[str]:
        notes = [
            f"Treat this as {profile['business_criticality']} business context for {profile['service_name']}.",
            f"Notify {profile['owner_team']} if containment or forensic collection is needed.",
        ]
        if exposure["internet_exposed"]:
            notes.append("Internet-exposed asset: prioritize external attack surface and WAF/proxy log review.")
        if asset_type in {"Database", "IAM", "CloudInstance"} or profile["business_criticality"] == "Critical":
            notes.append("High-impact asset: preserve evidence before disruptive containment if possible.")
        return notes

    def _debug_context(self, artifact_type: ArtifactType, value: str, profile: dict[str, str], seed: str, notes: list[str]) -> None:
        logger.debug(
            "Mock CMDB lookup artifact_type=%s artifact_value=%s profile_bucket=%s seed_hash=%s notes=%s",
            artifact_type.value,
            value,
            profile["bucket"],
            self._token(seed, 12),
            notes,
        )

    def _hostname(self, seed: str, asset_type: str) -> str:
        prefix = {
            "Server": "srv",
            "Database": "db",
            "Workstation": "pc",
            "CloudInstance": "cloud",
            "Firewall": "fw",
            "Router": "rtr",
            "Switch": "sw",
            "VPN Gateway": "vpn",
            "Load Balancer": "lb",
        }.get(asset_type, "asset")
        return f"{prefix}-{self._token(seed, 6).lower()}"

    def _ip(self, seed: str, profile: dict[str, str]) -> str:
        ranges = {
            "ecommerce-prod": "192.168.10.0/24",
            "database-prod": "172.16.0.0/20",
            "employee-office": "10.0.0.0/16",
            "identity-security": "10.30.0.0/16",
            "cloud-workload": "172.31.0.0/16",
            "network-infra": "172.31.0.0/24",
        }
        network = ipaddress.ip_network(ranges[profile["bucket"]])
        offset = self._stable_int(seed + ":ip") % (network.num_addresses - 2) + 1
        return str(network.network_address + offset)

    def _mac(self, seed: str) -> str:
        digest = self._token(seed + ":mac", 12)
        return ":".join(digest[index:index + 2] for index in range(0, 12, 2))

    def _service_name_for_port(self, port: int) -> str:
        return {
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            500: "IKE",
            161: "SNMP",
            3306: "MySQL",
            3389: "RDP",
            4500: "IPSec NAT-T",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP Alternate",
            8443: "HTTPS Alternate",
            9200: "Elasticsearch",
        }.get(port, "Unknown/Custom")

    def _resource_type(self, value: str) -> str:
        lower = value.lower()
        if lower.startswith(("i-", "ec2")) or ":instance/" in lower:
            return "Cloud Compute Instance"
        if "bucket" in lower or ":s3" in lower:
            return "Object Storage Bucket"
        if "role" in lower or "policy" in lower:
            return "IAM Resource"
        if "db" in lower or "rds" in lower:
            return "Cloud Database"
        return "Generic Resource"

    def _resource_provider(self, value: str) -> str:
        lower = value.lower()
        if lower.startswith("arn:") or lower.startswith(("i-", "ec2", "aws")):
            return "AWS"
        if lower.startswith(("gcp", "gce")):
            return "GCP"
        if lower.startswith(("az", "/subscriptions/")):
            return "Azure"
        return "Internal"

    def _display_name(self, value: str) -> str:
        parts = re.split(r"[._-]+", value.split("@", 1)[0])
        return " ".join(part.capitalize() for part in parts if part) or value

    def _safe_name(self, value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9-]", "-", value).strip("-").lower() or "unknown"

    def _seed(self, artifact_type: ArtifactType, artifact_value: str) -> str:
        return f"{artifact_type.value}:{artifact_value}"

    def _token(self, seed: str, length: int) -> str:
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:length].upper()

    def _stable_int(self, seed: str) -> int:
        return int(self._token(seed, 12), 16)

    def _pick(self, seed: str, values: list[Any]) -> Any:
        return values[self._stable_int(seed) % len(values)]


cmdb_instance = MockCMDB()
