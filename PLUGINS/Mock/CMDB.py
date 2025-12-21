import re
from typing import List, Dict, Optional, Any, Annotated

# Extended mock CMDB data, keyed by CI ID (consistent with the last time)
EXTENDED_CMDB_DATA = {
    # 1. Core server CI (unchanged)
    "SRV-WEB-001": {
        "ci_id": "SRV-WEB-001", "ci_type": "Server", "hostname": "prod-web-01", "ip_address": ["192.168.10.5", "10.10.10.5"],
        "ci_status": "Deployed/Active", "business_criticality": "High", "service_id": "SVC-ECOM-001",
        "owner_team": "WebOps Team", "network_zone": "DMZ", "os_version": "RHEL 8.6",
        "hardware_model": "Dell PowerEdge R640", "installed_software": [{"name": "nginx", "version": "1.20.1"}, {"name": "php-fpm", "version": "7.4"}],
        "open_ports": [{"port": 80, "protocol": "TCP"}, {"port": 443, "protocol": "TCP"}], "primary_user_id": None
    },
    # 2. Database CI (unchanged)
    "APP-DB-003": {
        "ci_id": "APP-DB-003", "ci_type": "Database", "hostname": "prod-db-03", "ip_address": ["172.16.0.22"],
        "ci_status": "Deployed/Active", "business_criticality": "Critical", "service_id": "SVC-ECOM-001",
        "owner_team": "DBA Team", "network_zone": "Internal Prod",
        "installed_software": [{"name": "mysql", "version": "8.0.27"}],
        "open_ports": [{"port": 3306, "protocol": "TCP"}], "primary_user_id": "user_a"
    },
    # 3. Employee CI (unchanged)
    "EMP-0010": {
        "ci_id": "EMP-0010", "ci_type": "Employee", "employee_name": "Zhang San", "user_id": "user_a",
        "department": "IT Operations", "job_title": "Database Administrator", "access_level": "High/Critical"
    },
    # 4. PC/Workstation CI (unchanged)
    "PC-HR-04": {
        "ci_id": "PC-HR-04", "ci_type": "Workstation", "hostname": "hr-pc-04", "ip_address": ["10.0.1.10"],
        "ci_status": "Deployed/Active", "business_criticality": "Low", "service_id": "SVC-HR-003",
        "owner_team": "HR Team", "os_version": "Windows 10", "mac_address": "00:1A:2B:3C:4D:5E",
        "installed_software": [{"name": "office", "version": "2021"}], "primary_user_id": "user_b"
    },
    # 5. Domain Name CI (unchanged)
    "DNS-ECOM-MAIN": {
        "ci_id": "DNS-ECOM-MAIN", "ci_type": "DomainName", "domain_name": "example-ecommerce.com",
        "ci_status": "Active", "business_criticality": "Critical", "owner_team": "Marketing",
        "dns_registrar": "GoDaddy", "expiration_date": "2026-10-10", "related_ip": ["192.168.10.5"]
    },
    # --- New Type 6: NetworkDevice ---
    "FW-DMZ-01": {
        "ci_id": "FW-DMZ-01", "ci_type": "NetworkDevice", "hostname": "dmz-fw-01",
        "ip_address": ["192.168.10.1", "10.10.10.1"], "ci_status": "Active",
        "business_criticality": "Critical", "owner_team": "NetSec", "device_type": "Firewall",
        "vendor": "Cisco", "os_version": "ASA 9.1", "location": "DC-Shanghai",
        "management_ip": "172.31.0.1"
    },
    "RTR-CORE-02": {
        "ci_id": "RTR-CORE-02", "ci_type": "NetworkDevice", "hostname": "core-rtr-02",
        "ip_address": ["172.16.255.2"], "ci_status": "Active", "business_criticality": "High",
        "owner_team": "Network", "device_type": "Router", "vendor": "Juniper",
        "os_version": "Junos 18.4", "location": "DC-Beijing"
    },
    "SW-PROD-05": {
        "ci_id": "SW-PROD-05", "ci_type": "NetworkDevice", "hostname": "prod-sw-05",
        "ip_address": ["172.16.1.5"], "ci_status": "Active", "business_criticality": "Medium",
        "owner_team": "Network", "device_type": "Switch", "vendor": "Huawei",
        "os_version": "VRP 5.1", "location": "DC-Shanghai"
    },
    "LB-EXT-01": {
        "ci_id": "LB-EXT-01", "ci_type": "NetworkDevice", "hostname": "ext-lb-01",
        "ip_address": ["103.20.10.1"], "ci_status": "Active", "business_criticality": "Critical",
        "owner_team": "WebOps", "device_type": "LoadBalancer", "vendor": "F5",
        "os_version": "TMOS 14.1", "location": "Cloud POP"
    },
    "VPN-GATE-03": {
        "ci_id": "VPN-GATE-03", "ci_type": "NetworkDevice", "hostname": "vpn-gate-03",
        "ip_address": ["203.0.113.1"], "ci_status": "Active", "business_criticality": "Medium",
        "owner_team": "NetSec", "device_type": "VPN Concentrator", "vendor": "Palo Alto",
        "os_version": "PAN-OS 10.0", "location": "DC-Shanghai"
    },

    # --- New Type 7: CloudInstance ---
    "EC2-PROD-A1": {
        "ci_id": "EC2-PROD-A1", "ci_type": "CloudInstance", "hostname": "aws-app-a1",
        "ip_address": ["172.31.5.10"], "ci_status": "Running", "business_criticality": "High",
        "service_id": "SVC-ECOM-001", "owner_team": "CloudOps", "cloud_provider": "AWS",
        "region": "us-east-1", "instance_type": "t3.medium", "os_version": "Amazon Linux 2",
        "installed_software": [{"name": "java", "version": "11"}, {"name": "tomcat", "version": "9"}],
        "primary_user_id": None
    },
    "GCE-DEV-B2": {
        "ci_id": "GCE-DEV-B2", "ci_type": "CloudInstance", "hostname": "gcp-test-b2",
        "ip_address": ["10.128.0.5"], "ci_status": "Stopped", "business_criticality": "Low",
        "service_id": "SVC-DEV-002", "owner_team": "Dev Team", "cloud_provider": "GCP",
        "region": "asia-east1", "instance_type": "e2-small", "os_version": "Debian 10"
    },
    "AZR-ANL-C3": {
        "ci_id": "AZR-ANL-C3", "ci_type": "CloudInstance", "hostname": "azr-etl-c3",
        "ip_address": ["40.1.1.1"], "ci_status": "Running", "business_criticality": "Medium",
        "service_id": "SVC-ANALYTICS-004", "owner_team": "Data Team", "cloud_provider": "Azure",
        "region": "East Asia", "instance_type": "Standard D4s v3", "os_version": "Windows Server 2019"
    },
    "EC2-DR-04": {
        "ci_id": "EC2-DR-04", "ci_type": "CloudInstance", "hostname": "aws-dr-04",
        "ip_address": ["172.31.20.10"], "ci_status": "Running", "business_criticality": "High",
        "service_id": "SVC-ECOM-001", "owner_team": "CloudOps", "cloud_provider": "AWS",
        "region": "ap-southeast-2", "instance_type": "t3.medium", "os_version": "Amazon Linux 2"
    },
    "GCE-ML-05": {
        "ci_id": "GCE-ML-05", "ci_type": "CloudInstance", "hostname": "gcp-ml-worker",
        "ip_address": ["10.128.0.6"], "ci_status": "Running", "business_criticality": "Medium",
        "service_id": "SVC-AI-005", "owner_team": "AI Team", "cloud_provider": "GCP",
        "region": "us-central1", "instance_type": "n1-standard-8", "os_version": "CentOS 7"
    }
}


class CMDB(object):
    """
    Simulates an enterprise-level CMDB interface, focusing on providing contextual search functions for SOC.
    This class is designed to provide a reliable tool interface for LLM Agents for security incident response and investigation.
    """

    def __init__(self, data: Dict[str, Any]):
        """
        Initializes the CMDB simulator, building multiple indexes to support efficient lookups.
        """
        self._data = data
        self._ip_map = {}
        self._hostname_map = {}
        self._mac_map = {}

        # Build an index for fast CI ID lookup by IP, Hostname, etc.
        for ci_id, ci in data.items():
            ci["ci_id"] = ci_id  # Ensure ci_id exists in every CI

            # Index IP addresses (supports multiple IPs)
            for ip in ci.get("ip_address", []):
                self._ip_map[ip] = ci_id

            # Index Hostname
            if ci.get("hostname"):
                self._hostname_map[ci["hostname"]] = ci_id

            # Index MAC address
            if ci.get("mac_address"):
                self._mac_map[ci["mac_address"]] = ci_id

    def _find_ci(self, identifier_type: str, identifier_value: str) -> Optional[Dict[str, Any]]:
        """Internal method: Find CI data by identifier, return the complete CI dictionary"""
        ci_id = None
        identifier_value = identifier_value.strip()

        if identifier_type == "ip_address":
            ci_id = self._ip_map.get(identifier_value)
        elif identifier_type == "hostname":
            ci_id = self._hostname_map.get(identifier_value)
        elif identifier_type == "mac_address":
            ci_id = self._mac_map.get(identifier_value)
        elif identifier_type == "ci_id":
            ci_id = identifier_value

        return self._data.get(ci_id) if ci_id else None

    # --- 1. Core common retrieval interface ---

    def get_ci_context(self,
                       identifier_type: Annotated[str, "The type of identifier used for the query, accepts 'ip_address', 'hostname', 'mac_address', 'ci_id' or 'user_id'"],
                       identifier_value: Annotated[str, "The specific value of the identifier, for example '192.168.10.5' or 'prod-web-01'"]
                       ) -> Annotated[Dict[str, Any], "The complete dictionary data of a single matched CI, including hundreds of attributes such as business criticality, owner team, etc."]:
        """
        [A. Exact Identifier Retrieval]: Retrieves the complete contextual information of a single configuration item (CI) based on an exact identifier (IP, hostname, CI ID, or user ID).
        This interface is used to quickly associate technical indicators in alarms with specific business assets when a security incident occurs.
        If the CI cannot be found, a LookupError is thrown.
        """
        if not identifier_type or not identifier_value:
            raise ValueError("Identifier type and value cannot be empty.")

        ci_data = self._find_ci(identifier_type, identifier_value)

        if not ci_data:
            # Add support for finding employee CIs
            if identifier_type == "user_id":
                for ci_data in self._data.values():
                    if ci_data.get("ci_type") == "Employee" and ci_data.get("user_id") == identifier_value:
                        return ci_data

            raise LookupError(f"CI not found for {identifier_type}: {identifier_value}")

        return ci_data

    def fuzzy_search_ci(self,
                        partial_hostname: Annotated[Optional[str], "Partial hostname fragment, e.g. 'prod-'. If provided, a partial match will be performed."] = None,
                        regex_pattern: Annotated[Optional[str], "Regular expression for advanced matching"] = None
                        ) -> Annotated[List[Dict[str, Any]], "A list of matched CIs, returning only CI ID, CI type, hostname, and business criticality."]:
        """
        [B. Fuzzy/Partial Match Retrieval]: Retrieves a list of matching configuration items (CIs) based on a partial hostname or regular expression.
        This interface is used to quickly determine the scope of assets (e.g., finding all AWS EC2 instances) when asset names are incomplete or need to be found according to a specific pattern.
        If neither partial_hostname nor regex_pattern is provided, a ValueError is thrown.
        """
        if not partial_hostname and not regex_pattern:
            raise ValueError("Either partial_hostname or regex_pattern must be provided.")

        matching_cis = []

        for ci_data in self._data.values():
            hostname = ci_data.get("hostname", ci_data.get("ci_id", ""))
            match = False

            if partial_hostname and partial_hostname.lower() in hostname.lower():
                match = True

            if regex_pattern:
                try:
                    if hostname and re.search(regex_pattern, hostname):
                        match = True
                except re.error as e:
                    raise ValueError(f"Invalid regular expression: {e}")

            if match:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ci_type": ci_data.get("ci_type"),
                    "business_criticality": ci_data.get("business_criticality"),
                    "hostname": hostname
                })

        return matching_cis

    # --- 2. Software/port association retrieval interface ---

    def get_cis_by_software(self,
                            software_name: Annotated[str, "The name of the software to find, for example 'nginx' or 'java'"],
                            version: Annotated[Optional[str], "Optional software version number, for example '11' or '1.20.1'. If not provided, all versions will be matched."] = None
                            ) -> Annotated[List[Dict[str, Any]], "A list of CIs running the specified software, including CI ID, IP address, CI type, and business criticality."]:
        """
        [C. Software Version Retrieval]: Retrieves a list of configuration items (CIs) running a specific software or software version.
        This interface is used in the vulnerability management process to quickly determine which assets are affected by known software vulnerabilities (such as Log4j, specific versions of Tomcat).
        """
        if not software_name:
            raise ValueError("Software name cannot be empty.")

        matching_cis = []
        for ci_data in self._data.values():
            software_list = ci_data.get("installed_software", [])
            for software in software_list:
                name_match = software["name"].lower() == software_name.lower()
                version_match = (version is None or software["version"] == version)

                if name_match and version_match:
                    matching_cis.append({
                        "ci_id": ci_data.get("ci_id"),
                        "ip_address": ci_data.get("ip_address"),
                        "ci_type": ci_data.get("ci_type"),
                        "business_criticality": ci_data.get("business_criticality")
                    })
                    break

        return matching_cis

    def get_cis_by_port(self,
                        port_number: Annotated[int, "The port number to find, for example 22 or 3306"],
                        protocol: Annotated[str, "Port protocol, for example 'TCP' or 'UDP', defaults to 'TCP'"] = "TCP"
                        ) -> Annotated[List[Dict[str, Any]], "A list of CIs that open the specified port and protocol, including CI ID, IP address, and network zone."]:
        """
        [D. Open Port Retrieval]: Retrieves a list of configuration items (CIs) that have a specific port and protocol open.
        This interface is used for security audits to quickly identify misconfigured assets or assets with unauthorized externally open services.
        """
        if not isinstance(port_number, int) or port_number <= 0:
            raise ValueError("Invalid port number.")

        matching_cis = []
        for ci_data in self._data.values():
            ports = ci_data.get("open_ports", [])
            for port_info in ports:
                if port_info["port"] == port_number and port_info["protocol"].upper() == protocol.upper():
                    matching_cis.append({
                        "ci_id": ci_data.get("ci_id"),
                        "ip_address": ci_data.get("ip_address"),
                        "network_zone": ci_data.get("network_zone")
                    })
                    break

        return matching_cis

    # --- 3. Business service association retrieval interface ---

    def get_cis_by_service(self,
                           service_id: Annotated[str, "The business service ID to query, for example 'SVC-ECOM-001'"]
                           ) -> Annotated[List[Dict[str, Any]], "A list of all underlying CIs that support the business service, including CI ID, IP address, CI type, and business criticality."]:
        """
        [E. Business Service Query]: Retrieves a list of all underlying configuration items (CIs) that support a specific critical business service.
        This interface is used for advanced impact analysis to quickly find all related servers, databases, and cloud instances when a business service alarm occurs.
        """
        if not service_id:
            raise ValueError("Service ID cannot be empty.")

        matching_cis = []
        for ci_data in self._data.values():
            # Exclude personnel and domain names, focus only on technical assets
            if ci_data.get("service_id") == service_id and ci_data.get("ci_type") not in ["Employee", "DomainName"]:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ip_address": ci_data.get("ip_address"),
                    "ci_type": ci_data.get("ci_type"),
                    "business_criticality": ci_data.get("business_criticality")
                })

        return matching_cis

    def get_cis_by_user(self,
                        user_id: Annotated[str, "The user ID to query, for example 'user_a'"]
                        ) -> Annotated[List[Dict[str, Any]], "A list of all CIs associated with the user, including employee profiles, primary PCs/workstations, or primarily responsible servers."]:
        """
        [F. User/Responsible Person Query]: Retrieves a list of all configuration items (CIs) primarily used by or responsible for by a specific user.
        This interface is used for user-related security incidents (such as phishing, credential leakage) to quickly locate all the user's related assets for isolation or forensics.
        If the associated CI or user profile cannot be found, a LookupError is thrown.
        """
        if not user_id:
            raise ValueError("User ID cannot be empty.")

        matching_cis = []
        found_profile = False

        for ci_data in self._data.values():
            # Find employee profile
            if ci_data.get("ci_type") == "Employee" and ci_data.get("user_id") == user_id:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ci_type": "Employee Profile",
                    "employee_name": ci_data.get("employee_name"),
                    "user_role": "Self"
                })
                found_profile = True

            # Find assets (PC, DB, etc.)
            if ci_data.get("primary_user_id") == user_id:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ci_type": ci_data.get("ci_type"),
                    "hostname": ci_data.get("hostname", ci_data.get("ci_id")),
                    "user_role": "Primary User"
                })

        if not matching_cis and not found_profile:
            raise LookupError(f"No CI found associated with user_id: {user_id}")

        return matching_cis


# 1. Create a CMDB instance
cmdb_instance = CMDB(EXTENDED_CMDB_DATA)


# 2. Bind instance methods to global function variables for use by LangChain Agent.
# This method is optimal because it preserves Annotated Type Hints and Docstrings.

def get_ci_context_tool(
        identifier_type: Annotated[str, "The type of identifier used for the query, accepts 'ip_address', 'hostname', 'mac_address', 'ci_id' or 'user_id'"],
        identifier_value: Annotated[str, "The specific value of the identifier, for example '192.168.10.5' or 'prod-web-01'"]
) -> Annotated[Dict[str, Any], "The complete dictionary data of a single matched CI, including hundreds of attributes such as business criticality, owner team, etc."]:
    """
    Retrieves the complete contextual information of a single configuration item (CI) based on an exact identifier (IP, hostname, CI ID, or user ID).
    This interface is used to quickly associate technical indicators in alarms with specific business assets when a security incident occurs.
    """
    return cmdb_instance.get_ci_context(identifier_type, identifier_value)


def fuzzy_search_ci_tool(
        partial_hostname: Annotated[Optional[str], "Partial hostname fragment, e.g. 'prod-'. If provided, a partial match will be performed."] = None,
        regex_pattern: Annotated[Optional[str], "Regular expression for advanced matching, for example 'aws-\\d+'. Choose one from partial_hostname."] = None
) -> Annotated[List[Dict[str, Any]], "A list of matched CIs, returning only CI ID, CI type, hostname, and business criticality."]:
    """
    Retrieves a list of matching configuration items (CIs) based on a partial hostname or regular expression.
    This interface is used to quickly determine the scope of assets (e.g., finding all AWS EC2 instances) when asset names are incomplete or need to be found according to a specific pattern.
    """
    return cmdb_instance.fuzzy_search_ci(partial_hostname, regex_pattern)


def get_cis_by_software_tool(
        software_name: Annotated[str, "The name of the software to find, for example 'nginx' or 'java'"],
        version: Annotated[Optional[str], "Optional software version number, for example '11' or '1.20.1'. If not provided, all versions will be matched."] = None
) -> Annotated[List[Dict[str, Any]], "A list of CIs running the specified software, including CI ID, IP address, CI type, and business criticality."]:
    """
    Retrieves a list of configuration items (CIs) running a specific software or software version.
    This interface is used in the vulnerability management process to quickly determine which assets are affected by known software vulnerabilities.
    """
    return cmdb_instance.get_cis_by_software(software_name, version)


def get_cis_by_port_tool(
        port_number: Annotated[int, "The port number to find, for example 22 or 3306"],
        protocol: Annotated[str, "Port protocol, for example 'TCP' or 'UDP', defaults to 'TCP'"] = "TCP"
) -> Annotated[List[Dict[str, Any]], "A list of CIs that open the specified port and protocol, including CI ID, IP address, and network zone."]:
    """
    Retrieves a list of configuration items (CIs) that have a specific port and protocol open.
    This interface is used for security audits to quickly identify misconfigured assets or assets with unauthorized externally open services.
    """
    return cmdb_instance.get_cis_by_port(port_number, protocol)


def get_cis_by_service_tool(
        service_id: Annotated[str, "The business service ID to query, for example 'SVC-ECOM-001'"]
) -> Annotated[List[Dict[str, Any]], "A list of all underlying CIs that support the business service, including CI ID, IP address, CI type, and business criticality."]:
    """
    Retrieves a list of all underlying configuration items (CIs) that support a specific critical business service.
    This interface is used for advanced impact analysis to quickly find all related servers, databases, and cloud instances when a business service alarm occurs.
    """
    return cmdb_instance.get_cis_by_service(service_id)


def get_cis_by_user_tool(
        user_id: Annotated[str, "The user ID to query, for example 'user_a'"]
) -> Annotated[List[Dict[str, Any]], "A list of all CIs associated with the user, including employee profiles, primary PCs/workstations, or primarily responsible servers."]:
    """
    Retrieves a list of all configuration items (CIs) primarily used by or responsible for by a specific user.
    This interface is used for user-related security incidents (such as phishing, credential leakage) to quickly locate all the user's related assets for isolation or forensics.
    """
    return cmdb_instance.get_cis_by_user(user_id)



