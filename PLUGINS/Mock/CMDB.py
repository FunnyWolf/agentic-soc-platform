import random
from typing import Dict, Optional


class CMDB:
    """
    模拟企业内部资产管理系统。
    包含预定义的关键资产（剧本需要），其他查询动态生成。
    """

    # 预定义的高价值目标 (High Value Targets)
    KNOWN_ASSETS = {
        "10.67.3.130": {
            "hostname": "FIN-PAYMENT-SRV-01",
            "os": "Red Hat Enterprise Linux 8.4",
            "business_unit": "Finance Dept",
            "owner": "Sarah Connor",
            "criticality": "Critical",
            "location": "DataCenter-HK-ZoneA",
            "tags": ["PCI-DSS", "Payment-Gateway"],
            "last_seen": "2025-11-30"
        },
        "10.67.3.131": {
            "hostname": "FIN-DB-SRV-01",
            "os": "Windows Server 2019",
            "business_unit": "Finance Dept",
            "owner": "John Doe",
            "criticality": "High",
            "location": "DataCenter-HK-ZoneA",
            "tags": ["Database", "Internal-Only"]
        }
    }

    @staticmethod
    def query_asset(
            ip: Optional[str] = None,
            hostname: Optional[str] = None,
            owner: Optional[str] = None
    ) -> Dict:
        """
        Query internal asset information from CMDB.

        Args:
            ip: The IP address to search for (e.g., '10.67.3.130').
            hostname: The hostname to search for (e.g., 'WEB-SRV-01').
            owner: The email or name of the asset owner.

        Returns:
            A dictionary containing asset details. Returns {"status": "not_found"} if no match.
        """
        print(f"   [🔧 CMDB Tool] Querying: ip={ip}, hostname={hostname}")

        # 1. 优先匹配预定义剧本数据
        if ip and ip in CMDB.KNOWN_ASSETS:
            return {"status": "success", "data": CMDB.KNOWN_ASSETS[ip]}

        # 2. 如果是内网 IP (10.x, 192.168.x)，动态生成一个看起来像真的资产
        if ip and (ip.startswith("10.") or ip.startswith("192.168.")):
            # 动态 Mock
            mock_data = {
                "hostname": f"WORKSTATION-{random.randint(1000, 9999)}",
                "os": random.choice(["Windows 10 Enterprise", "macOS Sonoma"]),
                "business_unit": random.choice(["HR", "IT Support", "Sales"]),
                "owner": f"user_{random.randint(1, 100)}@company.com",
                "criticality": "Low",
                "location": "Office-Building-B",
                "tags": ["EndUser-Device"]
            }
            return {"status": "success", "data": mock_data}

        # 3. 外网 IP 或未找到
        return {"status": "not_found", "message": f"No asset found for ip={ip}"}
