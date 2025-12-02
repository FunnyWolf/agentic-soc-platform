import random
from datetime import datetime
from typing import Dict, Literal


class TI:
    """
    模拟威胁情报查询。
    支持 IP, Domain, Hash。
    """

    # 预定义的恶意指标 (IOCs)
    KNOWN_THREATS = {
        "192.168.1.100": {  # 假设这是攻击源
            "score": 85,
            "verdict": "Malicious",
            "categories": ["Botnet", "Brute Force Source"],
            "country": "Unknown",
            "asn": "AS12345 BadISP",
            "last_analysis_date": "2025-11-29"
        },
        "45.33.22.11": {  # 假设这是 C2
            "score": 98,
            "verdict": "Malicious",
            "categories": ["C2 Server", "Cobalt Strike"],
            "country": "Ruritania",
            "asn": "AS666 CyberCrime",
            "tags": ["APT-29", "CozyBear"]
        }
    }

    @staticmethod
    def lookup(
            ioc_type: Literal["ip", "domain", "hash", "url"],
            ioc_value: str
    ) -> Dict:
        """
        Check Threat Intelligence reputation for an artifact.

        Args:
            ioc_type: The type of IOC. Supported: 'ip', 'domain', 'hash', 'url'.
            ioc_value: The value of the IOC (e.g., '1.1.1.1' or 'a1b2...').

        Returns:
            Threat intelligence report including risk score and categories.
        """
        print(f"   [🔧 TI Tool] Checking: type={ioc_type}, value={ioc_value}")

        # 1. 匹配剧本数据
        if ioc_value in TI.KNOWN_THREATS:
            return {"status": "found", "data": TI.KNOWN_THREATS[ioc_value]}

        # 2. 默认 Mock：大部分查询都是干净的 (Benign)
        # 偶尔随机生成一个低风险分数，增加真实感
        risk_score = 0 if random.random() > 0.1 else random.randint(5, 15)

        return {
            "status": "found",
            "data": {
                "score": risk_score,
                "verdict": "Benign" if risk_score < 30 else "Suspicious",
                "categories": ["Uncategorized"] if risk_score == 0 else ["Spam"],
                "country": random.choice(["US", "CN", "DE", "JP"]),
                "last_analysis_date": datetime.now().strftime("%Y-%m-%d")
            }
        }
