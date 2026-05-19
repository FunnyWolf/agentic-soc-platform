import re

import requests

from PLUGINS.AlienVaultOTX.CONFIG import API_KEY, HTTP_PROXY

MAX_PULSE_SUMMARIES = 5
MAX_LIST_ITEMS = 12


class AlienVaultOTX(object):
    headers = {
        "accept": "application/json",
        "X-OTX-API-KEY": API_KEY
    }
    base_url = "https://otx.alienvault.com/api/v1"

    def __init__(self):
        pass

    @classmethod
    def query(cls, indicator: str) -> dict:
        indicator = indicator.strip()

        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, indicator):
            parts = indicator.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                result = cls.query_ip(indicator)
                return result

        if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', indicator):
            result = cls.query_file(indicator)
            return result

        url_pattern = r'^(https?://|ftp://|www\.)'
        domain_pattern = r'\.'
        if re.match(url_pattern, indicator, re.IGNORECASE) or (re.search(domain_pattern, indicator) and '/' in indicator):
            result = cls.query_url(indicator)
            return result

        return {
            "error": "Unable to determine indicator type. Please provide a valid IP address, URL, or file hash.",
            "input": indicator
        }

    @classmethod
    def query_ip(cls, ip: str) -> dict:
        """
        查询指定 IP 地址的威胁情报信息

        Args:
            ip (str): 要查询的 IPv4 地址，格式为标准 IP 地址（如 "192.168.1.1"）

        Returns:
            dict: 包含以下字段的字典：
                - reputation_score (int): 计算得出的信誉分数，负数表示有风险，0或正数表示无风险
                - pulse_info (dict): 脉冲信息，包含相关威胁情报
                - validation (list): 验证信息列表
                - false_positive (list): 误报标记列表
                - error (str): 如果请求失败，返回错误信息
        """

        url = f"{cls.base_url}/indicators/IPv4/{ip}/general"
        req_result = cls._get(url)
        if req_result.get("error"):
            return cls.summarize_result(req_result, "ip", ip)
        req_result["reputation_score"] = cls.calculate_reputation_score(req_result)
        return cls.summarize_result(req_result, "ip", ip)

    @classmethod
    def query_url(cls, url: str) -> dict:
        """
        查询指定 URL 的威胁情报信息（不主动请求目标 URL）

        Args:
            url (str): 要查询的 URL 地址，格式为完整 URL（如 "http://example.com/path"）

        Returns:
            dict: 包含以下字段的字典：
                - original_url (str): 原始输入的 URL 地址
                - pulse_info (dict): 脉冲信息，包含相关威胁情报
                - validation (list): 验证信息列表
                - false_positive (list): 误报标记列表
                - error (str): 如果请求失败，返回错误信息
        """
        try:
            encoded_url = requests.utils.quote(url, safe='')
            otx_url = f"{cls.base_url}/indicators/url/{encoded_url}/general"

            result = cls._get(otx_url)
            return cls.summarize_result(result, "url", url)
        except Exception as e:
            return {"error": str(e)}

    @classmethod
    def query_file(cls, file_hash: str) -> dict:
        """
        查询指定文件哈希的威胁情报信息

        Args:
            file_hash (str): 文件的哈希值

        Returns:
            dict: 包含以下字段的字典：
                - reputation_score (int): 计算得出的信誉分数，负数表示有风险，0或正数表示无风险
                - pulse_info (dict): 脉冲信息，包含相关威胁情报
                - validation (list): 验证信息列表
                - false_positive (list): 误报标记列表
                - error (str): 如果哈希格式无效或请求失败，返回错误信息
        """
        hash_length = len(file_hash)
        if hash_length == 32:
            hash_type = "MD5"
        elif hash_length == 40:
            hash_type = "SHA1"
        elif hash_length == 64:
            hash_type = "SHA256"
        else:
            return {"error": "Invalid hash length. Must be 32 (MD5), 40 (SHA1), or 64 (SHA256)."}

        url = f"{cls.base_url}/indicators/file/{file_hash}/general"
        req_result = cls._get(url)
        if req_result.get("error"):
            return cls.summarize_result(req_result, "file", file_hash)
        req_result["reputation_score"] = cls.calculate_reputation_score(req_result)
        return cls.summarize_result(req_result, "file", file_hash)

    @classmethod
    def summarize_result(cls, attributes: dict, indicator_type: str, indicator: str) -> dict:
        if attributes.get("error"):
            return {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "provider": "AlienVault OTX",
                "error": attributes.get("error"),
            }

        pulse_info = attributes.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        reputation_score = attributes.get("reputation_score")
        pulse_count = pulse_info.get("count", len(pulses))

        summary = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "provider": "AlienVault OTX",
            "risk_level": cls._risk_level(reputation_score, pulse_count),
            "reputation_score": reputation_score,
            "pulse_count": pulse_count,
            "tags": cls._limit_list(cls._unique_items(tag for pulse in pulses for tag in pulse.get("tags", []))),
            "attack_techniques": cls._limit_list(cls._extract_attack_techniques(pulses)),
            "malware_families": cls._limit_list(cls._extract_related_values(pulse_info, "malware_families")),
            "adversaries": cls._limit_list(cls._extract_related_values(pulse_info, "adversary")),
            "industries": cls._limit_list(cls._extract_related_values(pulse_info, "industries")),
            "validation": cls._compact_named_items(attributes.get("validation") or []),
            "false_positive": cls._compact_named_items(attributes.get("false_positive") or []),
            "pulses": cls._compact_pulses(pulses),
        }

        network_context = cls._network_context(attributes)
        if network_context:
            summary["network_context"] = network_context

        return summary

    @staticmethod
    def _unique_items(items) -> list:
        unique = []
        for item in items:
            if item and item not in unique:
                unique.append(item)
        return unique

    @staticmethod
    def _limit_list(items: list, limit: int = MAX_LIST_ITEMS) -> list:
        return items[:limit]

    @classmethod
    def _extract_attack_techniques(cls, pulses: list) -> list:
        techniques = []
        for pulse in pulses:
            for attack in pulse.get("attack_ids", []) or []:
                display_name = attack.get("display_name") or attack.get("name") or attack.get("id")
                if display_name:
                    techniques.append(display_name)
        return cls._unique_items(techniques)

    @classmethod
    def _extract_related_values(cls, pulse_info: dict, key: str) -> list:
        related = pulse_info.get("related") or {}
        values = []
        for source in ("alienvault", "other"):
            values.extend((related.get(source) or {}).get(key, []) or [])
        return cls._unique_items(values)

    @classmethod
    def _compact_named_items(cls, items: list) -> list:
        compact = []
        for item in items:
            if isinstance(item, dict):
                value = item.get("name") or item.get("source") or item.get("description")
                if value:
                    compact.append(value)
            elif item:
                compact.append(item)
        return cls._limit_list(cls._unique_items(compact))

    @classmethod
    def _compact_pulses(cls, pulses: list) -> list:
        compact = []
        for pulse in pulses[:MAX_PULSE_SUMMARIES]:
            compact.append({
                "name": pulse.get("name"),
                "description": pulse.get("description"),
                "tags": cls._limit_list(pulse.get("tags", [])),
                "attack_techniques": cls._limit_list(cls._extract_attack_techniques([pulse])),
                "malware_families": cls._limit_list(pulse.get("malware_families", []) or []),
                "adversary": pulse.get("adversary"),
                "created": pulse.get("created"),
                "modified": pulse.get("modified"),
                "tlp": pulse.get("TLP"),
            })
        return compact

    @staticmethod
    def _network_context(attributes: dict) -> dict:
        context = {}
        for field in ("asn", "country_name", "country_code", "region", "city"):
            if attributes.get(field):
                context[field] = attributes.get(field)
        return context

    @staticmethod
    def _risk_level(reputation_score, pulse_count: int) -> str:
        score = reputation_score or 0
        if score >= 50 or pulse_count >= 5:
            return "high"
        if score >= 20 or pulse_count > 0:
            return "medium"
        return "low"

    @classmethod
    def _get(cls, url: str) -> dict:
        """通用 GET 请求方法"""
        try:
            if HTTP_PROXY is not None:
                proxies = {
                    "http": HTTP_PROXY,
                    "https": HTTP_PROXY,
                }
            else:
                proxies = {}
            resp = requests.get(url, headers=cls.headers, proxies=proxies, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    @classmethod
    def calculate_reputation_score(cls, attributes: dict) -> int:
        """
        重新计算OTX的reputation分值(简化版)

        Returns:
            int: reputation分值
            - 负数: 有风险
            - 0或正数: 无风险/低风险
        """
        score = 0

        # 1. 脉冲信息分析(核心指标)
        pulse_info = attributes.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        pulses = pulse_info.get('pulses', [])

        # 脉冲数量越多说明被更多威胁情报引用
        score -= pulse_count * 10  # 每个脉冲 -10分

        # 2. 相关威胁信息
        related = pulse_info.get('related', {})

        # 恶意软件家族
        malware_families = related.get('alienvault', {}).get('malware_families', []) + \
                           related.get('other', {}).get('malware_families', [])
        score -= len(malware_families) * 15  # 每个恶意软件家族 -15分

        # 对手/攻击者
        adversaries = related.get('alienvault', {}).get('adversary', []) + \
                      related.get('other', {}).get('adversary', [])
        score -= len(adversaries) * 12  # 每个攻击者 -12分

        # 3. 验证信息
        validation = attributes.get('validation', [])
        for val in validation:
            if val.get('name') == 'whitelist':
                score += 20  # 白名单 +20分
            elif val.get('name') == 'blacklist':
                score -= 25  # 黑名单 -25分

        # 4. 误报标记
        false_positive = attributes.get('false_positive', [])
        if false_positive:
            score += len(false_positive) * 10  # 每个误报标记 +10分

        # 5. 脉冲详细分析
        for pulse in pulses:
            # 检查脉冲标签中的威胁关键词
            tags = pulse.get('tags', [])
            threat_tags = ['malware', 'trojan', 'backdoor', 'botnet', 'apt', 'exploit']
            for tag in tags:
                if tag.lower() in threat_tags:
                    score -= 8  # 每个威胁标签 -8分

        return -score
