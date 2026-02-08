import requests

from PLUGINS.AlienVaultOTX.CONFIG import API_KEY, HTTP_PROXY


class AlienVaultOTX(object):
    headers = {
        "accept": "application/json",
        "X-OTX-API-KEY": API_KEY
    }
    base_url = "https://otx.alienvault.com/api/v1"

    def __init__(self):
        pass

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
        req_result["reputation_score"] = cls.calculate_reputation_score(req_result)
        return req_result

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
            if result and not result.get('error'):
                result['original_url'] = url
            return result
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
        req_result["reputation_score"] = cls.calculate_reputation_score(req_result)
        return req_result

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
                proxies = None
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


if __name__ == "__main__":
    target_ip = "66.240.205.34"
    result = AlienVaultOTX.query_ip(target_ip)
    print(result)
