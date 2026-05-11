Please analyze the following security event data and generate the final investigation report strictly in Markdown
format.

<alert_data>
{alert_data}
</alert_data>

<threat_intel>
{threat_intel}
</threat_intel>

<siem_logs>
{siem_logs}
</siem_logs>

# Output Structure

You MUST format your report using the following exact structure:

## 1. 研判结论 (Conclusion)

* **定性**: [True Positive / False Positive / Benign / Suspicious]
* **严重等级**: [Critical / High / Medium / Low / Informational]

## 2. 执行摘要 (Executive Summary)

Provide a concise 2-3 sentence summary of the incident. What happened, who is involved, and was it successful?

## 3. 攻击链路与证据 (Attack Timeline & Evidence)

Detail the sequence of events based on the SIEM logs and TI. You must extract and quote specific log snippets, IPs, or
timestamps from the logs above to back up your claims. Show the attack chain with exact values from the logs.

## 4. 影响面评估 (Impact Assessment)

Describe the potential or actual impact on the internal assets. Did the attack succeed? Are internal hosts compromised?

## 5. 处置建议 (Remediation Recommendations)

List highly actionable steps to mitigate the threat (e.g., Block IP x.x.x.x on firewall, isolate host Y, etc).
