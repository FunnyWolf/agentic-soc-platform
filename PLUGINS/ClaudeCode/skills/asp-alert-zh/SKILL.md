---
name: asp-alert-zh
description: '审查 ASP 告警、更新 AI 分析字段、查看告警讨论。'
argument-hint: 'review alert <alert_id> | list alerts [filters] | update alert <alert_id> <fields>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ alert-management, soc, triage, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Alert

当用户要围绕 ASP 告警开展 SOC 分析工作时，使用这个 skill。
Alert 是 ASP 中的二级数据,每个 Alert 都会挂载到一个 Case,一个 Alert 会挂载一个或多个 Artifact。

## 适用场景

- 用户给出一个告警 ID，希望快速查看、审查或总结。
- 用户希望按状态、严重级别、置信度或 correlation UID 查找告警。
- 用户想查看某条告警的分析讨论内容。
- 用户想更新告警上的 AI 分析字段。
- 用户想在分析后把 enrichment 附加到告警。

## 运行规则

- 回复要聚焦于分诊价值，而不是原样回显 schema 字段。

## 补充信息

- rowid 为每条告警记录的UUID,用于数据关联. alert_id 是每条告警记录人类可读的唯一ID

## 决策流程

1. 如果用户提供了具体告警 ID，或要求“open”“show”“review”“summarize”某条告警，调用 `list_alerts(alert_id=<id>, limit=1)`。
2. 如果用户要求讨论上下文，在取回告警后调用 `get_alert_discussions(alert_id)`。
3. 如果用户要浏览或对比多条告警，使用带支持过滤条件的 `list_alerts`。
4. 如果用户要更新 AI severity、AI confidence 或 AI comment，调用 `update_alert`。
5. 如果用户要附加分析结果、情报或结构化上下文，使用 `asp-enrichment-zh` skill。

## SOP

### 审查单条告警

1. 如果用户要求审查、分析或查看告警详情，调用 `list_alerts(alert_id=<id>, limit=1, lazy_load=false)` 获取完整关联数据。
2. 如果只需要快速查看告警基本信息，调用 `list_alerts(alert_id=<id>, limit=1)` 即可。
3. 如果结果为空，直接说明找不到该告警。
4. 解析第一条 JSON 记录。
5. 如果用户要求分析讨论上下文，调用 `get_alert_discussions(alert_id)`。
6. 只呈现最有价值的分诊字段。

首选回复结构：

- `Alert`：alert ID、标题或名称、严重级别、状态、置信度、correlation UID。
- `Timeline`：存在时给出创建或更新时间。
- `Key Context`：来源、规则、类别、负责人或其他高信号字段。
- `Discussions`：只在需要时给出最相关的分析或系统备注。
- `Assessment`：简短分诊判断。

### 列出告警

1. 提取支持的过滤字段：`alert_id`、`status`、`severity`、`confidence`、`correlation_uid`、`limit`。
2. 在调用 MCP 前，把自然语言过滤条件规范化。
3. 调用 `list_alerts`。
4. 解析返回的 JSON 字符串。
5. 以紧凑对比视图呈现。

首选回复结构：

| Alert ID | Title | Severity | Status | Confidence | First Seen | Rule Name |
|----------|-------|----------|--------|------------|------------|-----------|

然后在需要时补一句简短解释。

### 更新告警 AI 字段

1. 要求提供 `alert_id`。
2. 只提取支持的 AI 字段：`severity_ai`、`confidence_ai`、`comment_ai`。
3. 仅带变更字段调用 `update_alert`。
4. 如果结果为 `None`，说明找不到该告警。
5. 只确认实际修改的字段。

## 澄清规则

- 只有在缺少告警相关操作所需参数时才询问 `alert_id`。
- 只有当请求值不能清晰映射到 ASP 枚举时，才要求用户澄清枚举值。
- 如果用户说“降低 confidence”“提高 severity”或“留个备注”，在意图明确时直接映射到对应 AI 字段。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出原始 JSON。
- 优先使用分诊语义，而不是 schema 语义。
- 如果同时用了告警数据和讨论内容，要合并成一个连贯视图。
- 清楚指出阻塞项：告警不存在、不支持的过滤条件、无效枚举值，或不完整的追加载荷。

## 失败处理

- 如果告警不存在，直接说明。
- 如果过滤无结果，直接说明并建议最有用的收敛方式。
- 如果请求更新的字段不受支持，明确指出哪些告警字段是可写的。
