---
name: asp-artifact-zh
description: '按 IOC 查找 artifact'
argument-hint: 'review artifact <artifact_id> | list artifacts [filters]'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ artifact, pivot, enrichment, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Artifact

当用户要围绕 artifact 进行调查分析时，使用这个 skill。
artifact 由系统自动创建，用户只能查询和分析已有 artifact，并通过 enrichment 保存分析结果。

## 适用场景

- 用户想按 value、type、role、owner 或 reputation 查找 artifact。
- 用户想给 artifact 附加 enrichment 或结构化分析。

## 运行规则

- 把 artifact 视为平台里的最小调查对象。
- 查询和审查时使用 `list_artifacts`。
- 如果用户想把分析结果保存到 artifact 本身，使用 `create_enrichment` 加 `attach_enrichment_to_target`。
- 如需完整的 enrichment 持久化流程，使用 `asp-enrichment-zh` skill。

## 补充信息

- row_id 为每条 artifact 记录的UUID,用于数据关联. artifact_id 是每条 artifact 记录人类可读的唯一ID

## 决策流程

1. 如果用户要查找或审查 artifact，调用 `list_artifacts`。
2. 如果用户要为 artifact 附加情报、分析笔记或结构化分析，使用 `asp-enrichment-zh` skill。
3. 如果用户正从 artifact 出发进行调查，把 artifact 作为最小调查对象，只在必要时建议下一个最有价值的跳转点。

## SOP

### 列出 Artifact

1. 从请求中提取最窄且最有用的过滤条件。
2. 调用 `list_artifacts`。
3. 解析返回的 JSON 字符串。
4. 以紧凑的 artifact 视图呈现；如果用户大概率下一步要附加或复用该 artifact，则显式展示 artifact row_id。

首选回复结构：

| Artifact ID | Value | Type | Role | Owner | Reputation | Summary |
|-------------|-------|------|------|-------|------------|---------|

然后在需要时补一句简短解释。

## 澄清规则

- 只有当用户要 enrich 现有 artifact 却未提供时，才询问 `artifact_id`。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出原始 JSON。
- 优先使用 pivot 语义，而不是存储语义。
- 当匹配的 artifact 很多时，展示最有价值的一小部分，并简要说明整体模式。

## 失败处理

- 如果没有匹配的 artifact，直接说明，并建议最有用的收敛方式。
- 如果目标 artifact 不存在，直接说明。

