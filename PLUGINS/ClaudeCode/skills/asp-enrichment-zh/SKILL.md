---
name: asp-enrichment-zh
description: '把结构化数据保存为 enrichment，并附加到 case、alert 或 artifact。'
argument-hint: 'create enrichment for <case|alert|artifact> <target_id> | attach enrichment to <case|alert|artifact> <target_id>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ enrichment, analysis, context, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Enrichment

当数据需要以结构化上下文形式保存回 ASP 且挂载到对应 case , alert 或 artifact 时，使用这个 skill。

## 适用场景

- 用户想保存结构化分析、情报或调查结论。
- 用户想把上下文附加到 case、alert 或 artifact。
- 用户想持久化 SIEM 发现、威胁情报、资产上下文或分析师结论。
- 用户已经有 enrichment，希望把它复用并附加到目标对象。

## 运行规则

- 把 enrichment 视为平台的结构化结果层，而不是普通评论字段。
- 当目标是把分析结果持久化到 `case`、`alert` 或 `artifact` 上时，使用这个 skill。
- 区分“创建 enrichment”和“附加 enrichment”两个动作。
- 新结果记录使用 `create_enrichment`。
- 只有在已经拿到 enrichment row ID 后，才使用 `attach_enrichment_to_target`。
- enrichment payload 保持紧凑且可操作。
- 查看对象本身时优先使用对象对应的 skill；保存结果时再使用本 skill。

## 补充信息

- rowid 为每条 enrichment 记录的UUID,用于数据关联. enrichment_id 是每条 enrichment 记录人类可读的唯一ID

## 决策流程

1. 如果用户想保存新的结构化结果，先调用 `create_enrichment`。
2. 如果用户想把结果附加到 case、alert 或 artifact，调用 `attach_enrichment_to_target`。
3. 如果用户已经有现成的 enrichment row ID，跳过创建，直接附加。
4. 如果用户还处于对象探索阶段而不是保存结果，先使用对应对象 skill。

## SOP

### 创建并附加新的 Enrichment

1. 要求提供`target_id` (比如 case_000001 / alert_000001 / artifact_000001)。
2. 把用户的分析整理成紧凑的结构化 enrichment payload。
3. 调用 `create_enrichment` 并保留返回的 enrichment row ID。
4. 调用`attach_enrichment_to_target(target_id=<target_id>, enrichment_rowid=<created_rowid>)`。
5. 确认 enrichment 已创建并附加成功。

首选回复结构：

- `Target`：目标类型和目标 ID
- `Enrichment`：创建出的 enrichment row ID
- `Attachment`：已附加到目标
- `Next useful step`：可选，通常是继续调查、查看 enrich 后的对象，或继续自动化处理

### 附加已有 Enrichment

1. 要求提供 `target_id` 和 `enrichment_rowid`。
2. 调用`attach_enrichment_to_target(target_id=<target_id>, enrichment_rowid=<enrichment_rowid>)`。
3. 确认 enrichment 已附加成功。

## 澄清规则

- 只有在缺失时才询问 `target_type` 和 `target_id`。
- 只有当用户要复用现有 enrichment 且未提供时，才询问 enrichment row ID。
- 如果用户只说“把这个结果保存一下”，在上下文明确时推断最明显的目标对象。
- 如果用户要保存的是备注而非严格结构化结果，只要内容本质上是调查上下文，仍优先使用 enrichment。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出原始 JSON。
- 优先使用面向分析师的措辞，而不是存储层措辞。
- 明确说明保存了什么、附加到了哪里，以及它为什么有用。

## 失败处理

- 如果目标对象不存在，直接说明。
- 如果 enrichment payload 不完整，只问一个聚焦问题，不要猜测。
- 如果附加失败是因为缺少 enrichment row ID，就要求用户提供，或先创建新的 enrichment。
