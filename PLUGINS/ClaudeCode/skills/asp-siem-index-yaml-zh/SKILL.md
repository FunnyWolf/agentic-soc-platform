---
name: asp-siem-index-yaml-zh
description: '新建或更新 SIEM 索引配置 YAML。当用户想为某个 SIEM index 生成字段配置、更新现有索引 YAML、或把后端实时字段同步到配置文件时使用。'
argument-hint: '<index_name> <backend>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ SIEM, index, yaml, schema, configuration ]
  documentation: https://asp.viperrtp.com/
---

# ASP SIEM Index YAML

当用户要新建或更新 SIEM 索引配置 YAML 时，使用这个 skill 引导完成从字段发现到配置落盘的完整流程。

## 适用场景

- 用户想为某个 SIEM index 生成索引配置 YAML。
- 用户想根据后端实时字段更新现有索引 YAML。
- 用户想查看某个 index 在 ELK 或 Splunk 中实际有哪些字段。

## 运行规则

- 配置文件固定存放在 `DATA/Plugin_SIEM_Indexes/<index_name>.yaml`。
- 必须通过 `siem_discover_index_fields` 从后端拉取实时字段，不得跳过直接手写。
- `name`、`type`、`sample_values` 直接采用发现结果，`sample_values` 保持原始类型，不强转字符串。
- `description` 和 `is_key_field` 由模型根据字段语义和 sample_values 推断，标注为待确认。
- 不要在用户确认前覆盖现有 YAML。

## 决策流程

1. 如果用户未提供 `index_name` 或 `backend`，先询问。
2. 如果 `DATA/Plugin_SIEM_Indexes/<index_name>.yaml` 已存在，读取并作为对比基线。
3. 调用 `siem_discover_index_fields` 获取实时字段。
4. 生成草案，展示给用户 review。
5. 用户确认后写入文件。

## SOP

### Step 1 — 获取输入

要求用户提供：
- `index_name`：SIEM 索引名称。
- `backend`：`ELK` 或 `Splunk`。

### Step 2 — 检查现有配置

检查 `DATA/Plugin_SIEM_Indexes/<index_name>.yaml` 是否已存在。
- 如果存在，读取作为基线，后续展示差异。
- 如果不存在，标记为新建。

### Step 3 — 发现字段

调用 `siem_discover_index_fields(index_name=<index_name>, backend=<backend>)`。

返回数据包含每个字段的：
- `name`：字段名（嵌套字段用点号路径）
- `type`：后端报告的字段类型
- `sample_values`：Top-5 高频值（保持原始类型）

### Step 4 — 生成草案

对每个字段填充完整配置：

| 字段 | 来源 |
|------|------|
| `name` | 直接采用 |
| `type` | 直接采用 |
| `sample_values` | 直接采用 |
| `description` | 从字段名语义生成，结合 sample_values 补充示例范围 |
| `is_key_field` | 按调查价值启发式推断：身份、资产、网络四元组、动作、结果、高信号标识字段 → `true`；纯噪音或低价值字段 → `false` |

### Step 5 — 展示草案

向用户展示差异摘要和完整草案。

首选回复结构：

**草案摘要**

- 目标索引：`<index_name>`
- 后端：`<backend>`
- 字段总数：`<n>`
- 新增字段：`<list>`（对比基线，如有）
- 类型变化：`<list>`（对比基线，如有）
- `is_key_field=true` 的字段列表

**待确认项**

- `is_key_field` 推断是否合理
- `description` 是否符合命名规范
- 是否需要调整任何字段

### Step 6 — 写入文件

用户确认后，将完整 YAML 写入 `DATA/Plugin_SIEM_Indexes/<index_name>.yaml`。

YAML 顶层结构：

```yaml
name: <index_name>
backend: <backend>
description: <index description>

fields:
  - name: <field_name>
    type: <field_type>
    description: <field_description>
    is_key_field: <true|false>
    sample_values: [<value1>, <value2>, ...]
```

## 澄清规则

- 只有在缺失时才询问 `index_name` 或 `backend`。
- 如果 `siem_discover_index_fields` 返回空字段列表，说明可能 index 名称有误或后端无数据，要求用户确认。
- 如果用户对草案中某些字段的 `is_key_field` 或 `description` 有异议，按用户要求调整后重新展示。

## 输出规则

- 草案展示时优先用差异摘要 + 关键字段列表，不要直接倾倒完整 YAML。
- 只有在用户确认写入时才生成完整 YAML 文件内容。
- 保持简洁，不要重复解释每个字段的含义。

## 失败处理

- 如果 `siem_discover_index_fields` 调用失败，说明错误并要求用户检查 index 名称和后端连通性。
- 如果返回字段数为 0，提示用户确认 index 是否存在且有数据。
- 如果用户要求写入但未经过 review 确认，提醒先完成确认步骤。

