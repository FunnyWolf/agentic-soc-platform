# 定制开发文档信息架构调整设计

## 背景

当前 `集成 / Integrations` 中包含 Webhook 和 ELK Index Action，但这两个页面的实际职责不是“外部能力集成展示”，而是把 SIEM 告警送入 ASP 的 Redis Stream：

```text
SIEM Alert / Rule
  -> Webhook 或 ELK Index Action
  -> Redis Stream
  -> Module
  -> Case / Alert / Artifact
```

因此它们更接近 `定制开发 / Development` 主线中的“告警接入层”。如果继续放在 `Integrations`，会让读者误以为它们和 MCP、ClaudeCode 插件属于同一类集成能力，也会让 `定制开发` 栏目的链路不完整。

同时，当前 `定制开发` 栏目虽然已经有 Environment Setup、Custom Console、Module、Playbook、SIEM YAML、Mock Data、Custom Examples 等页面，但整体顺序仍偏文件类型和功能点罗列，没有清晰呈现“从日志源到 Case，再到自动化处理”的完整脉络。

## 目标

1. 将 Webhook 和 ELK Index Action 从 `Integrations` 移动到 `Development`。
2. 让 `Integrations` 只保留 MCP 和 ClaudeCode Plugin 这类外部 Agent / Harness 集成。
3. 将 `Development` 重组为一条更清晰的定制开发链路。
4. 明确 Webhook / ELK Index Action 的职责是把 SIEM 告警写入 Redis Stream，供 Module 消费。
5. 保持中英文文档结构一致。
6. 删除旧 Integrations 页面，不保留跳转页。

## 非目标

1. 不修改后端 API 或运行逻辑。
2. 不修改 Webhook / ELK Index Action 的功能行为。
3. 不新增图片或图片占位符。
4. 不运行 VitePress build，除非明确要求。

## 新导航结构

### Integrations / 集成

只保留：

```text
Overview
MCP
ClaudeCode Plugin
```

`Integrations` 总览页应只描述外部 Agent、协议、工具生态相关集成。Webhook 和 ELK Index Action 从这里移除。

### Development / 定制开发

按定制开发链路组织：

```text
Overview
Environment Setup
Mock Data
Alert Ingestion
  Overview
  Splunk Webhook
  Kibana Webhook
  ELK Index Action
SIEM YAML
Module Development
Playbook Development
Custom Console
Custom Examples
  Overview
  SIEM + Module Flow
  Custom Playbooks
```

推荐理解路径：

1. `Environment Setup`：准备开发环境。
2. `Mock Data`：生成工作台数据或 SIEM 测试日志。
3. `Alert Ingestion`：将 SIEM 告警写入 Redis Stream。
4. `SIEM YAML`：描述日志索引和字段，让 Agent / MCP 能理解日志。
5. `Module Development`：消费 Stream raw alert，生成 Case / Alert / Artifact。
6. `Playbook Development`：在 Case 上继续做调查、富化、摘要或知识提取。
7. `Custom Console`：观察和校验运行时加载状态。
8. `Custom Examples`：用端到端示例串起前面的能力。

## 页面迁移

删除旧页面：

```text
integrations/webhook/index.md
integrations/webhook/splunk/index.md
integrations/webhook/elk/index.md
integrations/elk-index-action/index.md
```

新增 / 移动到：

```text
development/alert-ingestion/index.md
development/alert-ingestion/splunk-webhook/index.md
development/alert-ingestion/kibana-webhook/index.md
development/alert-ingestion/elk-index-action/index.md
```

英文文档做同样迁移。

## 页面职责

### `development/alert-ingestion/`

职责：告警接入总览。

需要说明：

- Webhook：SIEM 直接 POST 到 ASP Webhook，适合 SIEM 能访问 ASP API 的环境。
- ELK Index Action：Kibana 先把 Action 写入 Elasticsearch 索引，ASP Worker 再轮询读取，适合无法直接 POST 或社区版能力受限的环境。
- 两种方式最终都会写入 Redis Stream。
- Stream 名称必须和后续 Module 的 `STREAM_NAME` 对齐。
- Alert Ingestion 是 Module 的上游，不负责直接生成 Case。

### `development/alert-ingestion/splunk-webhook/`

职责：Splunk Alert 直接 POST 到 ASP。

保留原有内容，并强化：

- `search_name` 会作为 Redis Stream 名称。
- `result` 是写入 Stream 的 raw alert。
- Splunk Alert 名称要和 Module `STREAM_NAME` 对齐。
- 链接到 Module Development 和 Custom Console。

### `development/alert-ingestion/kibana-webhook/`

职责：Kibana Rule 通过 Webhook connector 直接 POST 到 ASP。

保留原有内容，并强化：

- `rule.name` 会作为 Redis Stream 名称。
- `context.hits` 会逐条写入 Stream。
- Rule 名称要和 Module `STREAM_NAME` 对齐。
- 链接到 Module Development 和 Custom Console。

### `development/alert-ingestion/elk-index-action/`

职责：Kibana Rule 通过 Index connector 先写入 Elasticsearch，ASP 再轮询读取。

保留原有内容，并强化：

- Action Index 和轮询参数在 SIEM 设置中配置。
- `run_elk_action_worker` 持续读取 Action Index。
- 读取结果会转换为 Kibana webhook payload，再写入 Redis Stream。
- 链接到 SIEM 设置、Module Development、Custom Console。

## 现有页面更新

需要更新：

- `development/index.md`
  - 重写总览中的数据流和推荐阅读顺序。
  - 明确 Alert Ingestion 在 Mock Data 和 SIEM YAML / Module 之间。
- `development/mock-data/`
  - 链接到 Alert Ingestion，说明 Mock SIEM 日志可以作为告警规则输入。
- `development/siem-yaml/`
  - 链接到 Alert Ingestion 和 Custom Examples。
- `development/module-examples/`
  - 明确 Module 的上游是 Webhook / ELK Index Action 写入的 Redis Stream。
- `development/custom-examples/`
  - 将 Webhook / ELK Index Action 链接改到新路径。
- `settings/siem/`
  - 如果有指向旧 ELK Index Action 文档的链接，改到新路径。
- `integrations/index.md`
  - 移除 Webhook 和 ELK Index Action。
  - 只保留 MCP 和 ClaudeCode Plugin。

## 链接策略

按用户确认：

- 旧 Integrations 页面直接删除。
- 不保留 redirect / stub 页面。
- 所有文档内部链接必须更新到新路径。
- 若外部已有旧链接，后续可以通过站点层 redirects 再处理，但本次不做。

## 验证

手工验证应覆盖：

1. zh/en 侧边栏中 Integrations 不再包含 Webhook / ELK Index Action。
2. zh/en 侧边栏中 Development 包含 Alert Ingestion 分组。
3. 新路径下 zh/en 页面都存在。
4. 旧路径下 Webhook / ELK Index Action 页面已删除。
5. 文档中不再出现指向旧 `integrations/webhook` 或 `integrations/elk-index-action` 的相对链接。
6. Development 总览能读出清晰链路：Mock Data -> Alert Ingestion -> SIEM YAML -> Module -> Playbook -> Custom Console -> Custom Examples。
7. 除非明确要求，不运行 VitePress build。
