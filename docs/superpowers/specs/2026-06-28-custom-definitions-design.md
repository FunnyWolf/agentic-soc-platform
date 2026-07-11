# Custom Definitions Console 设计

## 背景

Custom Definitions 是 ASP 扩展框架的管理入口，用于让管理员理解当前运行环境中加载了哪些自定义能力，以及这些能力是否能被后端正确解析。现有入口位于 System Settings 的 Runtime Tab 内，只有一个聚合的 `Refresh / Validate` 区块，信息密度低，也把 Custom 功能和 Runtime 配置混在一起。

本次设计将 Custom Definitions 提升为独立的 admin-only 控制台，聚焦三个可管理对象：

- Modules
- Playbooks
- SIEM YAML

Prompt 文件不再作为 Custom Definitions 的管理对象。Playbook 可以选择把 prompt 写在代码中，也可以自行使用 `BasePlaybook.read_prompt()` 读取文件；框架不应要求或校验 playbook prompt 文件。

## 决策

采用 **Custom Console** 方案：

- 前端新增独立 `/custom` 页面和侧边栏 `Custom` 入口。
- 页面仅 admin 可见，分为 `Modules`、`Playbooks`、`SIEM YAML` 三个 tabs。
- 每个 tab 独立加载、刷新和校验自己的 definition。
- Modules 增加只读 Redis Stream inspection，用于辅助调试输入数据。
- Playbooks 和 SIEM YAML 以展示、校验为主，不提供创建和编辑。
- 删除 Custom Definitions 链路中的 prompt 扫描、计数和缺失校验。

## 目标

- 让管理员可以从独立入口查看所有已加载 definition。Playbook 需要区分 `official` / `custom` 来源；Modules 和 SIEM YAML 没有 official 来源概念，不展示 source。
- 将验证功能按 tab 拆分，避免一个聚合结果难以定位问题。
- 让 Module 页面展示对应 Redis Stream 的基础运行信息，并支持只读查看最近消息或指定消息。
- 让 Playbook 页面展示可运行定义，但不在 Custom 页面直接执行 playbook。
- 让 SIEM YAML 页面展示 index schema 和 fields，方便确认 YAML 是否符合预期。
- 从 Runtime 设置页移除 Custom Definitions 区块，使 Runtime 只负责运行配置。

## 非目标

- 不做文件创建、编辑、删除或在线 YAML 编辑器。
- 不提供 Module 投递测试消息、立即消费消息、run once 或删除 stream/message。
- 不在 Custom 页面运行 Playbook；Playbook 测试继续通过 Case 的 Run Playbook 入口完成。
- 不新增 URL 过滤、URL 打开指定记录或跨页面 deep link 能力；Playbook 运行记录跳转留到后续单独设计。
- 不新增数据库模型或迁移。
- 不新增 Prompts tab，不校验 prompt 文件是否存在。

## 权限与导航

`/custom` 使用与 System Settings 相同的 admin 权限边界：

- admin 用户在侧边栏看到 `Custom`，位置在 `Knowledge` 和 `Setting` 之间。
- 非 admin 用户不显示入口；直接访问 `/custom` 时重定向到 `/cases`。
- 页面 breadcrumb 显示 `Custom`。

`RuntimeSettings` 删除现有 Custom Definitions 区块，只保留 Prompt Language 和 Stream Maxlen 等 Runtime 配置。

## 后端 API

新增 admin-only API，路径不挂在 Runtime 下：

| Method | Path | 用途 |
| --- | --- | --- |
| `GET` | `/custom/modules/` | 自动加载 Module definitions 和 stream health，不写审计 |
| `POST` | `/custom/modules/` | 手动 Refresh / Validate Modules，写审计 |
| `GET` | `/custom/playbooks/` | 自动加载 Playbook definitions，不写审计 |
| `POST` | `/custom/playbooks/` | 手动 Refresh / Validate Playbooks，写审计 |
| `GET` | `/custom/siem/` | 自动加载 SIEM YAML definitions，不写审计 |
| `POST` | `/custom/siem/` | 手动 Refresh / Validate SIEM YAML，并 reload registry cache，写审计 |
| `GET` | `/custom/modules/stream/messages/` | 读取指定 stream 最近消息，默认 5 条，最大 20 条 |
| `GET` | `/custom/modules/stream/message/` | 按 stream name 和 message id 读取单条消息 |

`POST` 审计沿用现有 RuntimeConfig 单例作为审计目标，metadata 至少包含：

- `section`
- `success`
- `counts`

GET 自动加载不写审计，避免用户打开页面导致审计噪声。

## 数据契约

### Modules

Module section 返回：

- `items`
- `errors`
- `counts`
- `success`

每个 item 包含：

- `name`
- `description`
- `path`
- `stream_name`
- `thread_num`
- `stream_health`

`stream_health` 包含：

- `available`
- `length`
- `first_id`
- `last_id`
- `groups`
- `warning`

Redis 不可用或 stream 不存在时，definition scan 仍成功；仅在 `stream_health.warning` 中体现原因。

### Playbooks

Playbook section 返回：

- `items`
- `errors`
- `counts`
- `success`

每个 item 包含：

- `name`
- `description`
- `tags`
- `source`
- `path`

Custom Definitions 不再返回 `prompts` section、prompt counts 或 prompt errors。`REQUIRED_PROMPTS` 扫描从 refresh/validate 链路删除。

### SIEM YAML

SIEM section 返回：

- `items`
- `errors`
- `counts`
- `success`

每个 item 包含：

- `name`
- `backend`
- `description`
- `path`
- `field_count`
- `key_field_count`
- `fields`

每个 field 包含：

- `name`
- `type`
- `description`
- `is_key_field`
- `sample_values`

## 前端设计

新增 `CustomDefinitions` 页面。页面使用 Ant Design `Tabs`，包含三个 tab，不设置 Overview。

### Modules tab

Toolbar：

- `Refresh / Validate`
- `Reload`
- search

主表字段：

- Module name
- description
- stream_name
- thread_num
- stream length
- last message id
- path

点击行打开详情抽屉，展示：

- definition 基础信息
- stream health
- 最近消息 JSON viewer，默认 5 条，最多 20 条
- 按 message id 读取单条消息

所有 stream 操作只读，不提供写入、消费或删除。

### Playbooks tab

Toolbar：

- `Refresh / Validate`
- `Reload`
- source filter
- tag filter
- search

主表字段：

- Playbook name
- source
- tags
- description
- path

点击行打开详情抽屉，展示完整描述、tags 和路径。

动作：

- Playbook 运行记录跳转留到后续单独设计，本次不实现 URL 过滤或 deep link。

### SIEM YAML tab

Toolbar：

- `Refresh / Validate`
- `Reload`
- backend filter
- search

主表字段：

- index name
- backend
- description
- field count
- key field count
- path

点击行打开详情抽屉，展示 fields 表：

- name
- type
- key field
- description
- sample values

不提供 YAML 编辑、新建或 live query preview。

## 错误处理

- Definition scan 按文件收集错误，一个坏文件不阻断同类其他文件展示。
- 每个 tab 只展示本 section 的 errors。
- Redis stream health 失败降级为 warning，不影响 Module definition 列表。
- Stream message 读取失败时，前端显示 toast，并在抽屉内显示错误状态。
- SIEM YAML parse/validation 错误显示文件路径和异常信息。
- 删除 prompt 扫描后，prompt 文件缺失不再算 Custom Definitions validation error。

## 代码边界

后端复用现有 loader：

- `apps.agentic.runtime.module.scan_module_definitions`
- `apps.agentic.services.playbooks.scan_playbook_definitions`
- `integrations.siem.registry.scan_registry_configs`

需要拆出 section 级 service，避免一个聚合函数继续承载所有逻辑。旧的 Runtime nested refresh view 可以删除或替换为新 API。

保留 `BasePlaybook.prompt_path()` 和 `BasePlaybook.read_prompt()` 作为可选 helper；删除 Custom Definitions 中对 `REQUIRED_PROMPTS` 的扫描和错误计数。

前端新增页面组件时优先复用 Ant Design Table、Drawer、Tag、Alert、Input.Search 和现有 JSON viewer。不要为第一版引入自定义复杂布局。

## 文档

更新文档时先更新中文，再同步英文：

- Runtime 文档移除 Custom Definitions 区块。
- 新增或调整 Custom Definitions 文档，说明新入口、三个 tabs、Refresh / Validate 行为和 Module stream inspection。
- 说明 Prompt 文件不是 Custom Definitions 管理对象；文件 prompt 是 Playbook 可选实现方式。

## 验证标准

后端：

- 非 admin 访问 `/custom/*` 被拒绝。
- `GET /custom/modules/` 返回 definitions 和 stream health，不写 audit log。
- `POST /custom/modules/` 返回同样结构并写 section 审计。
- Module stream messages 默认 5 条，最大限制为 20 条。
- Redis 不可用时 Module definitions 仍返回，stream health 显示 warning。
- `GET/POST /custom/playbooks/` 不返回 prompts section，也不因 prompt 文件缺失报错。
- `GET/POST /custom/siem/` 返回 fields、field_count 和 key_field_count。
- `POST /custom/siem/` 会 reload SIEM registry cache。

前端：

- admin 侧边栏显示 `Custom`，非 admin 不显示。
- `/custom` 页面只有 Modules、Playbooks、SIEM YAML 三个 tabs。
- Runtime 页不再显示 Custom Definitions。
- 每个 tab 可单独 Refresh / Validate 并展示本 section errors。
- Modules 详情抽屉可读取最近 stream 消息和指定 message id。
- Playbooks tab 只展示，不直接执行 playbook。
- SIEM YAML 详情抽屉展示 fields 表。

文档：

- 中文和英文文档都不再描述 Prompt 作为 Custom Definitions 的校验对象。
