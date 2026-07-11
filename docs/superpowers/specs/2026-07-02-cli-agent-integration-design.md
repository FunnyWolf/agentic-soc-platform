# ASP CLI Agent 集成架构设计

## 状态

已确认。

## 背景

ASP 当前通过后端 MCP endpoint 向 Claude Code plugin 的 agents 和 skills 暴露能力。MCP 的优点是工具签名、参数和调用协议由框架处理，接入成本低；主要问题是工具列表和描述会固定进入上下文，缺少命令行天然具备的渐进式 help。ASP 的目标用户是安全工程师和 SOC 分析师，对 CLI 接受度较高，因此新架构将 CLI 作为 Agent 和人类共同使用的主集成面。

现有 `/api/mcp` 先保留兼容窗口。新能力以 CLI 和 Agent Operations API 为主路径，等 CLI 能力、文档和 marketplace skills 稳定后，再将 MCP 标记为 deprecated。

## 目标

- 提供符合主流 Agent/平台 CLI 习惯的 `asp` 命令。
- 通过分层命令和 help 支持渐进式能力发现。
- 首发使用 Python 实现，支持 `pipx install` 和一行 bootstrap 安装。
- 覆盖当前 MCP 暴露的能力，并为后续新增 operation 留出发版期扩展机制。
- 所有命令支持人类可读输出和稳定 JSON 输出。
- 复用成熟 CLI/HTTP/渲染库，避免手写底层框架。
- 保持 CLI 和后端运行时解耦，CLI 可独立安装。

## 非目标

- 不做运行时动态命令发现。服务端新增业务命令后，通过 CLI 发版暴露。
- 不把 CLI 做成后端 Django 管理命令，也不要求 CLI 在后端源码环境运行。
- 不把所有能力压到单一 `operation run` 或 `/run` RPC。
- 不按 MCP 函数名设计主命令；MCP 名只作为迁移映射和 alias 记录。
- 不让文件内容默认进入 CLI 输出或 Agent 上下文。

## 选定方案

采用“静态主流 CLI + build-time operation spec + Agent Operations API”。

- CLI 使用 Python Typer + Rich + httpx + Pydantic。
- CLI 业务命令是静态分层命令，随 CLI 发版。
- 后端新增版本化 Agent Operations API，提供适合 CLI/Agent 的稳定 schema。
- 后端维护发版期 operation spec，CLI 包内携带对应 spec snapshot。
- marketplace 新增 CLI 版 skills，与 MCP 版并行，稳定后切默认入口。

这个方案接近 `gh`、`docker`、`terraform` 等主流 CLI 的静态命令树模式，同时保留类似 AWS CLI 的 model/spec-driven 契约管理思想。相比服务端动态命令发现，它牺牲“服务端新增命令无需 CLI 发版”的便利，换取更稳定的 help、completion、测试和安装体验。

## 架构组件

### ASP CLI package

CLI 作为当前 monorepo 中的独立 package 维护，发布为 PyPI 包。

首发安装方式：

```bash
pipx install asp-cli
```

同时提供 PowerShell 和 bash bootstrap 一行命令，用于检测 Python/pipx 并安装 CLI。CLI 包不 import Django app、models 或 serializers；后端依赖不会进入 CLI 安装环境。

CLI 静态内置：

- `auth`
- `config`
- `doctor`
- `completion`
- 各业务命令组

CLI 使用包内 operation spec snapshot 提供命令说明、examples、兼容测试和文档生成输入。

### Backend Agent Operations API

后端新增 `/api/agent/v1/...` API 层，定位是给 Agent/CLI 使用的稳定接口。

API 原则：

- 版本化。
- 领域化。
- 可写 OpenAPI / operation spec。
- 复用现有 service、ORM、permission 和 audit 机制。
- 使用 Agent 专用 serializer/schema，不直接暴露 UI REST 字段。
- 不提供单一 `/run` RPC。

示例 endpoint 形态：

```text
GET   /api/agent/v1/version
GET   /api/agent/v1/cases/
GET   /api/agent/v1/cases/{case_id}/
PATCH /api/agent/v1/cases/{case_id}/ai-analysis/
POST  /api/agent/v1/comments/
GET   /api/agent/v1/files/{file_key}/
POST  /api/agent/v1/files/
POST  /api/agent/v1/siem/search/keyword/
POST  /api/agent/v1/threat-intel/query/
POST  /api/agent/v1/cmdb/lookup/
```

具体 URL 可在实现时细化，但不得退化为 UI REST 的不稳定透传。

### Operation spec

operation spec 是 CLI、Agent API、文档和 skills 的发版期契约源。

每个 operation 至少包含：

- operation id，例如 `case.list`。
- CLI path，例如 `case list`。
- HTTP method 和 endpoint。
- 参数 schema。
- 输出 schema。
- 权限要求。
- capability 要求。
- examples。
- deprecated aliases，例如旧 MCP 工具名 `list_cases`。
- 最低 CLI/API 版本要求。

CLI 不运行时动态拉取业务命令。服务端通过 `/api/agent/v1/version` 返回 `api_version`、`min_cli_version` 和 capabilities，CLI 用于兼容检查。CLI 新、服务端旧时，对不支持的 operation 明确报错；服务端要求更高 CLI 时，CLI 直接提示升级。

## 命令树

主命令树：

```text
asp auth login|status|logout
asp config get|set|list
asp doctor
asp completion powershell|bash|zsh

asp case list|show|update-ai
asp alert list|show
asp artifact list|show
asp enrichment create
asp knowledge search|show|update
asp playbook template list
asp playbook list|show|run

asp comment list|add
asp file upload|info|download|read-text

asp siem schema list|show
asp siem search keyword
asp siem query adaptive|spl|esql
asp siem fields discover

asp ti query
asp cmdb lookup

asp dev stream head|read
```

命名规则：

- 安全行业常用短名作为主命令，例如 `siem`、`ti`、`cmdb`。
- 长名通过 alias 或 help 提供，例如 `threat-intel` alias 到 `ti`。
- MCP 函数名不作为主 CLI UX。

### 当前 MCP 能力映射

| MCP 工具 | CLI 命令 |
| --- | --- |
| `list_cases` | `asp case list`, `asp case show` |
| `update_case` | `asp case update-ai` |
| `get_file` | `asp file info`, `asp file download`, `asp file read-text` |
| `add_comment` | `asp comment add` |
| `list_alerts` | `asp alert list`, `asp alert show` |
| `list_artifacts` | `asp artifact list`, `asp artifact show` |
| `create_enrichment` | `asp enrichment create` |
| `list_playbook_templates` | `asp playbook template list` |
| `execute_playbook` | `asp playbook run` |
| `list_playbooks` | `asp playbook list`, `asp playbook show` |
| `update_knowledge` | `asp knowledge update` |
| `search_knowledge` | `asp knowledge search` |
| `read_stream_message_by_id` | `asp dev stream read` |
| `read_stream_head` | `asp dev stream head` |
| `ti_query` | `asp ti query` |
| `cmdb_lookup` | `asp cmdb lookup` |
| `siem_explore_schema` | `asp siem schema list`, `asp siem schema show` |
| `siem_keyword_search` | `asp siem search keyword` |
| `siem_adaptive_query` | `asp siem query adaptive` |
| `siem_discover_index_fields` | `asp siem fields discover` |
| `siem_execute_spl` | `asp siem query spl` |
| `siem_execute_esql` | `asp siem query esql` |

CLI 可以比 MCP 更完整。首版设计包含 `comment list`、`file upload`、`file download`、`file read-text`，因为这些能力适合 CLI，但不适合 MCP tool 参数直接传输文件内容。

## Help 和命令发现

采用分层渐进式 help：

- `asp --help`：只显示全局选项和命令组。
- `asp case --help`：显示 case 子命令和常见流程。
- `asp case list --help`：显示完整参数、枚举、输出说明和 examples。

所有业务命令支持 `--output human|json`。Agent/skill 文档必须使用 `--output json`，避免解析 human 表格。

CLI 提供 shell completion：

```bash
asp completion powershell
asp completion bash
asp completion zsh
```

`asp auth login` 成功后给出下一步建议，例如运行 `asp doctor` 和一个只读 list 命令。

## 配置和认证

`asp auth login` 是主认证入口：

```bash
asp auth login --api-url https://asp.example.com --api-key asp_xxx
```

该命令默认将 base URL 和 API key 写入 settings。后续命令自动使用该配置，不需要再次认证。

配置范围：

- 全局个人配置。
- 当前仓库 local `.asp/settings.json`。

local 配置查找规则：

- 从当前目录向上查找最近的 `.asp/settings.json`。
- 不越过 git repository root。

配置优先级：

```text
explicit CLI flags > environment variables > local .asp/settings.json > global settings
```

环境变量仅作为 CI、容器或高级临时覆盖通道，日常文档主推 settings。

API key 明文保存在 settings 中。实现写入配置时尽量收紧文件权限；文档说明明文配置的行为和适用场景，`auth login` 成功路径不输出风险警告。

`asp auth status` 输出当前配置来源、base URL、认证用户和 key 状态，不显示完整 API key。`asp auth logout` 删除当前 scope 的认证配置。

## 输入契约

输入规则：

- 简单参数用 flags。
- 列表用重复 flag，兼容逗号分隔。
- 复杂对象支持 `--data-json`、`--data-file`、`--stdin`。
- 长文本支持 `--body`、`--body-file`，后续可支持 `--editor`。

示例：

```bash
asp case list --status New --severity High --limit 20
asp enrichment create case_000001 --name ti --data-file enrichment.json
asp comment add case_000001 --body-file note.md --file-key 6f2c...
```

## 输出契约

默认输出为 human，面向人类阅读：

- list/search 使用紧凑表格。
- show/detail 使用分区详情。
- 写操作输出变更摘要。
- SIEM/TI/CMDB 输出关键命中和分析摘要。

完整数据通过 JSON 输出：

```bash
asp case list --output json
```

成功 JSON 统一 envelope：

```json
{
  "data": {},
  "meta": {
    "operation": "case.list",
    "request_id": "req_...",
    "pagination": null
  }
}
```

失败 JSON 统一 envelope：

```json
{
  "error": {
    "code": "not_found",
    "message": "Case not found: case_000001",
    "details": {}
  },
  "meta": {
    "operation": "case.show",
    "request_id": "req_..."
  }
}
```

CLI 支持可选 `--query`，使用 JMESPath 对 JSON `data` 做客户端筛选：

```bash
asp case list --output json --query "data[].case_id"
```

## 分页和大结果

list/search 默认有界，避免一次拉取过多数据。

分页采用无状态 cursor。服务端不保存客户端翻页 session，cursor 是客户端携带的不透明 token。

JSON `meta.pagination` 示例：

```json
{
  "pagination": {
    "next_cursor": "opaque-token",
    "has_more": true
  }
}
```

CLI 支持：

- `--cursor`：继续下一页。
- `--limit`：控制返回数量。
- `--page-size`：控制单次请求大小。
- `--all`：显式自动翻页。
- `--max-items`：限制自动翻页最大数量。

SIEM 查询必须要求时间范围和 limit。若底层 SIEM 后端支持稳定 cursor/search_after，再提供 cursor；否则返回有界结果并在 meta 中说明限制。

## 错误、exit code 和日志

错误类型使用稳定 error code 和 exit code，至少区分：

- 参数错误。
- 认证失败。
- 权限不足。
- 资源不存在。
- 冲突。
- 版本不兼容。
- 网络错误。
- 服务端错误。

human 模式输出简短可行动错误。`--verbose` 才显示请求方法、URL path、HTTP status、request id 和耗时。

日志规则：

- 默认不写详细日志。
- `--verbose` 输出脱敏诊断信息。
- `--log-file` 显式写本地日志。
- `--debug-http` 仍强制脱敏。
- Authorization、API key 和敏感参数不得出现在日志中。

## 权限和写操作安全

认证继续使用 ASP User API Key。

权限规则：

- 读操作要求 authenticated。
- 写操作复用现有 business writer 规则。
- operation spec 标注 required permission 和 required capability。
- 后端写操作继续使用现有 audit 机制。

明确写命令不做二次确认，保证 Agent/skill 可无交互执行：

- `asp comment add`
- `asp case update-ai`
- `asp enrichment create`
- `asp playbook run`

未来 destructive 或 bulk 命令必须要求 `--yes`，并优先支持 `--dry-run`。JSON/CI 模式下不弹交互 prompt；缺少 `--yes` 时返回标准错误。

## 文件能力

CLI 文件命令：

- `asp file upload <path>`
- `asp file info <file_key>`
- `asp file download <file_key> --output-path <path>`
- `asp file read-text <file_key> --max-bytes <n>`

默认不输出文件 bytes、base64 或大文本。`read-text` 必须显式调用，并受大小和内容类型限制。

comment 附件继续使用 `file_key` 引用。CLI 上传本地文件后返回 `file_key`，可直接传给 `asp comment add --file-key ...`。

## `asp doctor`

`asp doctor` 是只读诊断命令，支持 human 和 JSON 输出。

检查内容：

- 当前配置来源。
- base URL 连通性。
- TLS/代理基础错误。
- API key 是否有效。
- 当前用户和角色。
- 服务端 API version。
- CLI version。
- 版本兼容。
- 服务端 capabilities，例如 SIEM、TI、CMDB。

`doctor` 不修改配置，不执行写操作。

## Marketplace skills 迁移

迁移策略：

1. 新增 CLI 版 skills，metadata 标记依赖 ASP CLI。
2. MCP 版 skills 保留兼容窗口。
3. CLI 版 skills 一律使用 `--output json`。
4. CLI 版稳定后，marketplace 默认入口切到 CLI。
5. MCP 版标记 deprecated，后续再移除。

同一个 skill 不同时兼容 MCP 和 CLI，避免分支逻辑复杂化。CLI 版 skill 应直接写最优 CLI 命令，不围绕 MCP 历史函数名设计。

## 文档

文档由两部分组成：

- 从 operation spec 生成命令/API 参考，包括参数、schema、examples 和输出结构。
- 手写指南和 SOP，包括安装、认证、配置、SOC 调查流程、Claude Code skills 使用。

asf-doc 修改遵循项目规则：先更新 zh 文档，zh 定稿后再同步 en 文档。

## 测试策略

后端测试：

- Agent API endpoint tests。
- 权限 tests。
- schema/envelope tests。
- cursor 分页 tests。
- 错误码 tests。

spec 测试：

- operation spec 结构校验。
- CLI command 覆盖检查。
- deprecated alias 映射检查。
- server `min_cli_version` 兼容检查。

CLI 测试：

- Typer 命令解析测试。
- httpx mock 集成测试。
- `--output json` contract tests。
- 关键 human 输出 snapshot tests。
- 配置优先级 tests。
- 脱敏日志 tests。

Marketplace skill 检查：

- 命令示例静态检查。
- JSON 输出契约引用检查。

## 实施阶段

### Phase 1: Foundation

- CLI package skeleton。
- `auth login/status/logout`。
- global/local settings。
- `doctor`。
- `--output human|json`。
- JSON envelope。
- 标准错误和 exit code。
- operation spec 基础结构。
- Agent API `/version` 和基础认证。

### Phase 2: Core SOC

- `case`。
- `comment`。
- `file`。
- `enrichment`。
- `knowledge`。
- `playbook`。
- 对应 Agent API 和 serializers。

### Phase 3: Investigation integrations

- `siem`。
- `ti`。
- `cmdb`。
- 对应 Agent API，覆盖当前 MCP 的 SIEM/TI/CMDB 能力。

### Phase 4: Advanced and migration

- `dev stream`。
- shell completion polish。
- generated command reference。
- CLI 版 marketplace skills。
- MCP deprecation 文档。

## 设计结论

ASP CLI 将成为新的 Agent 主集成面。后端提供稳定的 Agent Operations API，CLI 提供主流静态命令树和渐进式 help，operation spec 负责发版期契约同步。该方案优先保证主流 CLI 体验、低运行时复杂度、可测试性和长期可维护性，同时保留 MCP 兼容窗口降低迁移风险。
