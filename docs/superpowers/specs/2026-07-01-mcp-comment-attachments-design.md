# MCP 评论附件访问设计

## 背景

当前系统已经有评论和附件能力：

- `Comment` 通过 `content_type + object_id` 关联任意业务记录。
- `Comment.attachments` 通过多对多关系关联 `Attachment`。
- `Attachment` 使用 `access_key` 作为不可猜测的公开下载 key，并通过现有下载端点提供文件下载。
- REST 评论接口支持正文或附件至少一个；创建评论时通过 `attachment_ids` 关联已上传附件。
- REST 附件上传接口使用 multipart/form-data；全局 DRF 认证已经支持 `Authorization: Api-Key <key>`，因此 API key 用户可以通过 HTTP multipart 上传附件。

当前 MCP 侧存在缺口：

- `add_comment` 只能写入正文，不能关联附件、回复父评论或提及用户。
- MCP 的 `serialize_comment` 只返回 `id/body/author/created_at`，不会返回附件元数据。
- MCP 没有单独的 `list_comments` 工具；当前只有 `list_cases(include_related=True)` 会隐式返回 case comments，且其他可评论资源无法通过 MCP 读回评论。
- 文件内容不应默认进入 MCP tool 响应或模型上下文，否则会造成大文件 token 成本、二进制损坏和敏感内容扩散风险。

## 目标

- MCP 用户可以在现有记录查询工具中显式获取评论元数据。
- MCP 评论元数据包含附件列表，附件列表提供统一的 `file_key`、文件名、大小、内容类型和下载 URL。
- MCP 用户可以通过统一的 `get_file(file_key)` 获取文件下载信息。
- MCP 用户可以通过 `add_comment` 添加带附件、回复父评论、提及用户的评论。
- MCP 不通过 tool 参数上传文件内容，避免大文件进入模型上下文。
- 自定义 playbook 不新增封装；用户可继续用 Django ORM 和现有模型/服务直接处理评论附件。

## 非目标

- 不新增通用 MCP `list_comments` 工具。
- 不让 MCP `get_file` 默认返回文件内容、base64 或文本。
- 不新增 MCP base64 文件上传工具。
- 不改变附件下载端点的公开访问模型。
- 不改变 `/api/attachments/` 的上传权限。
- 不为自定义 playbook 增加 `BasePlaybook` helper、SDK 或文档。
- 不新增 enrichment 的 MCP 查询工具；enrichment comments 本次不通过 MCP 读取。
- 不新增数据库模型或字段。

## 选定方案

采用“现有记录查询工具显式包含评论 + HTTP multipart 上传 + `access_key` 作为统一 `file_key`”。

理由：

- `Attachment` 已经是统一文件存储表，未来 case、alert 等业务文件字段也应引用 `Attachment`，不需要再设计额外 namespace key。
- `access_key` 已经是当前公开下载机制的稳定外部 key，可直接作为 MCP `file_key`。
- HTTP multipart 上传让文件字节绕开 LLM 和 MCP tool 参数；tool 调用只传小体积元数据和 `file_key`。
- 评论读取挂到现有 `list_*`/search 工具，符合“不新增单独 list_comments”的方向。
- 文件内容默认不返回，符合大文件和任意文件类型场景。

## 备选方案和取舍

### 新增 `list_comments(target_id)`

优点是评论读取入口统一，能覆盖所有 `add_comment` 支持的 target，包括 enrichment。缺点是增加新的 MCP 工具，与“通过对应 list 获取评论”的现有使用方式不一致。本次不采用。

### MCP tool 直接上传 base64 文件

优点是所有动作都发生在 MCP 内。缺点是文件内容会进入 tool 参数和上下文，大文件成本高，二进制文件也容易被错误处理。本次不采用。

### `get_file` 返回 inline base64/text

优点是模型可直接读取小文件。缺点是默认行为容易把大文件或敏感文件带入上下文，也不适合任意文件类型。本次不采用。后续如果有明确需求，可单独设计受大小限制的 `read_text_file(file_key, max_bytes=...)`。

### 为 playbook 增加 helper

优点是降低自定义 playbook 作者理解 ContentType 和 Attachment ORM 的门槛。缺点是当前 playbook 本来就是后端 Python 代码，已能直接使用 Django ORM、`Attachment.file.open()` 和 `create_record_comment()`，新增封装不是必要条件。本次不采用。

## 数据标识

`file_key` 是 MCP 对外暴露的统一文件引用字段。

本次规定：

```text
file_key = str(Attachment.access_key)
```

MCP 响应不暴露 `Attachment.id`。调用方不应依赖数据库 id。

未来如果 case、alert、artifact 等资源增加文件字段，这些字段也应引用 `Attachment`，并继续返回同样的 `file_key`。

## MCP 评论读取设计

### 支持工具

以下现有 MCP 工具新增 `include_comments` 和 `comments_limit` 参数：

- `list_cases`
- `list_alerts`
- `list_artifacts`
- `list_playbooks`
- `search_knowledge`

`create_enrichment` 不变。由于 MCP 当前没有 `list_enrichments` 或 `get_enrichment`，enrichment comments 本次不提供 MCP 读取入口。

### 参数行为

```text
include_comments: bool = false
comments_limit: int = 20
```

规则：

- comments 只由 `include_comments` 控制。
- `include_related` 不再隐式返回 comments，包括 case。
- `include_comments=false` 时响应不包含 `comments` 字段。
- `comments_limit` 默认 20，最大 50，最小 1。
- 每个记录取最新 N 条评论，再按创建时间正序返回。

这会改变现有 `list_cases(include_related=True)` 的隐式 comments 行为。新行为更明确，也避免默认返回过多评论和附件元数据。

### Comment 响应字段

MCP comment 使用精简字段：

```json
{
  "id": 123,
  "body": "Please review the attached evidence.",
  "author": "alice",
  "created_at": "2026-07-01T12:00:00+00:00",
  "updated_at": "2026-07-01T12:00:00+00:00",
  "parent_id": null,
  "attachments": [
    {
      "file_key": "6f2c5d7e-31c6-4f48-9e3c-6d9b5f92c457",
      "filename": "evidence.zip",
      "size": 1048576,
      "content_type": "application/zip",
      "download_url": "https://asp.example.com/api/attachments/6f2c5d7e-31c6-4f48-9e3c-6d9b5f92c457/download/"
    }
  ]
}
```

不包含 REST UI 字段，例如 `can_delete`、avatar、`mentioned_users`、`parent_body`。

### Attachment 响应字段

附件元数据只返回外部字段：

- `file_key`：`Attachment.access_key` 字符串。
- `filename`：原始文件名。
- `size`：文件大小，单位 bytes。
- `content_type`：根据文件名推断的 MIME type；无法推断时使用 `application/octet-stream`。
- `download_url`：现有公开下载 URL。

`download_url` 优先返回绝对 URL。实现应从当前 MCP HTTP 请求的 scheme 和 host 推断 base URL；如果无法推断，则回退到相对路径 `/api/attachments/<access_key>/download/`。

## MCP 文件工具设计

新增 MCP 工具：

```text
get_file(file_key)
```

用途是获取文件下载信息，而不是读取文件内容。

MCP 服务运行在后端，不能可靠地直接把文件写入用户客户端本地磁盘。`get_file(file_key)` 的“一次调用”目标是返回可直接用于浏览器、curl 或客户端脚本下载的 URL；真正的文件字节通过普通 HTTP 下载，不进入 MCP tool 返回值。

返回：

```json
{
  "file_key": "6f2c5d7e-31c6-4f48-9e3c-6d9b5f92c457",
  "filename": "evidence.zip",
  "size": 1048576,
  "content_type": "application/zip",
  "download_url": "https://asp.example.com/api/attachments/6f2c5d7e-31c6-4f48-9e3c-6d9b5f92c457/download/"
}
```

行为：

- `file_key` 必须匹配现有 `Attachment.access_key`。
- 文件不存在时返回 MCP tool 错误。
- 不返回 `content`、`base64`、`text` 或文件 bytes。
- 下载继续复用现有 public access_key 下载端点，不要求额外认证。

## MCP 添加评论设计

扩展现有 MCP `add_comment`：

```text
add_comment(
  target_id,
  body="",
  file_keys=None,
  parent_id=None,
  mentions=None,
  ctx=None
)
```

### Target

`target_id` 沿用现有规则：

- `case_...`
- `alert_...`
- `artifact_...`
- `enrichment_...`
- `knowledge_...`
- `playbook_...`

找不到 target 时返回 MCP tool 错误。

### Body 和附件校验

`body` 和 `file_keys` 至少提供一个：

- 支持纯正文评论。
- 支持纯附件评论。
- 支持正文 + 附件评论。

如果 `body` 为空且 `file_keys` 为空，返回错误。

### File keys

`file_keys` 是一个或多个 `Attachment.access_key` 字符串。

输入可支持列表，也可兼容现有 MCP 参数风格中的 JSON 数组字符串或逗号分隔字符串。每个 key 必须能找到对应 `Attachment`，否则整体失败并返回错误。

权限规则：

- 任何有效 `access_key` 都可被关联到评论。
- 不要求附件由当前用户上传。

这与现有 REST 评论创建的宽松模型保持一致：REST 通过 `attachment_ids` 关联附件时也不校验上传者归属。

### Parent

`parent_id` 可选。

如果提供：

- 必须找到对应 `Comment`。
- 父评论必须属于同一个 `target_id` 对应的 `content_type + object_id`。
- 不允许跨记录回复。

### Mentions

`mentions` 可选，表示被提及用户。

输入规则：

- 以 username 为主要格式。
- 兼容数字用户 id。
- 可支持列表、JSON 数组字符串或逗号分隔字符串。
- 任意 mention 无法解析时，整体失败并返回错误。
- 不静默忽略无效 mention。

### 写权限

MCP `add_comment` 写权限对齐 REST：

- 只有 admin/user 角色可以创建评论。
- viewer 不能通过 MCP 创建评论或关联附件。
- 未认证或 API key 无效仍按现有 MCP 认证失败处理。

实现上应复用现有业务角色判断，例如 `is_business_writer(user)`。

`add_comment` 成功后返回同一套 MCP comment 精简结构，包括 `attachments` 元数据；不返回附件内容。

## 文件上传流程

MCP 不提供上传文件内容的 tool。

推荐流程：

1. 客户端或用户脚本使用 HTTP multipart 上传文件：

   ```text
   POST /api/attachments/
   Authorization: Api-Key <key>
   Content-Type: multipart/form-data
   ```

2. 上传响应中拿到 `access_key`。
3. 将该 `access_key` 作为 MCP `file_key` 传给 `add_comment(file_keys=[...])`。
4. 后续通过 `get_file(file_key)` 或评论附件元数据获取下载 URL。

`/api/attachments/` 上传权限保持现状：已认证用户可以上传。是否能把附件挂到评论由 `add_comment` 的写权限控制。

## 自定义 playbook 设计

本次不改自定义 playbook 接口。

用户在 playbook 中已经可以用 Python 代码直接实现：

- 用 `ContentType.objects.get_for_model(record)` 和 `Comment.objects.filter(...)` 查询记录评论。
- 用 `comment.attachments.all()` 获取附件列表。
- 用 `attachment.file.open("rb")` 读取任意文件类型的 bytes。
- 用 `create_record_comment(..., attachments=[...])` 创建带附件评论。

因此不新增 `BasePlaybook` 方法、不新增 service functions、不新增 playbook 文档。

## 错误处理

- 无效 `target_id`：返回明确错误，说明支持的前缀。
- 记录不存在：返回 `Record not found` 风格错误。
- 无效 `file_key`：返回文件不存在或无效 file key 错误。
- 无效 `parent_id`：返回父评论不存在或不属于同一 target 的错误。
- 无效 mention：返回无法解析的 username/id。
- viewer 调用 `add_comment`：返回权限错误。
- `get_file` 找不到附件：返回 MCP tool 错误。
- 下载 URL 指向的文件对象不存在时，现有下载端点继续返回 404。

不添加宽泛 try/except 或静默跳过无效输入；错误应显式暴露给 MCP 调用方。

## 安全和隐私

- 文件内容不会默认进入 MCP tool 响应。
- public download URL 继续依赖不可猜测 `access_key`，符合当前系统行为。
- MCP 写评论对齐 REST 角色权限，避免 viewer 通过 MCP 绕过 UI/REST 写权限。
- `download_url` 可能被模型上下文或日志保存；这是选择复用现有 public access_key URL 的已接受风险。
- 关联附件时不做上传者归属限制，保持与现有 REST 行为一致。

## 后端实现边界

预期改动集中在：

- `apps.mcp.serializers`
  - 增加 attachment 元数据序列化。
  - 扩展 comment 序列化。
  - 支持按记录加载 comments，并应用 `comments_limit` 和排序规则。
  - 支持根据 MCP request 构造绝对下载 URL，失败回退相对路径。
- `apps.mcp.tools`
  - 新增 `get_file(file_key)`。
  - 为 `list_cases/list_alerts/list_artifacts/list_playbooks/search_knowledge` 增加 `include_comments/comments_limit`。
  - 扩展 `add_comment` 参数和校验。
  - 增加 writer 权限校验。
  - 注册新增 MCP tool。

不需要数据库迁移。

## 兼容性

- REST 评论和附件接口保持兼容。
- REST 附件下载 URL 保持现状。
- MCP `add_comment(target_id, body)` 继续可用。
- MCP `list_cases(include_related=True)` 不再因为 `include_related` 隐式返回 comments；调用方需要显式传 `include_comments=true`。
- MCP comment 返回字段会新增 `updated_at`、`parent_id`、`attachments`。

## 验证标准

后端测试应覆盖：

- `get_file` 对有效 `file_key` 返回文件元数据和下载 URL。
- `get_file` 对无效 `file_key` 返回错误。
- comment 序列化返回附件外部字段，不返回数据库附件 id。
- `include_comments=false` 时各工具不返回 comments。
- `include_comments=true` 时各工具返回最新 N 条 comments，并按时间正序展示。
- `comments_limit` 默认 20，最大 50。
- `list_cases(include_related=True, include_comments=false)` 不返回 comments。
- `add_comment` 支持正文评论、纯附件评论、正文 + 附件评论。
- `add_comment` 在 body 和 file_keys 都为空时报错。
- `add_comment(file_keys=...)` 能通过 `access_key` 找到并关联附件。
- `add_comment` 对无效 file_key 报错且不创建评论。
- `add_comment(parent_id=...)` 只允许同一 target 的父评论。
- `add_comment(mentions=...)` 支持 username 和数字 id；无效 mention 报错。
- viewer API key 调用 `add_comment` 被拒绝。
- admin/user API key 调用 `add_comment` 成功。
- `/api/attachments/` 继续支持 `Authorization: Api-Key <key>` multipart 上传。
