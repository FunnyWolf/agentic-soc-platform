# Inbox message 资源链接展示设计

## 背景

Inbox message 中的资源链接当前会在部分资源上显示内部 `id`/UUID，而不是业务可读 ID，例如 `alert_000001`、`enrichment_000001`、`playbook_000001`、`knowledge_000001`。这不是 alert 单点问题，而是所有使用 readable id 的资源在 message 链接展示上的通用身份处理问题。

当前代码里资源身份被拆成两类字段：

- `object_id`：用于 GenericForeignKey 和详情接口加载记录的内部主键。
- `resource_label`：用于 message 链接展示的业务可读标签。

前端 `InboxDrawer` 的链接文字使用 `resource_label || object_id`。因此只要后端没有返回正确的 `resource_label`，内部主键就会泄漏到 message 链接文字上。

## 根因

现有逻辑只部分统一了 label 生成，没有统一 record identity 的完整生命周期。

`label_for_content_object()` 可以从对象上按字段优先级读取 `case_id`、`alert_id`、`artifact_id`、`enrichment_id`、`playbook_id`、`knowledge_id` 等 readable id，但它只是一个展示 label helper。`create_inbox_message()` 只有在调用方传入 `content_object` 时才会自动生成 `resource_key` 和 `resource_label`；如果调用链只传 `content_type + object_id`，或历史消息已经存了空 label/错误 label，最终序列化和前端 fallback 仍可能显示内部 `object_id`。

回复消息还会复制父消息模型字段里的 `resource_label`。如果父消息的持久化 label 已经是空值或内部 id，回复也会继承错误展示。

## 决策

保留 `object_id` 作为内部主键，继续用于打开详情页和 GenericForeignKey 查询；不要把详情路由和 ViewSet lookup 改成 readable id。

新增统一的 record identity 解析逻辑，输入可以是 `content_object`，也可以是 `content_type + object_id`，输出统一为：

- `resource_key`：前端资源 key，例如 `alerts`、`enrichments`、`playbooks`、`knowledge`。
- `object_id`：内部主键字符串，用于打开详情。
- `resource_label`：业务可读 ID，优先使用资源的 readable id 字段。

前端不再把内部 `object_id` 作为链接文字兜底。后端无法解析 label 时，前端显示中性占位文案，例如 `related record`，避免泄漏 UUID/id。

## 范围

覆盖以下资源：

- Case: `case_id`
- Alert: `alert_id`
- Artifact: `artifact_id`
- Enrichment: `enrichment_id`
- Playbook: `playbook_id`
- Knowledge: `knowledge_id`
- User: `username`

不改变资源详情接口 lookup 方式，不新增数据库字段，不迁移主键，不改变 comments/audit 使用 `object_id` 查询当前记录的设计。

## 组件设计

### 后端 identity helper

在 inbox 资源链接相关逻辑中集中定义资源身份解析：

1. 根据 `content_object` 直接读取模型和主键。
2. 如果只有 `content_type + object_id`，先通过 GenericForeignKey 等价逻辑解析对象。
3. 根据模型名映射 `resource_key`。
4. 根据模型名映射 readable id 字段，生成 `resource_label`。
5. 如果记录不存在或已删除，保留已有 `resource_label`，但不把内部 `object_id` 当作展示 label。

### Inbox 创建链路

`create_inbox_message()` 在保存前统一调用 identity helper：

- 新消息传入 `content_object` 时，自动补齐 `content_type`、`object_id`、`resource_key`、`resource_label`。
- 新消息只传 `content_type + object_id` 时，也解析对象并补齐 `resource_key`、`resource_label`。
- 调用方显式传入 `resource_label` 时，仍优先使用 helper 解析出的 readable label；只有对象不可解析时才保留调用方 label。

`send_system_message()`、`send_user_message()`、comment mention 通知都继续调用 `create_inbox_message()`，不各自重复 label 规则。

### Inbox 序列化链路

`InboxMessageSerializer.get_resource_label()` 使用同一个 identity helper 动态生成展示 label。这样可以修复历史 message 的 API 展示，即使数据库里的 `resource_label` 为空或已经存成内部 id，只要目标记录仍存在，API 也返回 readable id。

回复消息创建时不要直接复制父消息模型字段里的旧 `resource_label` 作为最终可信值，而是交给 `create_inbox_message()` 重新解析。

### 前端展示链路

`InboxDrawer.RecordLink` 保持使用 `object_id` 打开详情，因为后端 ViewSet 当前 lookup 都是内部主键。

链接文字改为只信任 `resource_label`；没有 label 时显示 `related record`，不显示 `object_id`。这保证未来某个资源解析失败时，UI 不会再次暴露内部 id。

## 数据流

1. 用户在资源详情评论中 mention 其他用户，前端提交 `content_type` 和当前记录内部 `id`。
2. 后端创建 Comment，随后创建 InboxMessage。
3. InboxMessage 创建前统一解析 record identity，保存内部 `object_id` 和 readable `resource_label`。
4. Inbox API 序列化时再次通过 helper 计算展示 label，修复历史数据和边界情况。
5. 前端 message 链接显示 `resource_label`，点击时仍用 `resource_key + object_id` 打开详情。

## 错误处理

- 目标记录已删除或 `content_type/object_id` 无法解析时，不抛出影响 inbox 列表的异常。
- API 保留已有 `resource_label`；如果没有可用 label，返回空字符串。
- 前端显示 `related record`，点击仍可尝试打开原 `object_id`；如果详情接口返回 404，沿用现有的 “Record not found or has been deleted” 提示。

## 验证

覆盖 case、alert、artifact、enrichment、playbook、knowledge 六类资源的 message 链接展示：

1. 新建 comment mention 后，Inbox API 的 `object_id` 是内部主键，`resource_label` 是对应 readable id。
2. 历史 message 即使持久化 `resource_label` 为空，API 仍能在目标记录存在时返回 readable id。
3. 回复 message 不继承错误 label，而是重新解析父消息目标资源。
4. 前端 Inbox 链接文字不再显示 UUID/id，点击仍能打开正确详情。

