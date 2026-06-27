# Playbook 与 Case 分配通知偏好设计

## 背景

ASP 已有 Inbox 站内信能力，支持系统消息、用户消息、未读计数和资源跳转。当前 Comment mention 会写入 Inbox，但 Playbook 执行完成和 Case 分配不会主动提醒相关用户。

本次目标是在不新增通知通道的前提下，让用户可以控制两类站内通知：

- Playbook 运行完成后通知触发该 Playbook 的用户。
- 用户被分配 Case 后通知新的负责人。

## 决策

采用 User 模型布尔字段保存个人通知偏好，并复用现有 Inbox system message 发送通知。

新增字段：

- `notify_on_playbook_completion`：Playbook 成功或失败完成后是否通知触发用户，默认开启。
- `notify_on_case_assignment`：Case 分配给当前用户时是否通知，默认开启。

偏好仅由用户本人在个人中心配置。管理员用户管理页面不新增代改入口。

## 目标

- Playbook 状态变为 `Success` 或 `Failed` 后，按触发用户偏好发送 Inbox 通知。
- Case `assignee` 从空或其他用户变为新用户后，按新负责人偏好发送 Inbox 通知。
- 个人中心新增 `Settings` 标签页，通知偏好作为其中一个设置区块。
- 通知失败不影响 Playbook 状态落库或 Case 分配保存，但必须记录错误日志。
- 更新 `asf-doc` 中对应用户文档，说明通知偏好和触发规则。

## 非目标

- 不新增邮件、Webhook、浏览器推送或实时 Toast 通知。
- 不让管理员代用户配置通知偏好。
- 不在取消分配、重复保存同一负责人时发送 Case 分配通知。
- 不在用户把 Case 分配给自己时发送 Case 分配通知。
- 不新增通用通知规则引擎或独立偏好表。

## 后端设计

### 用户偏好

在 `accounts.User` 上新增两个布尔字段，默认值为 `True`。迁移后现有用户也保持默认开启。

`UserSerializer` 返回两个字段，使登录、刷新用户资料和个人中心都能拿到当前偏好。

`UserProfileSerializer` 允许当前用户通过 `/auth/profile/` 更新这两个字段。管理员使用的 `UserAdminUpdateSerializer` 不包含这两个字段。

### 通知事件封装

新增一个小型事件通知模块，例如 `apps.inbox.notifications`，集中处理：

- 偏好判断。
- 用户是否存在、是否活跃。
- 自分配跳过逻辑。
- Inbox 文案。
- `metadata.source` 和相关上下文。
- 发送失败时的结构化日志。

通知仍通过 `apps.inbox.services.send_system_message()` 创建，使用 `content_object` 关联目标记录：

- Playbook 完成通知关联 `Playbook`，`metadata.source = "playbook_completion"`。
- Case 分配通知关联 `Case`，`metadata.source = "case_assignment"`。

### Playbook 完成通知

触发点在 Playbook worker 将状态写成终态之后：

- 成功路径：`mark_playbook_success()` 保存 `Success` 和 `remark` 后触发。
- 失败路径：`mark_playbook_failed()` 保存 `Failed` 和错误 remark 后触发。

发送条件：

- `playbook.user` 存在。
- 用户仍为 active。
- 用户开启 `notify_on_playbook_completion`。
- 状态为 `Success` 或 `Failed`。

通知内容包含 Playbook 名称、状态、关联 Case 标识和 remark 摘要，并链接到 Playbook 详情。

### Case 分配通知

触发点在 Case 更新保存后。保存前记录旧 `assignee_id`，保存后比较新值。

发送条件：

- 新 `assignee_id` 非空。
- 新 `assignee_id` 与旧值不同。
- 操作者不是新 assignee。
- 新 assignee 仍为 active。
- 新 assignee 开启 `notify_on_case_assignment`。

通知内容包含 Case 标识、标题和分配操作者，并链接到 Case 详情。

## 前端设计

个人中心新增 `Settings` 标签页。该标签页先包含一个 `Notification Preferences` 区块，后续可承载其他个人设置。

区块内包含两个 Ant Design `Switch`：

- `Notify me when my Playbook runs finish`
- `Notify me when a Case is assigned to me`

打开个人中心时使用 auth store 中的当前用户初始化表单。保存时 PATCH `/auth/profile/`，成功后刷新 auth store 并提示保存成功。

## 错误处理

通知发送是 best effort：

- Playbook 状态落库和 Case 分配保存是核心操作，通知失败不回滚这些操作。
- 通知失败必须记录错误日志，日志包含事件类型、目标记录 ID 和接收用户 ID。
- 偏好关闭、用户不存在、用户禁用、无触发用户、自分配等是正常跳过路径，不记录错误。

## 数据迁移

新增 accounts migration：

- 添加 `notify_on_playbook_completion = models.BooleanField(default=True)`。
- 添加 `notify_on_case_assignment = models.BooleanField(default=True)`。

不需要数据回填脚本，字段默认值覆盖现有用户。

## 文档

实现完成后更新 `asf-doc`：

- 先更新中文文档。
- 说明个人中心 `Settings` 中的通知偏好。
- 说明 Playbook 完成通知覆盖成功和失败。
- 说明 Case 分配通知只通知新负责人，取消分配、重复分配和自分配不会通知。
- 中文定稿后同步英文文档。

## 验证标准

后端：

- 迁移文件生成并可应用。
- Playbook 成功完成后，开启偏好的触发用户收到 Inbox system message。
- Playbook 失败完成后，开启偏好的触发用户收到 Inbox system message。
- 关闭 Playbook 完成通知后，不再收到 Playbook 完成消息。
- Case 分配给其他用户后，新负责人收到 Inbox system message。
- 关闭 Case 分配通知后，新负责人不再收到消息。
- 取消分配、重复保存同一 assignee、自分配不产生通知。

前端：

- 个人中心出现 `Settings` 标签页。
- 两个通知开关能反映当前用户偏好。
- 保存后刷新当前登录用户状态。

文档：

- `asf-doc` 中文和英文文档均描述该功能。
