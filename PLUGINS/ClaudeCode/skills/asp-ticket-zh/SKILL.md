---
name: asp-ticket-zh
description: '把外部 ticket 同步到 ASP、把 ticket 关联到 case、列出已同步 ticket，或更新已有 ticket 记录。'
argument-hint: 'list tickets [filters] | create ticket <uid> | attach ticket to case <case_id> | update ticket <ticket_id> <fields>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ ticket, case, sync, workflow ]
  documentation: https://asp.viperrtp.com/
---

# ASP Ticket

当用户要在 ASP 中处理外部 ticket 同步时，使用这个 skill。

## 适用场景

- 用户想创建一条已同步的外部 ticket 记录。
- 用户想把 ticket 关联到 case。
- 用户想按状态、类型或外部 UID 列出已同步 ticket。
- 用户想更新已同步 ticket 的字段。

## 运行规则

- 把 ticket 视为已同步的外部工作流记录，而不是平台的主要调查对象。
- 使用 `create_ticket` 创建已同步 ticket 记录。
- 使用 `attach_ticket_to_case` 把已有 ticket 记录关联到 case，前提是已经拿到 ticket row_id。
- 使用 `list_tickets` 浏览和查询。
- 使用 `update_ticket` 只修改用户明确要求变更的字段。

## 决策流程

1. 如果用户想创建已同步 ticket 记录，调用 `create_ticket`。
2. 如果用户想把 ticket 关联到 case，视情况先创建 ticket 或先取回已有 ticket row_id，再调用 `attach_ticket_to_case`。
3. 如果用户想浏览或对比已同步 ticket，调用 `list_tickets`。
4. 如果用户想修改已同步 ticket 字段，调用 `update_ticket`。

## SOP

### 列出 Ticket

1. 从请求中提取最窄且最有用的过滤条件。
2. 调用 `list_tickets`。
3. 解析返回的 JSON 字符串。
4. 以紧凑的工作流视图呈现；如果用户大概率下一步要附加或复用该 ticket，则显式展示 ticket row_id。

首选回复结构：

| Ticket ID | External UID | Type | Status | Title | Summary |
|-----------|--------------|------|--------|-------|---------|

然后在需要时补一句简短解释。

### 创建 Ticket

1. 收集用户想同步的外部 ticket 详情。
2. 调用 `create_ticket`。
3. 确认创建后的 ticket row_id。
4. 如果该 ticket 应该关联到 case，建议下一步附加到 case。

### 把 Ticket 附加到 Case

1. 要求提供 `case_id`。
2. 如果用户还没有 ticket row_id，则先为新 ticket 调用 `create_ticket`，或先取回已有 ticket。
3. 调用 `attach_ticket_to_case(case_id=<case_id>, ticket_row_id=<ticket_row_id>)`。
4. 确认 ticket 已附加成功。

### 更新 Ticket

1. 要求提供 `ticket_id`。
2. 只提取用户明确要求修改的字段。
3. 仅带变更字段调用 `update_ticket`。
4. 如果结果为 `None`，说明找不到该 ticket。
5. 只确认实际变更的字段。

首选回复结构：

- `Updated ticket`：ticket ID 或返回的 row_id
- `Changed fields`：只列本次请求实际提交的字段

## 澄清规则

- 只有当用户要附加到 case 却未提供时，才询问 `case_id`。
- 只有当用户要更新特定已同步 ticket 却未提供时，才询问 `ticket_id`。
- 如果用户想在一次请求中创建并附加 ticket，就完成两步，不要强迫用户拆分工作流。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出原始 JSON。
- 优先使用工作流语义，而不是存储语义。
- 当匹配的 ticket 很多时，展示最有价值的子集，并简要说明整体模式。

## 失败处理

- 如果没有匹配的 ticket，直接说明，并建议最有用的收敛方式。
- 如果目标 case 不存在，直接说明。
- 如果目标 ticket 不存在，直接说明。
- 如果请求更新信息不完整，只问一个聚焦问题，不要猜测。
