---
name: asp-knowledge-zh
description: 'ASP 平台存储的内部知识，通过RAG技术在内部知识库搜索,检查是否已有知识记录，或更新knowledge 记录。'
argument-hint: 'search in knowledge base | list knowledge |update knowledge <knowledge_id> <fields>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ knowledge, memory, rag, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Knowledge

当用户要在 ASP 中检索或维护内部知识库时，使用这个 skill。

# 设计思路

ASP 的内部 Knowledge 是一条一条数据库记录.有 title, body, using, action, source, tags字段.

- title 是该条知识的标题
- body 是知识的主体内容
- using 表示这个知识是否正在使用(True表示已经存储到向量数据库,False表示不在向量数据库中，系统自动调整，用户无法设置)
- tags 当前知识的标签,用于搜索过滤
- action 设置为 Store 该条数据进入向量化队列,设置为 Remove 数据进入向量数据库移除队列, Done 表示当前记录无操作
- source Manual 用户手动输入内容, Case 内容为历史某个 Case 总结(Case 格式 source当前未启用)

## 适用场景

- 用户想按标题、正文、标签、action、source 或使用状态查找已有内部知识。
- 用户想确认某条知识是否还应继续启用或应被移除。
- 用户想更新知识记录的内容、标签或生命周期状态。
- 用户想通过自然语言在 knowledge 生成的向量数据库中检索记录时

## 运行规则

- 把它视为知识检索与维护工具，而不是通用聊天记忆。
- 如果用户给的是短语、症状或部分表述，优先使用search_knowledge。
- list_knowledge / update_knowledge 通常用于维护知识记录,而不是搜索知识库

## 决策流程

1. 如果用户要通过语义查找相关知识，使用 `search_knowledge`。
2. 如果用户要修改已知记录的内容、状态、source、action 或 tags，调用 `update_knowledge`。
4. 如果用户要管理生命周期或启用状态，优先使用 `action` 和 `using`，而不是发明新的工作流。

## SOP

### 搜索 Knowledge

1. 提取支持的过滤条件：`action`、`source`、`using`、`title`、`body`、`tags`、`limit`。
2. 当用户给出部分文本时，使用模糊 title/body 过滤。
3. 当用户本质上是在按主题或场景查找时，使用 tags。
4. 调用 `list_knowledge`。
5. 解析返回的 JSON 字符串。
6. 输出一个小而有用的候选列表，而不是所有字段全量展开。

首选回复结构：

| Knowledge ID | Title | Source | Action | Using | Tags |
|--------------|-------|--------|--------|-------|------|

然后在需要时补一句简短解释。

### 更新 Knowledge

1. 要求提供 `knowledge_id`。
2. 只提取用户明确要求修改的字段：`title`、`body`、`action`、`tags`。
3. 仅带变更字段调用 `update_knowledge`。
4. 如果结果为 `None`，说明找不到该知识记录。
5. 只确认实际变更的字段。

首选回复结构：

- `Updated knowledge`：knowledge ID 或返回的 row ID

## 澄清规则

- 只有在用户要更新特定记录但未提供时，才询问 `knowledge_id`。
- 只有当请求状态不能清晰映射到 `action` 或 `using` 时，才要求澄清生命周期语义。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出完整 knowledge body。
- 优先使用可复用的分析师语义，而不是底层存储语义。
- 当匹配记录很多时，展示最有价值的子集，并简要说明整体模式。

## 失败处理

- 如果没有匹配的 knowledge 记录，直接说明，并建议最可能有用的收敛方式。
- 如果要更新的记录不存在，直接说明。
- 如果请求的生命周期变更含义不清，只问一个聚焦问题，不要猜测。
