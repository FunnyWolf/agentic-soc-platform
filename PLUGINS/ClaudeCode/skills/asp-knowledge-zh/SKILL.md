---
name: asp-knowledge-zh
description: 'ASP 平台内部 Knowledge 记录的检索与维护。支持在数据库中筛选 knowledge 记录，也支持通过 search_knowledge 在向量数据库中做关键词或语义搜索。'
argument-hint: 'search knowledge <query> | list knowledge <filters> | update knowledge <knowledge_id> <fields>'
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

ASP 的内部 Knowledge 本质上是一条一条数据库记录，核心字段包括 `title`、`body`、`using`、`action`、`source`、`tags`。

- title 是该条知识的标题
- body 是知识的主体内容
- using 表示该记录当前是否已在向量数据库中可被检索。这个字段由系统后端处理流程自动维护，用户不能直接设置
- tags 是当前知识的标签，可用于筛选和组织
- action 是后端轮询线程的处理指令。设置为 `Store` 后，系统会把该记录送入向量化存储队列；设置为 `Remove` 后，系统会把该记录送入向量数据库移除队列；`Done` 表示当前无待处理动作
- source 表示知识来源。`Manual` 为用户手动输入；`Case` 表示来自历史 Case 总结，当前 `Case` 来源尚未启用

`search_knowledge` 搜索的是向量数据库，不是原始数据库表。它适合在已经进入向量库的知识中进行关键词搜索和语义搜索。

`list_knowledge` 面向数据库记录本身，适合按字段筛选、巡检状态、确认某条记录是否存在，以及查看是否已入库或是否有待处理动作。

## 适用场景

- 用户想通过关键词或语义相似度，在已经向量化的内部知识中查找相关内容。
- 用户想按标题、正文、标签、action、source 或 using 状态筛选数据库中的 knowledge 记录。
- 用户想确认某条 knowledge 当前是否已进入向量库，或是否仍在等待后端处理。
- 用户想更新 knowledge 记录的内容或变更其处理动作，例如要求入库或从向量库移除。

## 运行规则

- 把它视为知识检索与维护工具，而不是通用聊天记忆。
- 如果用户是在“找相关知识内容”，尤其是给出主题、问题描述、症状、案件特征、短语或自然语言查询，优先使用 `search_knowledge`。
- 如果用户是在“查数据库里有哪些 knowledge 记录”或“按字段过滤某些记录”，使用 `list_knowledge`。
- 如果用户是在维护某条记录的标题、正文、标签或处理动作，使用 `update_knowledge`。
- 不要把 `using` 当作可直接更新的字段；它是系统处理后的结果状态。
- 当用户说“加入知识库”或“让它可被检索”时，通常应理解为把 `action` 设为 `Store`，而不是直接改 `using`。
- 当用户说“移出知识库”或“不要再参与检索”时，通常应理解为把 `action` 设为 `Remove`。

注意：`action=Store` 和 `action=Remove` 由后端异步处理，所以可检索状态可能会滞后于更新。

## 决策流程

1. 如果用户要在“已向量化的知识内容”里查找相关结论、经验或历史知识，使用 `search_knowledge`。
2. 如果用户要按数据库字段筛选 knowledge 记录，或确认记录状态，使用 `list_knowledge`。
3. 如果用户要修改已知 knowledge 记录的内容或处理动作，调用 `update_knowledge`。

## SOP

### 搜索 Knowledge

1. 判断用户是在找“相关知识内容”，而不是查表字段。
2. 将用户问题、关键词、场景描述或症状整理为检索 query。
3. 调用 `search_knowledge`，在向量数据库中执行搜索。
4. 返回最相关的少量结果，优先给出与用户问题直接相关的知识标题和简短说明。
5. 除非用户明确要求，否则不要展开完整 body。

首选回复结构：

| Knowledge ID | Title | Tags | Relevance |
|--------------|-------|------|-----------|

然后补一句这些结果与查询的关系。

### 列出或筛选 Knowledge 记录

1. 提取支持的结构化过滤条件，例如 `action`、`source`、`using`、`title`、`body`、`tags`、`limit`。
2. 当用户要核对记录状态、查待入库记录、查待移除记录、确认是否存在某条知识时，调用 `list_knowledge`。
3. 输出一个小而有用的候选列表，而不是把所有字段全量展开。

首选回复结构：

| Knowledge ID | Title | Source | Action | Using | Tags |
|--------------|-------|--------|--------|-------|------|

然后在需要时补一句简短解释。

### 更新 Knowledge

1. 要求提供 `knowledge_id`。
2. 只提取用户明确要求修改的字段：`title`、`body`、`action`、`tags`。
3. 仅带变更字段调用 `update_knowledge`。
4. 如果结果为 `None`，说明找不到该知识记录。
5. 不要尝试直接更新 `using`。
6. 如果用户要求“加入向量库”或“恢复检索”，通常把 `action` 更新为 `Store`。
7. 如果用户要求“从向量库删除”或“停止参与检索”，通常把 `action` 更新为 `Remove`。
8. 只确认实际变更的字段。

首选回复结构：

- `Updated knowledge`：knowledge ID 或返回的 row_id

## 澄清规则

- 只有在用户要更新特定记录但未提供时，才询问 `knowledge_id`。
- 只有当用户的意图不能清晰映射到 `search_knowledge`、`list_knowledge` 或 `update_knowledge` 时，才补问一个聚焦问题。
- 只有当请求的生命周期变更不能明确映射到 `action` 时，才要求澄清。
- 不要因为 `using` 的值不符合预期就建议直接修改它；应结合 `action` 和后端异步处理语义来解释。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出完整 knowledge body。
- 优先使用可复用的分析师语义，而不是底层存储语义。
- 当在解释状态时，明确区分“数据库记录状态”和“向量库可检索状态”。
- 当匹配记录很多时，展示最有价值的子集，并简要说明整体模式。

## 失败处理

- 如果 `search_knowledge` 没有结果，直接说明，并提示用户换一组关键词、换更完整的场景描述。
- 如果 `list_knowledge` 没有匹配记录，直接说明，并建议最可能有用的筛选收敛方式。
- 如果要更新的记录不存在，直接说明。
- 如果请求的生命周期变更含义不清，只问一个聚焦问题，不要猜测。
