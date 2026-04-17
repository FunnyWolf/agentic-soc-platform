---
name: asp-knowledge-en
description: 'Search and maintain ASP internal knowledge records. Supports filtering database records and keyword or semantic retrieval in the vector store.'
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

Use this skill when the user needs to retrieve or maintain internal knowledge on ASP.

## Design Rationale

ASP internal Knowledge is stored as individual database records. The main fields are `title`, `body`, `using`, `action`, `source`, and `tags`.

- `title` is the knowledge title.
- `body` is the main knowledge content.
- `using` indicates whether the record can currently be retrieved from the vector database. This state is maintained by the backend workflow and cannot be set directly by the user.
- `tags` are the current labels for filtering and organization.
- `action` is the backend polling instruction. `Store` sends the record to the vectorization queue, `Remove` sends it to the vector store removal queue, and `Done` means there is no pending action.
- `source` is the knowledge origin. `Manual` means user-entered content; `Case` means content from historical case summaries, and the `Case` source is not enabled yet.

`search_knowledge` searches the vector database, not the raw database table. It is suitable for keyword or semantic lookup across knowledge that is already vectorized.

`list_knowledge` works on the database records themselves. It is suitable for field filtering, status checks, confirming whether a record exists, and checking whether it has been ingested or still has a pending action.

## When to Use

- The user wants to find relevant content in already vectorized internal knowledge by keyword or semantic similarity.
- The user wants to filter knowledge records by title, body, tags, action, source, or using state.
- The user wants to confirm whether a knowledge record has already entered the vector store or is still waiting for backend processing.
- The user wants to update a knowledge record or change its lifecycle action, such as storing it or removing it from the vector store.

## Operating Rules

- Treat this as a knowledge retrieval and maintenance tool, not as generic chat memory.
- If the user is looking for related knowledge content and provides a topic, problem description, symptom, case characteristic, phrase, or natural-language query, prefer `search_knowledge`.
- If the user wants to see what knowledge records exist or filter by database fields, use `list_knowledge`.
- If the user wants to maintain the title, body, tags, or action for a record, use `update_knowledge`.
- Do not treat `using` as a user-editable field; it is a system-maintained result state.
- When the user says to "add to the knowledge base" or "make it retrievable", interpret that as setting `action` to `Store`, not editing `using` directly.
- When the user says to "remove from the knowledge base" or "stop using it for retrieval", interpret that as setting `action` to `Remove`.

Note: `action=Store` and `action=Remove` are handled asynchronously by the backend, so the retrievability state may lag behind the update.

## Decision Flow

1. If the user wants to search vectorized knowledge content for relevant conclusions, experience, or historical knowledge, use `search_knowledge`.
2. If the user wants to filter knowledge records by database fields or confirm record status, use `list_knowledge`.
3. If the user wants to modify a known knowledge record's content or action, call `update_knowledge`.

## SOP

### Search Knowledge

1. Determine whether the user is looking for related knowledge content rather than querying table fields.
2. Convert the user's question, keywords, scenario description, or symptoms into a search query.
3. Call `search_knowledge` against the vector database.
4. Return the most relevant few results, prioritizing knowledge titles and short explanations that directly answer the user's question.
5. Do not expand the full body unless the user explicitly asks for it.

Preferred response structure:

| Knowledge ID | Title | Tags | Relevance |
|--------------|-------|------|-----------|

Then add one short line explaining how the results relate to the query.

### List or Filter Knowledge Records

1. Extract supported filters such as `action`, `source`, `using`, `title`, `body`, `tags`, and `limit`.
2. When the user wants to verify status, check pending store or remove records, or confirm whether a knowledge item exists, call `list_knowledge`.
3. Return a small, useful candidate list instead of expanding every field.

Preferred response structure:

| Knowledge ID | Title | Source | Action | Using | Tags |
|--------------|-------|--------|--------|-------|------|

Then add one short explanation when needed.

### Update Knowledge

1. Require `knowledge_id`.
2. Extract only the fields the user explicitly wants to change: `title`, `body`, `action`, and `tags`.
3. Call `update_knowledge` with only the changed fields.
4. If the result is `None`, state that the knowledge record was not found.
5. Do not attempt to update `using` directly.
6. If the user wants to "add to the vector store" or "restore retrieval", usually update `action` to `Store`.
7. If the user wants to "remove from the vector store" or "stop participating in retrieval", usually update `action` to `Remove`.
8. Confirm only the fields that actually changed.

Preferred response structure:

- `Updated knowledge`: knowledge ID or returned row_id

## Clarification Rules

- Ask for `knowledge_id` only when the user wants to update a specific record and did not provide it.
- Ask one focused question only when the intent cannot be clearly mapped to `search_knowledge`, `list_knowledge`, or `update_knowledge`.
- Ask for clarification only when the lifecycle change cannot be clearly mapped to `action`.
- Do not suggest editing `using` directly just because its current value is unexpected; explain it in terms of `action` and backend async processing.

## Output Rules

- Be concise.
- Do not output the full knowledge body unless the user explicitly asks for it.
- Prefer analyst-friendly wording over low-level storage wording.
- When explaining status, clearly distinguish between the database record state and the vector store retrievability state.
- When many records match, show the most valuable subset and briefly explain the overall pattern.

## Failure Handling

- If `search_knowledge` returns no results, say so directly and suggest a different keyword set or a more complete scenario description.
- If `list_knowledge` returns no matching records, say so directly and suggest the most useful refinement.
- If the record to update does not exist, say so directly.
- If the requested lifecycle change is unclear, ask one focused question instead of guessing.