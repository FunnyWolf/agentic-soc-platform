---
name: asp-knowledge
description: 'Find internal guidance for a case or alert, check whether knowledge already exists, or update existing ASP knowledge records.'
argument-hint: 'search knowledge [filters] | update knowledge <knowledge_id> <fields>'
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

Use this skill for internal knowledge retrieval and maintenance on ASP.

## When to Use

- The user wants to find existing internal knowledge by title, body, tags, action, source, or usage state.
- The user wants to review whether a knowledge item should remain active or be removed.
- The user wants to update the content, tags, or lifecycle state of a knowledge record.
- The user wants to inspect reusable analyst knowledge before deciding the next case, alert, or hunt action.

## Operating Rules

- Treat this as knowledge retrieval and curation, not general free-form chat memory.
- Prefer the narrowest useful search filters first.
- Use fuzzy title or body matching when the user gives phrases, symptoms, or partial wording.
- Use tags when the user is operating by scenario, technique, or topic.
- For updates, modify only the fields the user explicitly wants changed.
- If the user needs semantic search rather than field-based filtering, say that the current MCP surface is still filter-oriented.

## Decision Flow

1. If the user wants to find or browse knowledge, call `list_knowledge` with the narrowest useful filters.
2. If the user asks to revise content, status, source, action, or tags for a known record, call `update_knowledge`.
3. If the user asks whether some knowledge already exists but gives only partial wording, start with fuzzy `title` and `body` filters.
4. If the user asks to manage lifecycle or storage state, use `action` and `using` rather than inventing a separate workflow.

## SOP

### Search Knowledge

1. Extract supported filters: `action`, `source`, `using`, `title`, `body`, `tags`, `limit`.
2. Use fuzzy title or body filters when the user gives partial text.
3. Use tags when the user is really asking for a topic or scenario bucket.
4. Call `list_knowledge`.
5. Parse returned JSON strings.
6. Present a small, useful shortlist instead of every field.

Preferred response structure:

| Knowledge ID | Title | Source | Action | Using | Tags |
|--------------|-------|--------|--------|-------|------|

Then add one short interpretation line when useful.

### Update Knowledge

1. Require `knowledge_id`.
2. Extract only fields the user explicitly wants to change: `title`, `body`, `using`, `action`, `source`, `tags`.
3. Call `update_knowledge` with only changed fields.
4. If the result is `None`, state that the knowledge record was not found.
5. Confirm only the changed fields.

Preferred response structure:

- `Updated knowledge`: knowledge ID or returned row ID
- `Changed fields`: only the fields sent in the request
- `Next useful step`: optional, usually to query similar knowledge or verify the updated record through a narrowed search

## Clarification Rules

- Ask for `knowledge_id` only when the user wants to update a specific record and did not provide it.
- Ask for lifecycle clarification only when the requested state does not map cleanly to `action` or `using`.
- If the user asks to "disable", "archive", or "stop using" a knowledge record, prefer clarifying whether they mean `using=false`, a lifecycle `action`, or both.

## Output Rules

- Be concise.
- Do not dump full knowledge bodies unless the user explicitly asks.
- Prefer reusable analyst wording over raw storage wording.
- When many records match, show the best subset and explain the pattern briefly.

## Failure Handling

- If no knowledge records match, say that directly and suggest the most likely useful refinement.
- If the record to update is missing, say so directly.
- If the requested lifecycle change is ambiguous, ask one focused question instead of guessing.