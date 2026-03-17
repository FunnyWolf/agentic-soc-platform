---
name: asp-case
description: 'Manage ASP security cases. Use when users ask to get a case, review a case, list cases, find cases by status or severity, or update case status, verdict, severity, or AI analysis fields.'
argument-hint: 'get case <case_id> | list cases [filters] | update case <case_id> <fields>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.2.0
  mcp-server: asp
  category: cyber security
  tags: [ case-management, soc, triage, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Case

Use this skill for case-centric SOC work on ASP. 

## When to Use

- The user gives a case ID and wants details, triage context, or a quick summary.
- The user wants to find cases by status, severity, or confidence.
- The user wants to update case workflow fields or AI analysis fields.
- The user wants help deciding what case to inspect next.

## Operating Rules

- Do not start by asking which operation they want if the request already implies it.
- Collect only missing required inputs.
- Prefer one MCP call when the user request is specific enough.
- Do not repeat MCP field descriptions back to the user unless needed to clarify an enum or missing input.
- Summarize case data for actionability, not as raw schema output.
- If an update request is ambiguous, ask a targeted clarification before writing.
- After updates, confirm only the fields that were changed.

## Decision Flow

1. If the user provides a specific case ID or says "open", "show", "review", or "summarize" a case, use `get_case`.
2. If the user asks to find, browse, or compare cases, use `list_cases`.
3. If the user asks to change status, verdict, severity, or AI fields, use `update_case`.
4. If the user asks to update a case but does not provide a case ID, ask for it.
5. If the user gives multiple possible filters, apply the ones ASP supports directly and mention any unsupported filters explicitly.

## SOP

### Review One Case

1. Call `get_case` with the case ID.
2. If the result is `None`, state that the case was not found.
3. Parse the JSON.
4. Present only the most useful sections for the request.
5. Highlight missing or suspicious fields only if they matter to the user's goal.

Preferred response structure:

- `Case`: case ID, title, severity, status, verdict, confidence, priority, category.
- `Timeline`: created, acknowledged, closed, calculated start/end if present.
- `Key Alerts`: only the most relevant alerts, not every alert by default.
- `Key Artifacts`: only high-signal artifacts such as IP, user, host, hash, URL.
- `Analyst / AI Notes`: comment, summary, AI fields when relevant.

Use concise incident-review language. Prefer a short analytical summary before structured details when the user asks for "what happened" or "help me understand this case".

### List Cases

1. Extract supported filters: `status`, `severity`, `confidence`, `limit`.
2. If the user gives comma-separated or natural-language lists, normalize them before calling MCP.
3. Call `list_cases`.
4. Parse the returned JSON strings.
5. Present a compact comparison view.
6. If the result set is large, suggest the next best filter rather than dumping many rows.

Preferred response structure:

| Case ID | Title | Severity | Status | Verdict | Confidence | Priority | Updated |
|---------|-------|----------|--------|---------|------------|----------|---------|

Then add one short line of interpretation when useful, for example:

- "Most matching cases are still in progress."
- "High-severity cases are concentrated in one category."
- "No matching cases were found."

### Update a Case

1. Require `case_id`.
2. Extract only fields the user explicitly wants to change.
3. Validate enum-like values from the request before calling MCP.
4. Call `update_case` with only changed fields.
5. If the result is `None`, state that the case was not found.
6. Confirm the update in a short changelog style.
7. If the user likely needs verification, suggest fetching the case again.

Good update targets:

- `severity`
- `status`
- `verdict`
- `severity_ai`
- `confidence_ai`
- `attack_stage_ai`
- `comment_ai`
- `summary_ai`

Preferred response structure:

- `Updated case`: case ID or returned row ID
- `Changed fields`: only the fields sent in the request
- `Next useful step`: optional, usually `get_case` if the user needs the refreshed record

## Clarification Rules

- Ask for `case_id` only when missing.
- Ask for enum clarification only when the requested value does not map cleanly to ASP values.
- If the user asks for "close", "resolve", or "mark suspicious", you may map directly to the corresponding status or verdict when the intent is unambiguous.
- If the user asks for a broad review like "show recent important cases", start with `list_cases` instead of forcing them to choose an operation.

## Output Rules

- Be concise.
- Do not dump raw JSON unless the user explicitly asks for it.
- Prefer analyst-facing wording over schema wording.
- Keep tables small; when many rows match, show the best subset and state the total count.
- Surface blockers clearly: case not found, unsupported filter, invalid enum value.

## Failure Handling

- If the case is missing, say so directly.
- If filters return no results, state that and suggest the most likely useful refinement.
- If an update target is unclear, ask one focused question instead of guessing.
