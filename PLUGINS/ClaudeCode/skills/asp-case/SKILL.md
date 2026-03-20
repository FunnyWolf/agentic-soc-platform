---
name: asp-case
description: 'Manage ASP security cases. Use when users ask to review a case, list cases, inspect case discussions, check related alerts or playbook runs for a case, or update case workflow and AI analysis fields.'
argument-hint: 'review case <case_id> | list cases [filters] | update case <case_id> <fields> | run playbook for case <case_id> <playbook_name>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.3.0
  mcp-server: asp
  category: cyber security
  tags: [ case-management, soc, triage, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Case

Use this skill for case-centric SOC work on ASP. 

## When to Use

- The user gives a case ID and wants a review, triage context, or quick summary.
- The user wants to find cases by status, severity, confidence, verdict, correlation UID, title, or tags.
- The user wants case discussion context.
- The user wants to check related alerts or playbook runs from a case view.
- The user wants to update case workflow fields or AI analysis fields.
- The user wants to attach enrichment or structured analysis to a case.
- The user wants to attach an external ticket record to a case.
- The user wants to run a playbook against a case.

## Operating Rules

- Do not start by asking which operation they want if the request already implies it.
- Collect only missing required inputs.
- Prefer one MCP call when the user request is specific enough, but use a short multi-step flow when the user asks for a real case review.
- Do not repeat MCP field descriptions back to the user unless needed to clarify an enum or missing input.
- Summarize case data for actionability, not as raw schema output.
- If an update request is ambiguous, ask a targeted clarification before writing.
- After updates, confirm only the fields that were changed.
- For single-case retrieval, use `list_cases(case_id=...)` because the current MCP surface does not expose a separate `get_case` tool.
- Keep case as the primary user view. Pull alerts, discussions, or playbook runs only when they help answer the case question.
- If the user wants to save structured analysis back onto the case, use the `asp-enrichment` skill.

## Decision Flow

1. If the user provides a specific case ID or says "open", "show", "review", or "summarize" a case, call `list_cases` with `case_id` and `limit=1`.
2. If the user wants discussion history or analyst context, call `get_case_discussions` after retrieving the case.
3. If the user wants related alert context, pivot through the case's `correlation_uid` and call `list_alerts` when that helps answer the case question.
4. If the user wants case automation status, call `list_playbook_runs(source_id=case_id, type=[CASE])`.
5. If the user wants to run automation on the case, use `list_available_playbook_definitions` only when the playbook name is missing, then call `execute_playbook(type=CASE, record_id=case_id, name=...)`.
6. If the user asks to attach enrichment or structured analysis to the case, use the `asp-enrichment` skill.
7. If the user asks to attach an external ticket to the case, first call `create_ticket`, then call `attach_ticket_to_case(case_id=<case_id>, ticket_rowid=<created_rowid>)`.
8. If the user asks to find, browse, or compare cases, use `list_cases`.
9. If the user asks to change status, verdict, severity, or AI fields, use `update_case`.
10. If the user asks to update a case but does not provide a case ID, ask for it.
11. If the user gives multiple possible filters, apply the ones ASP supports directly and mention any unsupported filters explicitly.

## SOP

### Review One Case

1. Call `list_cases(case_id=<id>, limit=1)`.
2. If the result is empty, state that the case was not found.
3. Parse the first JSON record.
4. If the user asks for analyst context, call `get_case_discussions(case_id)`.
5. If the case contains a useful `correlation_uid` and the user needs related alert context, use it as a pivot and call `list_alerts(correlation_uid=...)`.
6. If the user asks whether automation has run or is pending, call `list_playbook_runs(source_id=case_id, type=[CASE])`.
7. Present only the most useful sections for the request.
8. Highlight missing or suspicious fields only if they matter to the user's goal.

Preferred response structure:

- `Case`: case ID, title, severity, status, verdict, confidence, priority, category.
- `Timeline`: created, acknowledged, closed, calculated start/end if present.
- `Key Alerts`: only the most relevant alerts, not every alert by default.
- `Discussions`: only the key analyst or system discussion points when relevant.
- `Playbook Runs`: only current or recent runs when relevant.
- `Analyst / AI Notes`: comment, summary, AI fields when relevant.

Use concise incident-review language. Prefer a short analytical summary before structured details when the user asks for "what happened" or "help me understand this case".

### List Cases

1. Extract supported filters: `case_id`, `status`, `severity`, `confidence`, `verdict`, `correlation_uid`, `title`, `tags`, `limit`.
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

### Run A Case Playbook

1. Require `case_id`.
2. If the user has not named a playbook definition, call `list_available_playbook_definitions` and suggest the most relevant options instead of guessing.
3. Call `execute_playbook(type=CASE, record_id=case_id, name=<definition_name>, user_input=<optional>)`.
4. Confirm that a pending playbook run record was created.
5. If the user wants follow-up status, call `list_playbook_runs(source_id=case_id, type=[CASE])`.

Preferred response structure:

- `Case`: case ID
- `Playbook`: definition name
- `Run status`: usually pending at creation time
- `User input`: only if provided
- `Next useful step`: optional, usually to query case-related runs

### Attach Ticket To Case

1. Require `case_id`.
2. Collect the external ticket details the user wants to sync.
3. Call `create_ticket` and keep the returned ticket row ID.
4. Call `attach_ticket_to_case(case_id=<case_id>, ticket_rowid=<created_rowid>)`.
5. Confirm that the ticket was created and attached to the case.

Preferred response structure:

- `Case`: case ID
- `Ticket`: created ticket row ID or external ticket identifier when useful
- `Attachment`: attached to case
- `Next useful step`: optional, usually to review the case again or update the synced ticket later

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
- `Next useful step`: optional, usually `list_cases(case_id=..., limit=1)` if the user needs the refreshed record

## Clarification Rules

- Ask for `case_id` only when missing.
- Ask for enum clarification only when the requested value does not map cleanly to ASP values.
- If the user asks for "close", "resolve", or "mark suspicious", you may map directly to the corresponding status or verdict when the intent is unambiguous.
- If the user asks for case automation but does not provide a playbook definition name, show available definitions instead of inventing one.
- If the user asks for a broad review like "show recent important cases", start with `list_cases` instead of forcing them to choose an operation.

## Output Rules

- Be concise.
- Do not dump raw JSON unless the user explicitly asks for it.
- Prefer analyst-facing wording over schema wording.
- Keep tables small; when many rows match, show the best subset and state the total count.
- When using multiple MCP calls for one review, merge the result into one coherent case narrative instead of showing call-by-call output.
- Surface blockers clearly: case not found, unsupported filter, invalid enum value.

## Failure Handling

- If the case is missing, say so directly.
- If filters return no results, state that and suggest the most likely useful refinement.
- If the playbook definition name does not match available definitions, say that directly and offer the closest available options.
- If an update target is unclear, ask one focused question instead of guessing.
