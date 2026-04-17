---
name: asp-case-en
description: 'Manage ASP security cases, review discussions, update workflow or AI analysis fields, attach enrichment, or attach external tickets.'
argument-hint: 'review case <case_id> | list cases [filters] | update case <case_id> <fields>'
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

Use this skill when the user wants to work on ASP cases in a case-centric SOC flow.
Case is the core investigation object in ASP. One case can have one or more alerts, and one alert can have one or more artifacts, so users usually work primarily at the case level.

## When to Use

- The user gives a case ID and wants to review, triage, or quickly summarize it.
- The user wants to find cases by status, severity, confidence, verdict, correlation UID, title, or tags.
- The user wants case discussion context.
- The user wants to update case workflow fields or AI analysis fields.
- The user wants to attach enrichment or structured analysis to a case.
- The user wants to attach an external ticket record to a case.

## Operating Rules

- Summarize case data for decision-making, not as raw schema output.
- Keep the case as the primary view. Only pull related alerts or discussions when they help answer the case question.

## Additional Information

- `row_id` is the UUID for each case record and is used for data association.
- `case_id` is the human-readable unique ID for each case record.

## Decision Flow

1. If the user provides a specific case ID or says "open", "show", "review", or "summarize" a case, call `list_cases(case_id=<id>, limit=1)`.
2. If the user wants discussion history or analyst context, call `get_case_discussions` after retrieving the case.
3. If the user wants to browse or compare cases, use `list_cases`.
4. If the user wants to change status, verdict, severity, or AI fields, use `update_case`.
5. If the user wants to update a case but did not provide a case ID, ask for the case ID.
6. If the user gives multiple filters, apply only the ones ASP supports directly and state any unsupported filters explicitly.
7. If the user wants to attach enrichment or structured analysis to the case, use the `asp-enrichment-en` skill.
8. If the user wants to attach an external ticket to the case, use the `asp-ticket-en` skill.

## SOP

### Review One Case

1. If the user wants to review, analyze, or inspect case details, call `list_cases(case_id=<id>, limit=1, lazy_load=false)` to fetch the full related data, including alerts, enrichments, and tickets.
2. If the user only needs the basic case information, call `list_cases(case_id=<id>, limit=1)`.
3. If the result is empty, state that the case was not found.
4. If the user wants analyst context, call `get_case_discussions(case_id)`.
5. Present only the parts most relevant to the user's request.
6. Only emphasize missing or suspicious fields when they matter to the user's goal.

Preferred response structure:

- `Case`: case ID, title, severity, status, verdict, confidence, priority, category.
- `Timeline`: created, acknowledged, closed, and start/end if present.
- `Key Alerts`: only the most relevant alerts, not every alert by default.
- `Discussions`: only the key analyst or system discussion points when relevant.
- `Analyst / AI Notes`: comment, summary, and AI fields when relevant.

When the user asks "what happened" or "help me understand this case", start with a short analytical summary before structured details.

### List Cases

1. Extract supported filters: `case_id`, `status`, `severity`, `confidence`, `verdict`, `correlation_uid`, `title`, `tags`, and `limit`.
2. If the user provides comma-separated or natural-language lists, normalize them before calling MCP.
3. Call `list_cases`.
4. Parse the returned JSON strings.
5. Present a compact comparison view.
6. If the result set is large, suggest the next most useful filter instead of dumping many rows.

Preferred response structure:

| Case ID | Title | Severity | Status | Verdict | Confidence | Priority | Updated |
|---------|-------|----------|--------|---------|------------|----------|---------|

Then add one short interpretation line when useful, for example:

- "Most matching cases are still in progress."
- "High-severity cases are concentrated in one category."
- "No matching cases were found."

### Update Case

1. Require `case_id`.
2. Extract only the fields the user explicitly wants to change.
3. Validate enum-like values from the request before calling MCP.
4. Call `update_case` with only the changed fields.
5. If the result is `None`, state that the case was not found.
6. Confirm the update in a short changelog style.
7. If the user likely needs verification, suggest fetching the case again.

Common update targets:

- `severity`
- `status`
- `verdict`
- `severity_ai`
- `confidence_ai`
- `attack_stage_ai`
- `comment_ai`
- `summary_ai`

Preferred response structure:

- `Updated case`: case ID or returned row_id
- `Changed fields`: only the fields sent in the request

## Clarification Rules

- Ask for `case_id` only when it is missing.
- Ask for enum clarification only when the requested value does not map cleanly to ASP values.
- If the user asks for "close", "resolve", or "mark suspicious", map it directly to the corresponding status or verdict when the intent is unambiguous.
- If the user asks for a broad review like "show recent important cases", start with `list_cases` instead of forcing them to choose an operation.

## Output Rules

- Be concise.
- Do not output raw JSON unless the user explicitly asks for it.
- Prefer analyst-facing wording over schema wording.
- Keep tables small; when many rows match, show the most valuable subset and state the total count.
- When using multiple MCP calls for one review, merge the result into one coherent case narrative instead of showing call-by-call output.
- State blockers clearly: case not found, unsupported filter, invalid enum value.

## Failure Handling

- If the case does not exist, say so directly.
- If filters return no results, say so directly and suggest the most useful refinement.
- If the update target is unclear, ask one focused question instead of guessing.
