---
name: asp-alert-en
description: 'Review ASP alerts, update AI analysis fields, inspect alert discussions, or attach enrichment after analysis.'
argument-hint: 'review alert <alert_id> | list alerts [filters] | update alert <alert_id> <fields>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ alert-management, soc, triage, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Alert

Use this skill when the user needs to work on ASP alerts for SOC analysis.
An alert is secondary data in ASP. Each alert belongs to a case, and each alert can have one or more artifacts attached.

## When to Use

- The user gives an alert ID and wants a quick review, inspection, or summary.
- The user wants to find alerts by status, severity, confidence, or correlation UID.
- The user wants to inspect discussion context for an alert.
- The user wants to update AI analysis fields on an alert.
- The user wants to attach enrichment to an alert after analysis.

## Operating Rules

- Keep the response focused on triage value rather than repeating schema fields.
- If the user is working on a specific alert, prefer `list_alerts(alert_id=<id>, limit=1)` because the current MCP surface does not expose a separate `get_alert` tool.
- If the user wants to save structured analysis back onto the alert, use the `asp-enrichment-en` skill.

Note: alerts only support `severity_ai`, `confidence_ai`, and `comment_ai` updates; verdict and summary fields belong to case updates.

## Additional Information

- `row_id` is the UUID for each alert record and is used for data association.
- `alert_id` is the human-readable unique ID for each alert record.

## Decision Flow

1. If the user provides a specific alert ID or says "open", "show", "review", or "summarize" an alert, call `list_alerts(alert_id=<id>, limit=1)`.
2. If the user wants discussion context, call `get_alert_discussions(alert_id)` after retrieving the alert.
3. If the user wants to browse or compare alerts, use `list_alerts` with supported filters.
4. If the user wants to update AI severity, AI confidence, or AI comment, call `update_alert`.
5. If the user wants to attach analysis results, intelligence, or structured context to the alert, use the `asp-enrichment-en` skill.

## SOP

### Review One Alert

1. If the user wants to review, analyze, or inspect alert details, call `list_alerts(alert_id=<id>, limit=1, lazy_load=false)` to fetch the full related data.
2. If the user only needs the basic alert information, call `list_alerts(alert_id=<id>, limit=1)`.
3. If the result is empty, state that the alert was not found.
4. Parse the first JSON record.
5. If the user wants analyst discussion context, call `get_alert_discussions(alert_id)`.
6. Present only the most useful triage fields.

Preferred response structure:

- `Alert`: alert ID, title or name, severity, status, confidence, correlation UID.
- `Timeline`: created or updated time when present.
- `Key Context`: source, rule, category, owner, or other high-signal fields.
- `Discussions`: only the most relevant analyst or system notes when needed.
- `Assessment`: short triage judgment.

### List Alerts

1. Extract supported filters: `alert_id`, `status`, `severity`, `confidence`, `correlation_uid`, `limit`.
2. Normalize natural-language filters before calling MCP.
3. Call `list_alerts`.
4. Parse the returned JSON strings.
5. Present a compact comparison view.

Preferred response structure:

| Alert ID | Title | Severity | Status | Confidence | First Seen | Rule Name |
|----------|-------|----------|--------|------------|------------|-----------|

Then add one short explanation line when needed.

### Update Alert AI Fields

1. Require `alert_id`.
2. Extract only supported AI fields: `severity_ai`, `confidence_ai`, and `comment_ai`.
3. Call `update_alert` with only the changed fields.
4. If the result is `None`, state that the alert was not found.
5. Confirm only the fields that changed.

## Clarification Rules

- Ask for `alert_id` only when it is missing for alert-related actions.
- Ask for enum clarification only when the requested value does not map cleanly to ASP values.
- If the user says "lower confidence", "raise severity", or "leave a note", map it directly to the matching AI field when the intent is clear.

## Output Rules

- Be concise.
- Do not output raw JSON unless the user explicitly asks for it.
- Prefer triage wording over schema wording.
- If alert data and discussion context are both used, merge them into one coherent view.
- State blockers clearly: alert not found, unsupported filter, invalid enum value, or incomplete follow-up payload.

## Failure Handling

- If the alert does not exist, say so directly.
- If filters return no results, say so directly and suggest the most useful refinement.
- If the requested update field is unsupported, say which alert fields are writable.
- If the enrichment input is incomplete, ask one focused follow-up instead of guessing.