---
name: asp-alert
description: 'Review ASP alerts, update AI triage, create and attach new artifacts, inspect alert discussions, or attach enrichment to alerts.'
argument-hint: 'review alert <alert_id> | list alerts [filters] | update alert <alert_id> <fields> | append artifact to alert <alert_id>'
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

Use this skill for alert-centric SOC work on ASP.

## When to Use

- The user gives an alert ID and wants a quick review or triage summary.
- The user wants to find alerts by status, severity, confidence, or correlation UID.
- The user wants analyst discussion context on an alert.
- The user wants to update AI triage fields on an alert.
- The user wants to create and attach a new artifact to an alert.
- The user wants to attach enrichment to an alert after analysis.

## Operating Rules

- Do not ask the user to choose an operation if the request already implies one.
- Collect only missing required inputs.
- Prefer `list_alerts(alert_id=..., limit=1)` for single-alert retrieval because there is no separate `get_alert` tool on the current MCP surface.
- Keep the response focused on triage value rather than raw schema output.
- For updates, change only the fields the user explicitly requested.
- For append actions, confirm the target alert ID and the minimum required payload before writing.
- For attachment flows, distinguish between creating a new related record and reusing an existing one. Attach tools need the related record row ID.
- If the user wants to save structured analysis back onto the alert, use the `asp-enrichment` skill.

## Decision Flow

1. If the user provides a specific alert ID or says "open", "show", "review", or "summarize" an alert, call `list_alerts(alert_id=<id>, limit=1)`.
2. If the user asks for discussion context, call `get_alert_discussions(alert_id)` after retrieving the alert.
3. If the user asks to browse or compare alerts, call `list_alerts` with supported filters.
4. If the user asks to update AI severity, AI confidence, or AI comment, call `update_alert`.
5. If the user asks to add an IOC, host, user, URL, or hash to the alert, first call `create_artifact` for a new artifact or locate an existing artifact row ID, then call `attach_artifact_to_alert(alert_id=<alert_id>, artifact_rowid=<artifact_rowid>)`.
6. If the user asks to attach analysis results, intel, or structured context to the alert, use the `asp-enrichment` skill.

## SOP

### Review One Alert

1. Call `list_alerts(alert_id=<id>, limit=1)`.
2. If the result is empty, state that the alert was not found.
3. Parse the first JSON record.
4. If the user asked for analyst context, call `get_alert_discussions(alert_id)`.
5. Present only the most useful triage fields.

Preferred response structure:

- `Alert`: alert ID, title or name if present, severity, status, confidence, correlation UID.
- `Timeline`: created or updated times when present.
- `Key Context`: source, rule, category, owner, or similar high-signal fields.
- `Discussions`: only the most relevant analyst or system notes when needed.
- `Assessment`: short triage interpretation.

### List Alerts

1. Extract supported filters: `alert_id`, `status`, `severity`, `confidence`, `correlation_uid`, `limit`.
2. Normalize natural-language filter lists before calling MCP.
3. Call `list_alerts`.
4. Parse returned JSON strings.
5. Present a compact comparison view.

Preferred response structure:

| Alert ID | Severity | Status | Confidence | Correlation UID | Summary |
|----------|----------|--------|------------|-----------------|---------|

Then add one short interpretation line when useful.

### Update Alert AI Fields

1. Require `alert_id`.
2. Extract only supported AI fields: `severity_ai`, `confidence_ai`, `comment_ai`.
3. Call `update_alert` with only changed fields.
4. If the result is `None`, state that the alert was not found.
5. Confirm only the changed fields.

### Append Artifact To Alert

1. Require `alert_id`.
2. If the user wants a new artifact, collect the smallest useful artifact payload first: usually `value`, and when possible `name`, `type`, or `role`.
3. For a new artifact, call `create_artifact` and keep the returned artifact row ID.
4. For an existing artifact, first retrieve it and keep the returned artifact row ID.
5. Call `attach_artifact_to_alert(alert_id=<alert_id>, artifact_rowid=<artifact_rowid>)`.
6. Confirm that the artifact is attached.
7. If the artifact is likely to need context, suggest creating enrichment for the artifact or the alert next.

## Clarification Rules

- Ask for `alert_id` only when missing for alert-specific actions.
- Ask for enum clarification only when the requested value does not map cleanly to ASP values.
- If the user asks to "lower confidence", "raise severity", or "leave a note", map directly to the matching AI fields when intent is clear.
- If the user asks to add an artifact but the value is missing, ask for the artifact value before writing.

## Output Rules

- Be concise.
- Do not dump raw JSON unless the user explicitly asks for it.
- Prefer triage wording over schema wording.
- Merge alert data and discussion context into one coherent view when both are used.
- Surface blockers clearly: alert not found, unsupported filter, invalid enum value, or incomplete append payload.

## Failure Handling

- If the alert is missing, say so directly.
- If filters return no results, state that and suggest the most useful refinement.
- If the requested update field is unsupported, say which alert fields are actually writable.
- If enrichment or artifact input is incomplete, ask one focused follow-up instead of guessing.