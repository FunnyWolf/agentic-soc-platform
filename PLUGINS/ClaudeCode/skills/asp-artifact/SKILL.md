---
name: asp-artifact
description: 'Find artifacts by IOC, create new artifacts, attach artifacts to alerts, or save enrichment on artifacts.'
argument-hint: 'review artifact <artifact_id> | list artifacts [filters] | create artifact <value> | attach artifact to alert <alert_id> | enrich artifact <artifact_id>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ artifact, pivot, enrichment, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Artifact

Use this skill for artifact-centric investigation work on ASP.

## When to Use

- The user wants to find artifacts by value, type, role, owner, or reputation.
- The user wants to create a new artifact record.
- The user wants to attach a newly created artifact to an alert.
- The user wants to attach an existing artifact to an alert when they already have the artifact row ID.
- The user wants to attach enrichment or structured analysis to an artifact.

## Operating Rules

- Treat artifacts as the smallest pivot objects in the platform.
- Do not ask the user to choose an operation if the request already implies one.
- Collect only missing required inputs.
- Use `list_artifacts` for lookup and review.
- Use `create_artifact` when the user wants to add a new artifact record.
- Use `attach_artifact_to_alert` only after you already have an artifact row ID.
- Use `create_enrichment` plus `attach_enrichment_to_target` when the user wants to save analysis on the artifact itself.
- For detailed enrichment persistence workflow, use the `asp-enrichment` skill.
- Keep artifact responses short and investigation-oriented.

## Decision Flow

1. If the user asks to find or review artifacts, call `list_artifacts`.
2. If the user asks to create a new artifact, call `create_artifact`.
3. If the user asks to add an artifact to an alert, first call `create_artifact` when needed or retrieve an existing artifact row ID, then call `attach_artifact_to_alert`.
4. If the user asks to attach intel, analyst notes, or structured analysis to an artifact, use the `asp-enrichment` skill.
5. If the user is investigating from an artifact, use the artifact as a pivot and suggest the next useful hop only when needed.

## SOP

### List Artifacts

1. Extract the narrowest useful filters from the request.
2. Call `list_artifacts`.
3. Parse the returned JSON strings.
4. Present a compact artifact-oriented view, and surface the artifact row ID when the user is likely to attach or reuse the artifact next.

Preferred response structure:

| Artifact ID | Value | Type | Role | Owner | Reputation | Summary |
|-------------|-------|------|------|-------|------------|---------|

Then add one short interpretation line when useful.

### Create Artifact

1. Collect the minimum useful artifact information.
2. Call `create_artifact`.
3. Confirm the created artifact row ID.
4. If the artifact should belong to an alert, suggest attaching it next.

Preferred response structure:

- `Artifact`: created artifact row ID
- `Value`: the main artifact value when useful
- `Next useful step`: optional, usually attach it to an alert or enrich it

### Attach Artifact To Alert

1. Require `alert_id`.
2. If the user does not already have an artifact row ID, either call `create_artifact` for a new artifact or retrieve the existing artifact first.
3. Call `attach_artifact_to_alert(alert_id=<alert_id>, artifact_rowid=<artifact_rowid>)`.
4. Confirm that the artifact is attached.

## Clarification Rules

- Ask for `alert_id` only when the user wants alert attachment and did not provide it.
- Ask for `artifact_id` only when the user wants to enrich an existing artifact and did not provide it.
- If the user wants to add an artifact but does not clearly want it attached anywhere, create it without assuming a parent object.
- If the user asks for a pivot but not a specific tool path, start from artifact review and then suggest the next hop.

## Output Rules

- Be concise.
- Do not dump raw JSON unless the user explicitly asks for it.
- Prefer pivot-oriented language over storage wording.
- When many artifacts match, show the best subset and state the pattern briefly.

## Failure Handling

- If no artifacts match, say that directly and suggest the most useful refinement.
- If the target alert is missing, say that directly.
- If the target artifact is missing, say that directly.
- If the enrichment request is incomplete, ask one focused follow-up instead of guessing.
