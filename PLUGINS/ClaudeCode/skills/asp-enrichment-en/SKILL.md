---
name: asp-enrichment-en
description: 'Save structured data as enrichment and attach it to a case, alert, or artifact.'
argument-hint: 'create enrichment for <case|alert|artifact> <target_id> | attach enrichment to <case|alert|artifact> <target_id>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ enrichment, analysis, context, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Enrichment

Use this skill when analysis results need to be saved back into ASP as structured context and attached to the corresponding case, alert, or artifact.

## When to Use

- The user wants to save structured analysis, intelligence, or investigation conclusions.
- The user wants to attach context to a case, alert, or artifact.
- The user wants to persist SIEM findings, threat intel, asset context, or analyst conclusions.
- The user already has an enrichment and wants to reuse it on a target object.

## Operating Rules

- Treat enrichment as the platform's structured result layer, not as a generic comment field.
- When the goal is to persist analysis on a `case`, `alert`, or `artifact`, use this skill.
- Separate creation from attachment.
- Use `create_enrichment` for a new result record.
- Use `attach_enrichment_to_target` only after you have the enrichment row_id.
- Keep the payload compact and actionable.
- Use the object-specific skill first when the user is still inspecting the object, and use this skill when saving the result.

## Additional Information

- `row_id` is the UUID for each enrichment record and is used for data association.
- `enrichment_id` is the human-readable unique ID for each enrichment record.

## Decision Flow

1. If the user wants to save a new structured result, call `create_enrichment` first.
2. If the user wants to attach the result to a case, alert, or artifact, call `attach_enrichment_to_target`.
3. If the user already has an enrichment row_id, skip creation and attach it directly.
4. If the user is still exploring the object rather than saving a result, use the corresponding object skill first.

## SOP

### Create And Attach New Enrichment

1. Require `target_id` such as `case_000001`, `alert_000001`, or `artifact_000001`.
2. Convert the user's analysis into a compact structured enrichment payload.
3. Call `create_enrichment` and keep the returned enrichment row_id.
4. Call `attach_enrichment_to_target(target_id=<target_id>, enrichment_row_id=<created_row_id>)`.
5. Confirm that the enrichment was created and attached successfully.

Preferred response structure:

- `Target ID`: target ID
- `Enrichment`: created enrichment row_id

### Attach Existing Enrichment

1. Require `target_id` and `enrichment_row_id`.
2. Call `attach_enrichment_to_target(target_id=<target_id>, enrichment_row_id=<enrichment_row_id>)`.
3. Confirm that the enrichment was attached successfully.

## Clarification Rules

- Ask for `target_id` only when it is missing.
- Ask for the enrichment row_id only when the user wants to reuse an existing enrichment and did not provide it.
- If the user only says "save this result", infer the most obvious target object from the current request when it is clear, and prefer Case.

## Output Rules

- Be concise.
- Do not output raw JSON unless the user explicitly asks for it.
- Prefer analyst-facing wording over storage wording.
- Clearly state what was saved, where it was attached, and why it is useful.

## Failure Handling

- If the target object does not exist, say so directly.
- If the enrichment payload is incomplete, ask one focused follow-up instead of guessing.
- If attachment fails because the enrichment row_id is missing, ask for it or create a new enrichment first.
