---
name: asp-enrichment
description: 'Save structured analysis results as enrichment and attach them to a case, alert, or artifact.'
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

Use this skill when analysis results should be saved back into ASP as structured context.

## When to Use

- The user wants to save structured analysis, intel, or investigation notes.
- The user wants to attach context to a case, alert, or artifact.
- The user wants to persist SIEM findings, threat intel, asset context, or analyst conclusions.
- The user wants to reuse an existing enrichment and attach it to a target object.

## Operating Rules

- Treat enrichment as the platform's structured result layer, not as a generic comment field.
- Use this skill when the goal is to persist analysis on a `case`, `alert`, or `artifact`.
- Separate creation from attachment.
- Use `create_enrichment` for a new result record.
- Use `attach_enrichment_to_target` only after you have the enrichment row ID.
- Keep the payload compact and operational.
- Prefer object-local skills for reviewing the object itself, and this skill for saving the result.

## Decision Flow

1. If the user wants to save a new structured result, call `create_enrichment` first.
2. If the user wants to attach that result to a case, alert, or artifact, call `attach_enrichment_to_target`.
3. If the user already has an existing enrichment row ID, skip creation and attach it directly.
4. If the user is still exploring the object rather than saving a result, use the corresponding object skill first.

## SOP

### Create And Attach New Enrichment

1. Require `target_type` and `target_id`.
2. Convert the user's analysis into a compact structured enrichment payload.
3. Call `create_enrichment` and keep the returned enrichment row ID.
4. Call `attach_enrichment_to_target(target_type=<target_type>, target_id=<target_id>, enrichment_rowid=<created_rowid>)`.
5. Confirm that the enrichment was created and attached.

Preferred response structure:

- `Target`: target type and target ID
- `Enrichment`: created enrichment row ID
- `Attachment`: attached to target
- `Next useful step`: optional, usually continue investigation, review the enriched object, or run follow-up automation

### Attach Existing Enrichment

1. Require `target_type`, `target_id`, and `enrichment_rowid`.
2. Call `attach_enrichment_to_target(target_type=<target_type>, target_id=<target_id>, enrichment_rowid=<enrichment_rowid>)`.
3. Confirm that the enrichment was attached.

## Clarification Rules

- Ask for `target_type` and `target_id` only when missing.
- Ask for the enrichment row ID only when the user wants to reuse an existing enrichment and did not provide it.
- If the user only says "save this result", infer the most obvious target object from the current request when it is clear.
- If the user wants a note rather than a structured result, still prefer enrichment when the content is investigative context.

## Output Rules

- Be concise.
- Do not dump raw JSON unless the user explicitly asks for it.
- Prefer analyst-facing wording over storage wording.
- Emphasize what was saved, where it was attached, and why it is useful.

## Failure Handling

- If the target object is missing, say so directly.
- If the enrichment payload is incomplete, ask one focused follow-up instead of guessing.
- If attachment fails because the enrichment row ID is missing, ask for it or create a new enrichment first.
