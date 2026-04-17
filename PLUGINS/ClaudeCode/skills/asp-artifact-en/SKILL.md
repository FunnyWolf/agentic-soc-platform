---
name: asp-artifact-en
description: 'Find artifacts by IOC and attach enrichment to artifacts.'
argument-hint: 'review artifact <artifact_id> | list artifacts [filters]'
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

Use this skill when the user needs to investigate artifacts on ASP.
Artifacts are created automatically by system processes. You can list and analyze existing artifacts, and save analysis back through enrichment.

## When to Use

- The user wants to find artifacts by value, type, role, owner, or reputation.
- The user wants to attach enrichment or structured analysis to an artifact.

## Operating Rules

- Treat artifacts as the smallest investigation object on the platform.
- Use `list_artifacts` for lookup and review.
- If the user wants to save analysis on the artifact itself, use `create_enrichment` plus `attach_enrichment_to_target`.
- For the full enrichment persistence workflow, use the `asp-enrichment-en` skill.

## Additional Information

- `row_id` is the UUID for each artifact record and is used for data association.
- `artifact_id` is the human-readable unique ID for each artifact record.

## Decision Flow

1. If the user wants to find or review an artifact, call `list_artifacts`.
2. If the user wants to attach intelligence, analysis notes, or structured analysis to an artifact, use the `asp-enrichment-en` skill.
3. If the user is investigating from an artifact, treat the artifact as the smallest pivot object and suggest the next most useful hop only when needed.

## SOP

### List Artifacts

1. Extract the narrowest useful filters from the request.
2. Call `list_artifacts`.
3. Parse the returned JSON strings.
4. Present a compact artifact view. If the user will likely attach or reuse the artifact next, surface the artifact row_id explicitly.

Preferred response structure:

| Artifact ID | Value | Type | Role | Owner | Reputation | Summary |
|-------------|-------|------|------|-------|------------|---------|

Then add one short explanation line when needed.

## Clarification Rules

- Ask for `artifact_id` only when the user wants to enrich an existing artifact and did not provide it.

## Output Rules

- Be concise.
- Do not output raw JSON unless the user explicitly asks for it.
- Prefer pivot-oriented wording over storage wording.
- When many artifacts match, show the most valuable subset and briefly explain the overall pattern.

## Failure Handling

- If no artifacts match, say so directly and suggest the most useful refinement.
- If the target artifact does not exist, say so directly.
