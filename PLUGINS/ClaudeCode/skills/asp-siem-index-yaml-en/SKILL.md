---
name: asp-siem-index-yaml-en
description: 'Create or update SIEM index configuration YAML. Use when the user wants to generate field configs for a SIEM index, refresh an existing index YAML, or sync live backend fields into a config file.'
argument-hint: '<index_name> <backend>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ SIEM, index, yaml, schema, configuration ]
  documentation: https://asp.viperrtp.com/
---

# ASP SIEM Index YAML

Use this skill when the user wants to create or update a SIEM index configuration YAML, guiding the full workflow from field discovery to writing the config file.

## When to Use

- User wants to generate an index configuration YAML for a SIEM index.
- User wants to update an existing index YAML with live backend fields.
- User wants to see what fields actually exist in an ELK or Splunk index.

## Rules

- Config files are stored at `DATA/Plugin_SIEM_Indexes/<index_name>.yaml`.
- Must call `siem_discover_index_fields` to fetch live fields from the backend — never skip this and write fields manually.
- `name`, `type`, and `sample_values` are taken directly from discovery results. `sample_values` must preserve native types — do not cast everything to strings.
- `description` and `is_key_field` are inferred by the model based on field semantics and sample_values, marked as pending confirmation.
- Do not overwrite an existing YAML before the user confirms.

## Decision Flow

1. If `index_name` or `backend` is missing, ask the user first.
2. If `DATA/Plugin_SIEM_Indexes/<index_name>.yaml` already exists, read it as a baseline for comparison.
3. Call `siem_discover_index_fields` to get live fields.
4. Generate a draft and present it for user review.
5. Write the file only after user confirmation.

## SOP

### Step 1 — Gather Input

Ask the user for:
- `index_name`: the SIEM index name.
- `backend`: `ELK` or `Splunk`.

### Step 2 — Check Existing Config

Check whether `DATA/Plugin_SIEM_Indexes/<index_name>.yaml` already exists.
- If it exists, read it as a baseline and show diffs later.
- If not, mark as new creation.

### Step 3 — Discover Fields

Call `siem_discover_index_fields(index_name=<index_name>, backend=<backend>)`.

The response contains for each field:
- `name`: field name (nested fields use dot-path notation)
- `type`: field type as reported by the backend
- `sample_values`: top-5 high-frequency values (native types preserved)

### Step 4 — Generate Draft

Populate the full config for each field:

| Field | Source |
|-------|--------|
| `name` | Taken directly |
| `type` | Taken directly |
| `sample_values` | Taken directly |
| `description` | Generated from field name semantics, enriched with sample_values range |
| `is_key_field` | Heuristic based on investigation value: identity, asset, network tuple, action, outcome, high-signal identifier → `true`; noise or low-value fields → `false` |

### Step 5 — Present Draft

Show the user a diff summary and the full draft.

Preferred reply structure:

**Draft Summary**

- Target index: `<index_name>`
- Backend: `<backend>`
- Total fields: `<n>`
- New fields: `<list>` (compared to baseline, if any)
- Type changes: `<list>` (compared to baseline, if any)
- Fields with `is_key_field=true`

**Pending Confirmation**

- Whether `is_key_field` inferences are reasonable
- Whether `description` values match naming conventions
- Whether any fields need adjustment

### Step 6 — Write File

After user confirmation, write the full YAML to `DATA/Plugin_SIEM_Indexes/<index_name>.yaml`.

Top-level YAML structure:

```yaml
name: <index_name>
backend: <backend>
description: <index description>

fields:
  - name: <field_name>
    type: <field_type>
    description: <field_description>
    is_key_field: <true|false>
    sample_values: [<value1>, <value2>, ...]
```

## Clarification Rules

- Only ask for `index_name` or `backend` when missing.
- If `siem_discover_index_fields` returns an empty field list, the index name may be wrong or the backend has no data — ask the user to verify.
- If the user disagrees with `is_key_field` or `description` for certain fields, adjust per their request and re-present.

## Output Rules

- When presenting the draft, prefer a diff summary + key field list over dumping the full YAML.
- Only produce the full YAML file content when the user confirms the write.
- Keep it concise — do not re-explain each field's meaning.

## Failure Handling

- If `siem_discover_index_fields` fails, report the error and ask the user to check the index name and backend connectivity.
- If the returned field count is 0, prompt the user to verify the index exists and contains data.
- If the user requests a write without having reviewed the draft, remind them to complete the review step first.
