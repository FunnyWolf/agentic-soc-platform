---
name: asp-case-update
description: Update an existing security case
argument-hint: "<case_id> [title=<title>] [severity=<severity>] [status=<status>] [description=<description>]"
allowed-tools: [ "*" ]
---

Update case {{case_id}} with the following changes:

- Title: {{title}}
- Severity: {{severity}}
- Status: {{status}}
- Description: {{description}}

**Valid values:**

- Severity: Informational, Low, Medium, High, Critical, Fatal, Unknown, Other
- Status: New, In Progress, On Hold, Resolved, Closed

Use the MCP tool `update_case` with the case ID and any provided update fields.

The tool returns the updated case row ID, or `None` if the case does not exist.

If the tool returns `None`, clearly state that the case was not found.

After successful update, display:

**Case Updated Successfully**

Show the fields that were requested to change, then display:

- Rowid
- Case ID
- Title
- Severity
- Status
- Description

If full updated details are needed, call `get_case` after the update and present the latest case data.
