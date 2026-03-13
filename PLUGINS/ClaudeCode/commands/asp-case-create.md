---
name: asp-case-create
description: Create a new security case
argument-hint: "title=<title> severity=<severity> [description=<description>] [status=<status>]"
allowed-tools: [ "*" ]
---

Create a new security case with:

- Title: {{title}}
- Severity: {{severity}}
- Description: {{description}}
- Status: {{status}} (default: New)

**Valid values:**

- Severity: Informational, Low, Medium, High, Critical, Fatal, Unknown, Other
- Status: New, In Progress, On Hold, Resolved, Closed

Use the MCP tool `create_case` with the provided parameters.

The tool returns the created case row ID.

After successful creation, display:

**Case Created Successfully**

- Rowid: [database rowid]
- Title: [title]
- Severity: [severity]
- Status: [status]
- Description: [description]

If the user needs full case details, suggest querying the case separately after creation.
