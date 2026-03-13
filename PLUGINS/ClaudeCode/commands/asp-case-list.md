---
name: asp-case-list
description: List security cases with optional filters
argument-hint: "[status=<status1,status2,...>] [severity=<severity1,severity2,...>] [limit=<number>]"
allowed-tools: [ "*" ]
---

List cases with the following filters:

- Status: {{status}}
- Severity: {{severity}}
- Limit: {{limit}}

Use the MCP tool `list_cases` with the provided parameters.

The `status` and `severity` filters support lists. If multiple values are provided, pass them as arrays to the MCP tool.

**Valid filter values:**

- Status: New, In Progress, On Hold, Resolved, Closed
- Severity: Informational, Low, Medium, High, Critical, Fatal, Unknown, Other
- Limit: Any positive integer (default: 10)

The tool returns a list of AI-friendly JSON strings. Parse each item before rendering.

Display results in a table format and include as many useful fields as are available:

| Case ID | Title | Severity | Status | Priority | Confidence | Category | Correlation UID | Created | Updated |
|---------|-------|----------|--------|----------|------------|----------|-----------------|---------|---------|
| ...     | ...   | ...      | ...    | ...      | ...        | ...      | ...             | ...     | ...     |

After the table, only provide the total count of cases returned.

If no filters are provided, list recent cases with default limit of 10.
