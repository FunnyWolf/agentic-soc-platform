---
name: asp-case-get
description: Query security case details by case ID
argument-hint: "<case_id>"
allowed-tools: [ "*" ]
---

Query case details for: {{id}}

Use the MCP tool `get_case` with the provided parameters.

The tool returns an AI-friendly JSON string. Parse it before presenting the result.

If the tool returns `None`, clearly state that the case was not found.

Format the output with:

**Case Overview**

- Case ID
- Title
- Severity
- Status
- Description
- Confidence
- Priority
- Category
- Created/Updated timestamps

**Associated Alerts**

- Total count
- For each key alert, show title, severity, status, source UID, correlation UID, first seen time, and last seen time when available

**Associated Artifacts**

- Total count
- For each key artifact, show name, value, type, role, and reputation score when available

**Timeline**

- Created time
- Acknowledged time
- Closed time
- Start/end time if available

**AI Analysis**

- Analysis rationale
- Recommended actions
- Attack stage
- AI severity and AI confidence
- Threat hunting report

Present the information in a clear, structured format with appropriate sections.
