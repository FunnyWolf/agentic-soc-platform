---
name: asp-ticket
description: 'Manage ASP ticket sync records. Use when users ask to create synced tickets, attach tickets to cases, list tickets, or update synced ticket fields.'
argument-hint: 'list tickets [filters] | create ticket <uid> | attach ticket to case <case_id> | update ticket <ticket_id> <fields>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ ticket, case, sync, workflow ]
  documentation: https://asp.viperrtp.com/
---

# ASP Ticket

Use this skill for external ticket sync work on ASP.

## When to Use

- The user wants to create a synced external ticket record.
- The user wants to attach a ticket to a case.
- The user wants to list tickets by status, type, or external UID.
- The user wants to update synced ticket fields.

## Operating Rules

- Treat tickets as synced external workflow records, not as the platform's main investigation object.
- Do not ask the user to choose an operation if the request already implies one.
- Collect only missing required inputs.
- Use `create_ticket` to create the synced ticket record.
- Use `attach_ticket_to_case` to link an existing ticket record to a case.
- Use `list_tickets` for browsing and lookup.
- Use `update_ticket` only for fields the user explicitly wants changed.

## Decision Flow

1. If the user wants to create a synced ticket record, call `create_ticket`.
2. If the user wants to attach a ticket to a case, first create the ticket when needed, then call `attach_ticket_to_case`.
3. If the user wants to browse or compare synced tickets, call `list_tickets`.
4. If the user wants to revise synced ticket fields, call `update_ticket`.

## SOP

### List Tickets

1. Extract the narrowest useful filters from the request.
2. Call `list_tickets`.
3. Parse the returned JSON strings.
4. Present a compact workflow-oriented view.

Preferred response structure:

| Ticket ID | External UID | Type | Status | Title | Summary |
|-----------|--------------|------|--------|-------|---------|

Then add one short interpretation line when useful.

### Create Ticket

1. Collect the external ticket details the user wants to sync.
2. Call `create_ticket`.
3. Confirm the created ticket row ID.
4. If the ticket should be linked to a case, suggest attaching it next.

### Attach Ticket To Case

1. Require `case_id`.
2. If the user does not already have a ticket row ID, call `create_ticket` first.
3. Call `attach_ticket_to_case(case_id=<case_id>, ticket_rowid=<ticket_rowid>)`.
4. Confirm that the ticket is attached.

### Update Ticket

1. Require `ticket_id`.
2. Extract only the fields the user explicitly wants to change.
3. Call `update_ticket` with only changed fields.
4. If the result is `None`, state that the ticket was not found.
5. Confirm only the changed fields.

Preferred response structure:

- `Updated ticket`: ticket ID or returned row ID
- `Changed fields`: only the fields sent in the request
- `Next useful step`: optional, usually to attach it to a case or review the refreshed ticket

## Clarification Rules

- Ask for `case_id` only when the user wants case attachment and did not provide it.
- Ask for `ticket_id` only when the user wants to update a specific synced ticket and did not provide it.
- If the user wants to create a ticket and attach it in one request, do both steps without forcing them to separate the workflow.

## Output Rules

- Be concise.
- Do not dump raw JSON unless the user explicitly asks for it.
- Prefer workflow wording over storage wording.
- When many tickets match, show the best subset and explain the pattern briefly.

## Failure Handling

- If no tickets match, say that directly and suggest the most useful refinement.
- If the target case is missing, say that directly.
- If the target ticket is missing, say that directly.
- If the requested update is incomplete, ask one focused follow-up instead of guessing.
