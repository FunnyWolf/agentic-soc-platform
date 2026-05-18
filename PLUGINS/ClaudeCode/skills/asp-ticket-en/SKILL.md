---
name: asp-ticket-en
description: 'Sync external tickets into ASP, create tickets linked to cases, list synced tickets, or update existing ticket records.'
argument-hint: 'list tickets [filters] | create ticket <case_id> <uid> | update ticket <ticket_id> <fields>'
compatibility: connect to asp mcp server
metadata:
   author: Funnywolf
   version: 0.2.0
   mcp-server: asp
   category: cyber security
   tags: [ ticket, case, sync, workflow ]
   documentation: https://asp.viperrtp.com/
---

# ASP Ticket

Use this skill when the user needs to sync external tickets on ASP.

## When to Use

- The user wants to create a synced external ticket record linked to a case.
- The user wants to list synced tickets by status, type, or external UID.
- The user wants to update synced ticket fields.

## Operating Rules

- Treat tickets as synced external workflow records, not as the platform's main investigation object.
- Use `create_ticket` to create the synced ticket record and attach it to a case in one step.
- Use `list_tickets` for browsing and lookup.
- Use `update_ticket` only for fields the user explicitly wants changed.

## Decision Flow

1. If the user wants to create a synced ticket record linked to a case, call `create_ticket(case_id=..., uid=...)`.
2. If the user wants to browse or compare synced tickets, call `list_tickets`.
3. If the user wants to update synced ticket fields, call `update_ticket`.

## SOP

### List Tickets

1. Extract the narrowest useful filters from the request.
2. Call `list_tickets`.
3. Parse the returned JSON strings.
4. Present a compact workflow-oriented view, and surface the ticket row_id when the user will likely reuse the ticket next.

Preferred response structure:

| Ticket ID | External UID | Type | Status | Title | Summary |
|-----------|--------------|------|--------|-------|---------|

Then add one short explanation line when needed.

### Create Ticket

1. Require `case_id`.
2. Collect the external ticket details the user wants to sync.
3. Call `create_ticket(case_id=..., uid=..., ...)`.
4. Confirm the created ticket row_id and that it is attached to the case.

### Update Ticket

1. Require `ticket_id`.
2. Extract only the fields the user explicitly wants to change.
3. Call `update_ticket` with only the changed fields.
4. If the result is `None`, state that the ticket was not found.
5. Confirm only the changed fields.

Preferred response structure:

- `Updated ticket`: ticket ID or returned row_id
- `Changed fields`: only the fields sent in the request

## Clarification Rules

- Ask for `case_id` only when creating a ticket and it was not provided.
- Ask for `ticket_id` only when the user wants to update a specific synced ticket and did not provide it.

## Output Rules

- Be concise.
- Do not output raw JSON unless the user explicitly asks for it.
- Prefer workflow wording over storage wording.
- When many tickets match, show the best subset and explain the pattern briefly.

Tip: there is no direct `case_id` filter for `list_tickets`; use `list_cases(case_id=..., lazy_load=false)` to inspect attached tickets when needed.

## Failure Handling

- If no tickets match, say that directly and suggest the most useful refinement.
- If the target case does not exist, say that directly.
- If the target ticket does not exist, say that directly.
- If the requested update is incomplete, ask one focused follow-up instead of guessing.
