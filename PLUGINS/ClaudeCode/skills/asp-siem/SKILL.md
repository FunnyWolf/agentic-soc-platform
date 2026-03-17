---
name: asp-siem
description: 'Investigate ASP SIEM data with keyword search. Use when users ask to search logs, pivot on IOC values, check activity in a time range, hunt related events, or refine SIEM evidence across ELK or Splunk.'
argument-hint: 'search <keyword> from <UTC start> to <UTC end> [index_name] [time_field]'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.2.0
  mcp-server: asp
  category: cyber security
  tags: [ SIEM, search, SOC, hunting, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP SIEM

Use this skill for SIEM investigation on ASP. This skill should guide search strategy and evidence collection.

## When to Use

- The user wants to search logs by IP, user, host, hash, domain, process, email, or arbitrary keyword.
- The user wants to pivot from an alert, artifact, or case into SIEM evidence.
- The user wants to narrow a noisy search or expand an empty one.
- The user wants complete raw evidence, not only a high-level count.

## Operating Rules

- Do not ask the user to choose an operation when the request already implies a SIEM search.
- Collect only missing essentials: keyword and UTC time range.
- Treat this as an investigation workflow, not a one-shot query helper.
- Use the result `status` to decide whether to refine, expand, or stop.
- Optimize for useful evidence, not maximum raw output.
- Prefer `full` when the user needs exact logs or evidence preservation.
- If the user only needs scoping, `summary` or `sample` may be enough.

## Decision Flow

1. If the user already provides keyword and time range, search immediately.
2. If the user gives only an IOC or keyword, ask for the narrowest workable UTC time range.
3. If the user knows the data source, pass `index_name`; otherwise search broadly.
4. If the source likely uses a non-default time field, ask for it; otherwise use `@timestamp`.
5. After each search, decide whether to stop, narrow, or expand based on `status`, hit volume, and user goal.

## SOP

### Start the Search

1. Extract the strongest known keyword first.
2. Normalize multiple keywords into an AND set only when the user truly means all conditions must match.
3. Require UTC timestamps ending in `Z`.
4. Call `siem_keyword_search`.
5. Parse each returned JSON string.

### Refine the Search

Use the returned `status` as the control signal:

- `full`: stop if the user asked for concrete evidence or raw logs.
- `sample`: inspect records and statistics, then narrow if exact logs are still needed.
- `summary`: narrow aggressively by time range, source, or added keywords.

Preferred refinement actions:

1. Narrow time range before adding many new keywords.
2. Add one or two high-signal keywords instead of many weak ones.
3. Remove one restrictive keyword if the query is empty.
4. Add `index_name` when broad search returns too much irrelevant data.
5. Keep iterating until the result quality matches the user's goal.

### Investigation Patterns

Use these patterns when helpful:

- `IOC pivot`: start with one IOC, then add host, user, process, or action from returned records.
- `Alert follow-up`: search with the alert artifact plus the alert time window, then tighten around first and last seen.
- `User activity check`: start with username plus narrow time range, then pivot to source IP, host, and action.
- `Infrastructure pivot`: start with IP or hostname, then pivot to related users, processes, and destinations.

### Stop Conditions

Stop refining when one of these is true:

- The result is `full` and satisfies the request.
- The user asked only for scope, trend, or prevalence.
- Further refinement would likely remove relevant evidence.
- Repeated refinement still returns no useful data.

## Response Strategy

Always explain what the search means, not only what it returned.

Preferred response structure:

### Search Overview

- keyword set
- time range
- searched index or `all`
- number of result groups
- overall interpretation in one or two lines

### Result Groups

| Backend | Status | Total Hits | Index Distribution | Meaning |
|---------|--------|------------|--------------------|---------|

### Evidence Highlights

- Key field statistics that matter to the investigation.
- Representative records only when they add value.
- Important pivots: user, host, IP, process, event, action, destination, or other relevant fields.

### Next Best Step

- Narrow time range
- Add one stronger keyword
- Remove one restrictive keyword
- Search a specific index
- Stop because evidence is already sufficient

## Clarification Rules

- Ask for time range if missing.
- Ask for timezone only if the user did not provide UTC and the intended timezone is unclear.
- Ask for `index_name` only when broad search is likely wasteful or the user already hints at a known source.
- If the user says "look around this event", derive a reasonable first search from the available IOC and timeframe rather than asking them to design the query.

## Output Rules

- Be concise.
- Do not dump every returned record by default.
- Prefer the most relevant records and statistics.
- Group results by backend and index when multiple groups are returned.
- Explicitly state when the result is partial (`summary` or `sample`).
- If no data is found, say that directly and suggest the most likely useful adjustment.

## Failure Handling

- Invalid time format: ask for UTC ISO8601 with trailing `Z`.
- Empty results: expand time range or remove one keyword.
- Too many hits: narrow time range first, then add signal.
- Backend or source issue: state which backend or index failed if the result indicates it.
