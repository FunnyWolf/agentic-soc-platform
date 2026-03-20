---
name: asp-siem
description: 'Investigate ASP SIEM data with schema exploration, keyword search, and adaptive field queries. Use when users ask to find the right index, inspect available fields, search logs by IOC, or run structured hunts with exact filters and aggregations.'
argument-hint: 'explore schema [index] | search <keyword> from <UTC start> to <UTC end> | adaptive query <index_name> <time range> [filters] [aggregations]'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.3.0
  mcp-server: asp
  category: cyber security
  tags: [ SIEM, search, SOC, hunting, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP SIEM

Use this skill for SIEM investigation on ASP. This skill should guide search strategy and evidence collection.

## When to Use

- The user wants to discover which indices or fields exist before searching.
- The user wants to search logs by IP, user, host, hash, domain, process, email, or arbitrary keyword.
- The user wants to pivot from an alert, artifact, or case into SIEM evidence.
- The user wants exact-match filtering and top-N statistics instead of free-text search.
- The user wants to narrow a noisy search or expand an empty one.
- The user wants complete raw evidence, not only a high-level count.

## Operating Rules

- Do not ask the user to choose an operation when the request already implies a SIEM search.
- Collect only missing essentials for the chosen path.
- Treat this as an investigation workflow, not a one-shot query helper.
- Use `siem_explore_schema` when the user does not know the right index or fields.
- Use `siem_keyword_search` when the user has one or more strong keywords and needs matching events.
- Use `siem_adaptive_query` when the user already knows the target index and wants exact field filters or statistics.
- If the user gives a relative time window, call `get_current_time` first and derive a workable UTC range from the returned local time with timezone.
- Optimize for useful evidence, not maximum raw output.

## Decision Flow

1. If the user asks which index to use, which fields exist, or how the SIEM source is structured, use `siem_explore_schema`.
2. If the user already provides keyword and time range, use `siem_keyword_search` immediately.
3. If the user gives a relative time window, call `get_current_time`, derive a workable UTC range from the returned local time with timezone, then continue.
4. If the user gives only an IOC or keyword, ask for the narrowest workable UTC time range.
5. If the user wants exact field filters, grouped statistics, or controlled aggregations, use `siem_adaptive_query`.
6. If the user knows the data source, pass `index_name`; otherwise search broadly first or explore schema.
7. If the source likely uses a non-default time field, ask for it; otherwise use `@timestamp`.
8. After each search, decide whether to stop, narrow, expand, or write the useful result back as enrichment.

## SOP

### Explore Schema

1. If the user does not know the target source, call `siem_explore_schema()` first.
2. If the user already knows the index and wants field structure, call `siem_explore_schema(target_index=<index>)`.
3. Parse the returned JSON.
4. Summarize the most relevant indices, time field candidates, and high-signal fields for the investigation goal.
5. Recommend the next query path: keyword search or adaptive query.

### Start the Search

1. Extract the strongest known keyword first.
2. Normalize multiple keywords into an AND set only when the user truly means all conditions must match.
3. Require UTC timestamps ending in `Z`.
4. Call `siem_keyword_search`.
5. Parse each returned JSON string.

### Run A Structured Hunt

1. Require `index_name`, UTC time range, and at least one exact filter or explicit aggregation goal.
2. Normalize filters into exact field/value pairs.
3. Add `aggregation_fields` only when the user wants prevalence, top-N statistics, or grouped scoping.
4. Call `siem_adaptive_query`.
5. Summarize both the filtered scope and any aggregation output in analyst language.

### Refine The Search

Preferred refinement actions:

1. Narrow time range before adding many new keywords.
2. Add one or two high-signal keywords instead of many weak ones.
3. Remove one restrictive keyword if the query is empty.
4. Add `index_name` when broad search returns too much irrelevant data.
5. Switch to `siem_adaptive_query` when the user has learned enough field structure to stop using keyword search.
6. Keep iterating until the result quality matches the user's goal.

### Investigation Patterns

Use these patterns when helpful:

- `IOC pivot`: start with one IOC, then add host, user, process, or action from returned records.
- `Alert follow-up`: search with the alert artifact plus the alert time window, then tighten around first and last seen.
- `User activity check`: start with username plus narrow time range, then pivot to source IP, host, and action.
- `Infrastructure pivot`: start with IP or hostname, then pivot to related users, processes, and destinations.

### Stop Conditions

Stop refining when one of these is true:

- The user asked only for scope, trend, or prevalence.
- Further refinement would likely remove relevant evidence.
- Repeated refinement still returns no useful data.
- The user already has the right index and exact field constraints, in which case the next step is an adaptive query rather than another keyword search.

## Response Strategy

Always explain what the search means, not only what it returned.

Preferred response structure:

### Search Overview

- search mode: schema exploration, keyword search, or adaptive query
- keyword set or exact filters
- time range
- searched index or `all`
- aggregation fields if used
- number of result groups
- overall interpretation in one or two lines

### Result Groups

| Backend | Status | Total Hits | Index Distribution | Meaning |
|---------|--------|------------|--------------------|---------|

### Evidence Highlights

- Key field statistics that matter to the investigation.
- Representative records only when they add value.
- Important pivots: user, host, IP, process, event, action, destination, or other relevant fields.
- For schema exploration, highlight only the indices and fields that matter to the hunt.

### Next Best Step

- Narrow time range
- Add one stronger keyword
- Remove one restrictive keyword
- Search a specific index
- Switch to adaptive query with exact filters
- Save the useful SIEM result as enrichment on the relevant case, alert, or artifact
- Stop because evidence is already sufficient

## Clarification Rules

- Ask for time range if missing.
- Ask for timezone only if the user did not provide UTC and the intended timezone is unclear.
- Ask for `index_name` only when broad search is likely wasteful, the user already hints at a known source, or adaptive query is the right tool.
- Ask for exact field names only when the user wants adaptive query and the schema is still unclear.
- If the user says "look around this event", derive a reasonable first search from the available IOC and timeframe rather than asking them to design the query.

## Output Rules

- Be concise.
- Do not dump every returned record by default.
- Prefer the most relevant records and statistics.
- Group results by backend and index when multiple groups are returned.
- For schema exploration, present a shortlist rather than a raw field inventory.
- If no data is found, say that directly and suggest the most likely useful adjustment.

## Failure Handling

- Invalid time format: ask for UTC ISO8601 with trailing `Z`.
- Empty results: expand time range or remove one keyword.
- Too many hits: narrow time range first, then add signal.
- Unknown index or field choice: use `siem_explore_schema` before guessing.
- Backend or source issue: state which backend or index failed if the result indicates it.
