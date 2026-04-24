---
name: asp-siem-search-en
description: 'Investigate ASP SIEM data with schema exploration, keyword search, and adaptive queries. Use when users want to find the right index, inspect available fields, search logs by IOC, or run structured hunts with exact filters and aggregations.'
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

Use this skill when the user needs SIEM investigation on ASP. The focus is on choosing the right query path and returning evidence that is useful for analysis.

## When to Use

- The user wants to confirm which indices, fields, or data sources are available.
- The user wants to search for related logs using IOC, alert context, or keywords.
- The user wants to do further filtering, statistics, or structured analysis within a known scope.
- The user wants to pivot into SIEM evidence from an alert, artifact, or case.

## Operating Rules

- If the request already implies SIEM search, do not ask which operation to choose.
- Collect only the minimum missing inputs for the selected path.
- When the user does not know the correct index or field, use `siem_explore_schema`.
- `siem_keyword_search` is suitable for keyword-driven search, both broad exploration and fast lookup within a known index.
- `siem_adaptive_query` is suitable for exact field filtering, controlled aggregation, and stable reproduction. It is closer to a structured SIEM API.
- If the user gives a relative time window, call `get_current_time` first and derive a usable UTC range from the returned local time with timezone.
- Optimize for useful evidence, not for maximum raw output.

## Function Notes

### `siem_keyword_search`

Use when:

- The user has an IP, domain, username, hostname, hash, process name, email address, error text, or other keywords and wants to check for related logs.
- The user is not sure which index the logs live in and wants to start with a broader or global search.
- The user wants to iterate like a SIEM search interface, adjusting keywords and time range to observe result distribution.
- The user already knows the index but only needs a fast keyword search rather than exact field filtering.

How to use it:

- Required parameters are `keyword`, `time_range_start`, and `time_range_end`.
- `keyword` can be a string or a list of strings; when a list is used, it means AND matching.
- `index_name` is optional. If omitted, search globally. If provided, search only within that source or index.
- `time_field` defaults to `@timestamp`. Change it only when the source is known to use another time field.

What it is good for:

- It returns the event set that matches the search, which is useful for checking whether something hit, where it hit, whether the time distribution is concentrated, and whether new suspicious keywords or fields appear.
- It can be the starting point of an investigation or a fast secondary search during an investigation.
- It does not require the exact field names up front, so it is better for fuzzy search and exploration.

### `siem_adaptive_query`

Use when:

- The user already knows or has mostly confirmed the target `index_name`.
- The user already has clear filters, such as exact field matches or a few precise conditions.
- The user wants top-N output, group statistics, field aggregation, or controlled scope queries.
- The user needs a stable, reproducible, structured query instead of more free-form keyword search.

How to use it:

- Required parameters are `index_name`, `time_range_start`, and `time_range_end`.
- `filters` are exact field filters; keys are field names and values can be a single string or a list of strings.
- `aggregation_fields` is optional. Add it only when the user explicitly wants statistics or grouping.
- `time_field` defaults to `@timestamp`. Change it only when the target source uses another field.

What it is good for:

- It returns structured query results and is better for stable verification, field statistics, and evidence that supports a conclusion.
- It is more like a SIEM API for the model. It does not have to come from `siem_keyword_search`, but it usually needs clearer context.
- When the user has already given the index, time range, and general conditions, use it directly rather than forcing keyword search first.

### How To Choose

- If the clue is mainly a keyword, prefer `siem_keyword_search`.
- If the clue is mainly a known index plus known field conditions, prefer `siem_adaptive_query`.
- If the goal is to find events, see the distribution, and gather clues, prefer `siem_keyword_search`.
- If the goal is exact filtering, aggregation, or stable reproduction, prefer `siem_adaptive_query`.
- If the user does not name fields and the index is unclear, do not force `siem_adaptive_query`.
- If the user already gives a clear index and filters, do not mechanically start with `siem_keyword_search`.

## Decision Flow

1. If the user asks which index to use, which fields exist, or how the SIEM source is organized, use `siem_explore_schema`.
2. If the user gives a relative time window, call `get_current_time`, derive a usable UTC range from the returned local time with timezone, and continue.

## SOP

### Explore Schema

1. If the user does not know the target source, call `siem_explore_schema()` first.
2. If the user already knows the index and wants field structure, call `siem_explore_schema(target_index=<index>)`.
3. Parse the returned JSON.
4. Summarize the indices, time field candidates, and high-signal fields most relevant to the investigation goal.
5. Recommend the next query path: keyword search or adaptive query.

### Use `siem_keyword_search`

1. Start with the strongest known keyword.
2. Normalize multiple keywords into an AND set only when the user truly means all conditions must match.
3. Require UTC timestamps ending in `Z`.
4. If the user did not specify `index_name`, you may start globally; if the user has a known source, you can restrict to that index.
5. Call `siem_keyword_search`.
6. Parse each returned JSON string, and choose output emphasis based on the user's goal:
   - If the user is looking for events, show representative hits first.
   - If the user is checking where the logs landed, focus on backend, index distribution, and time distribution.
   - If the user is narrowing further, summarize which keywords should be added or removed next.
7. Decide the next round based on the results:
   - If there are too many hits, narrow the time range first, then add one or two high-signal keywords.
   - If there are too few hits or none, remove one restrictive keyword or expand the time range moderately.
   - If hits are concentrated in a few indices, specify `index_name` next time.
   - When the results already explain the log location and key fields, switch to `siem_adaptive_query`.

### Use `siem_adaptive_query`

1. Require `index_name`, a UTC time range, and at least one exact filter or a clear aggregation goal.
2. Normalize filters into exact field/value pairs.
3. Add `aggregation_fields` only when the user wants prevalence, top-N statistics, or grouped scoping.
4. Call `siem_adaptive_query`.
5. Summarize the filtered scope, hit count, and any aggregation output in analyst language.
6. If the result is not useful, first decide whether the filters are too strict, the field name is wrong, the time range is wrong, or the user should return to `siem_keyword_search` for more context.

### Refine Search

Preferred refinement actions:

1. Narrow the time range before adding many new keywords.
2. Add one or two high-signal keywords instead of many weak ones.
3. Remove one restrictive keyword if the query returns no results.
4. Add `index_name` when broad search returns too much irrelevant data.
5. Switch to `siem_adaptive_query` when the user has learned enough field structure to stop using keyword search.
6. Keep iterating until the result quality matches the user's goal.

## Response Strategy

Always explain what the search means, not just what it returned.

Preferred response structure:

### Search Overview

- Search mode: schema exploration, keyword search, or adaptive query
- Keyword set or exact filters
- Time range
- Searched index or `all`
- Aggregation fields if used
- Overall explanation in one or two lines describing whether this is exploration, narrowing, or validation

### Evidence Highlights

- Key field statistics that matter to the investigation.
- Representative records only when they add value.
- For schema exploration, only highlight the indices and fields that matter to the hunt.
- For keyword search, explain that the result is a keyword match set that can be used for follow-up search, distribution review, clue gathering, or source location.
- For adaptive query, explain that the result is a structured filter or aggregation result that supports validation, statistics, and stable reproduction.

### Next Best Step

- Narrow the time range
- Add one stronger keyword
- Remove one restrictive keyword
- Search a specific index
- Switch to adaptive query with exact filters
- Save the useful SIEM result as enrichment on the relevant case, alert, or artifact
- Stop because the evidence is already sufficient

## Clarification Rules

- Ask for the time range if it is missing.
- Ask for timezone only if the user did not provide UTC and the intended timezone is unclear.
- Ask for `index_name` only when broad search is likely wasteful, the user already hints at a known source, or adaptive query is the right tool.
- Ask for exact field names only when the user wants adaptive query and the schema is still unclear.
- If the user says "look around this event", derive a reasonable first search from the available IOC and time window instead of asking them to design the query.

## Output Rules

- Be concise.
- Do not dump every returned record by default.
- Prefer the most relevant records and statistics.
- Group results by backend and index when multiple groups are returned.
- For schema exploration, present a shortlist rather than a raw field inventory.
- For keyword search, prefer output that helps guide the next search step instead of mechanically listing logs.
- For adaptive query, prefer output that supports the conclusion through filters and aggregation results.
- If no data is found, say that directly and suggest the most useful adjustment.

## Failure Handling

- Invalid time format: ask for UTC ISO8601 with trailing `Z`.
- Empty results: widen the time range or remove one keyword.
- Too many hits: narrow the time range first, then add signal.
- Unknown index or field choice: use `siem_explore_schema` before guessing.
- Backend or source issue: state which backend or index failed if the result indicates it.
