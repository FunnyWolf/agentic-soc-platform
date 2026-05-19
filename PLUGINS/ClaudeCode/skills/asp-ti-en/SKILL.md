---
name: asp-ti-en
description: 'Query threat intelligence for IOCs (IP, hash, URL, domain). Use when users want to check an indicator against TI providers, assess risk level, or gather threat context.'
argument-hint: 'query ti <indicator> | query ti <indicator> from <provider>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ threat-intelligence, IOC, enrichment, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Threat Intelligence

Use this skill when the user needs to look up an indicator against threat intelligence providers. Supports IP addresses, file hashes, URLs, and domains.

## When to Use

- The user wants to check if an IP, hash, URL, or domain is malicious.
- The user wants risk assessment or reputation data for an indicator.
- The user wants to gather threat context (tags, attack techniques, malware families) for an IOC.
- The user wants to enrich an artifact or investigation with external threat intelligence.

## Operating Rules

- Use `ti_query` to query one or all registered TI providers.
- If `provider` is omitted, the tool queries all providers and aggregates the results.
- If the user wants a specific provider, pass the provider name (e.g. `"AlienVaultOTX"`).
- When enriching existing case artifacts, combine this skill with `asp-enrichment-en` to save results.

## Additional Information

- Available providers can be listed by calling `ti_query` and checking the response.
- Currently registered: AlienVaultOTX. More providers can be added as needed.
- `aggregated_risk_level` in the response is the highest risk across all providers: high > medium > low.

## Decision Flow

1. If the user gives an indicator (IP, hash, URL, domain), call `ti_query` directly.
2. If the user specifies a provider name, pass it as the `provider` parameter.
3. If the user wants to save the result, use `asp-enrichment-en` to persist as enrichment.

## SOP

### Query Threat Intelligence

1. Extract the indicator from the user's request.
2. Determine if the user wants a specific provider or all providers.
3. Call `ti_query(indicator=<value>, provider=<name or None>)`.
4. Parse the response and present the findings.

Preferred response structure:

**Indicator Overview**
- Indicator value and detected type
- Provider(s) queried
- Aggregated risk level

**Threat Findings**
- Risk level per provider
- Reputation score
- Tags, attack techniques, malware families, adversaries (if any)
- Network context (ASN, country, etc.) for IP indicators

**Assessment**
- One-line verdict: malicious / suspicious / clean / unknown
- Recommended next steps if relevant

## Clarification Rules

- Ask for the indicator value if it is missing or ambiguous.
- If the user says "check this IP" but provides a hash, confirm the indicator type.
- Do not ask which provider to use unless the user specifically wants a provider choice.

## Output Rules

- Be concise. Lead with the risk level and verdict.
- Do not dump raw JSON unless the user asks for it.
- Highlight only the fields that matter: risk_level, tags, attack_techniques, malware_families.
- If the indicator is clean, say so briefly. Do not over-explain a negative result.
- If multiple providers return results, summarize the consensus and note any disagreement.

## Failure Handling

- If the provider returns an error, report the error and suggest checking API configuration.
- If the indicator format is invalid, explain the expected format for the type.
- If no providers are available, report that directly.
