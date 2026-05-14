---
name: asp-module-creator-en
description: 'Create an ASP alert processing module. Use when the user wants to create an ASP module for a SIEM rule, write an alert processing script, or add a new Python module under the MODULES directory.'
argument-hint: '<rule-name>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ module, siem, alert-processing, development ]
  documentation: https://asp.viperrtp.com/
---

# ASP Module Creator

Use this skill to guide the user through the full workflow — from requirement confirmation to code generation — when creating an ASP alert processing module for a SIEM rule.

## When to Use

- The user wants to create an ASP processing module for a SIEM rule.
- The user wants to add a new Python alert processing script under `MODULES/`.
- The user wants to integrate a SIEM alert into the ASP Alert/Case management pipeline.

## Operating Rules

- The module filename must exactly match the SIEM rule name (case-sensitive) — Rule name = Redis Stream name = filename. This is a hard constraint; any mismatch will prevent the framework from routing alerts to the module.
- A raw_alert sample must be obtained before writing any code. Never guess field structure.
- Before writing code, read `PLUGINS/SIRP/sirpcoremodel.py`; enum values must come only from the actual definitions in that file, never from memory or inference.
- All modules must inherit `BaseModule` and implement the `run()` method.
- SIRP data hierarchy: `Case → Alert → Artifact` (three-tier). Artifact is the smallest atomic investigation entity (an IP, a username); Alerts are attached to Cases; related alerts are aggregated into the same Case via `correlation_uid`. Enrichment is a cross-cutting attachment layer independent of the three-tier hierarchy — it can be attached to any level (Case / Alert / Artifact).
- Reference implementation: `MODULES/Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy.py`.
- Data model reference: `PLUGINS/SIRP/sirpcoremodel.py`.

## Decision Flow

1. If the user has not provided a rule name, ask first.
2. If no raw_alert sample has been obtained, try the three methods in priority order (see SOP Step 3).
3. Analyse the field structure from the sample before writing code.
4. After generating the code, prompt the user to add the debug entry point and verify.

## SOP

### Step 1 — Get the Rule Name

Ask the user for the full SIEM Rule name, e.g. `XXX-01-YYY-ZZZ1-ZZZ2-ZZZ3`.
- The module file will be named `MODULES/XXX-01-YYY-ZZZ1-ZZZ2-ZZZ3.py`.
- Alerts will be consumed from the Redis Stream named `XXX-01-YYY-ZZZ1-ZZZ2-ZZZ3`.

### Step 2 — Confirm Prerequisites

Prompt the user to confirm all three of the following are ready:
1. A rule named `<rule-name>` exists in the SIEM.
2. The rule has already produced alerts.
3. Alerts have been forwarded to Redis Stream `<rule-name>` by the forwarding tool.

### Step 3 — Obtain a raw_alert Sample

Try the following methods in priority order; proceed as soon as one succeeds:

**Method A (recommended, requires ASP MCP connection):**
Call `ASP:read_stream_head(stream_name="<rule-name>")` to read the first few alerts from the stream.
Or call `ASP:read_stream_message_by_id(stream_name="<rule-name>", message_id=<id>)` to read a specific message.

**Method B (offline development):**
Ask the user to copy one or more raw_alert JSON samples to `DATA/MODULES/<rule-name>/raw_alert_*.json`, then read the file.

**Method C (direct paste):**
Ask the user to open Redis Insight, select the `<rule-name>` stream, copy a message's JSON content, and paste it into the conversation.

### Step 4 — Analyse the raw_alert Structure

Read the sample and identify:
- Event time field (e.g. `@timestamp`, `eventTime`)
- Principal identity fields (username, ARN, account ID, AccessKey, etc.)
- Target fields (target user, target resource, etc.)
- Network fields (source IP, User-Agent, etc.)
- Outcome fields (errorCode, outcome, status, etc.)
- Risk scoring fields (e.g. `event.risk_score`, `log.level`)
- Any other fields with investigation value

Before determining `correlation_uid`, first identify what kind of SOC scenario the rule describes. Different alert types require different aggregation logic. Do not mechanically reuse fixed fields or a fixed time window.

**Aggregation design goals:**
- One Case should represent one investigable, actionable security event or attack activity, not one log line and not an overly broad asset bucket.
- Prefer aggregation keys that are stable invariants of the attack activity. Avoid fields that vary by victim, session, request, or timestamp.
- Match the aggregation window to the response cadence: too short splits one activity and repeats notifications; too long delays response to a new wave.

**Think through aggregation keys in this order:**
1. Attacker dimension: source IP, sender, external account, malicious domain, malicious file hash, C2 domain, etc.
2. Target/victim dimension: target user, target host, target resource. Include these only when "same attacker against same target" is what defines one event.
3. Behaviour/payload dimension: email subject, URL domain, file hash, command-line signature, API name, rule subtype, etc. Include only when the field is stable and separates activities.
4. Environment dimension: cloud account, tenant, business system, region, etc. These are usually auxiliary keys and should not be the only aggregation key.

**Avoid using these as aggregation keys:**
- Random or high-cardinality fields: message_id, request_id, session_id, trace_id, uuid, exact timestamp.
- Victim fields when the scenario is broad delivery/scanning/brute force from the same attacker. Do not add every recipient/user/host to the key, or one campaign will fragment into many Cases.
- Overly broad fields: account_id, tenant_id, or rule_name alone will merge unrelated alerts.

**Common scenario guidance:**
- User-reported phishing mail: prefer sender/sender domain. If the email title does not contain random values such as recipient names, timestamps, or order numbers, include a normalized title. Usually do not include recipient. Recommended window: `12h`, which keeps one phishing wave together without delaying notifications and response too much.
- Same malicious URL/domain delivery: use URL domain or normalized URL + sender domain. If the URL contains one-time tokens, use only the domain or stable path.
- Malicious process/command on endpoint: use host + stable process/command signature. If it looks like lateral movement or a hash-wide outbreak, aggregate by file hash/command signature and do not necessarily include host.
- Cloud IAM abnormal operation: usually use cloud account/tenant + principal identity + API/target resource. If investigating one broad attack wave, aggregate by principal identity or source IP and keep target resources as supporting context.
- C2 communication: use C2 IP/domain + internal host. If one C2 affects many hosts, aggregate by C2 first and keep affected hosts in the Case.

**Time-window guidance:**
- User-reporting/notification-driven alerts: `6h`-`12h`, commonly `12h`.
- High-frequency scanning, brute force, C2 beaconing: `15m`-`2h`, adjusted by detection frequency and response need.
- Cloud permission changes, account anomalies, low-frequency high-risk operations: `4h`-`24h`.
- When using a window, explain the reason after generating the code.

If the aggregation key is unclear, propose candidate keys based on raw_alert and alert semantics, then ask the user to confirm. Do not default to `24h` or include every principal/target field without explaining why.

### Step 5 — Write the Module Code

**Prerequisite action:** read `PLUGINS/SIRP/sirpcoremodel.py` and confirm all enum values that will be used before writing code.

Generate `MODULES/<rule-name>.py` using the following structure:

```python
import json
from typing import List

from dateutil import parser

from Lib.basemodule import BaseModule
from PLUGINS.SIRP.correlation import Correlation
from PLUGINS.SIRP.sirpapi import Alert, Case
from PLUGINS.SIRP.sirpcoremodel import (
    ArtifactType, ArtifactRole, Severity, Impact, Disposition, AlertAction,
    Confidence, AlertAnalyticType, ProductCategory, AlertPolicyType,
    AlertRiskLevel, AlertStatus, CasePriority,
    ArtifactModel, AlertModel, CaseModel, EnrichmentModel
)


class Module(BaseModule):
    def __init__(self):
        super().__init__()

    def run(self):
        # 1. Read raw alert
        raw_alert = self.read_stream_message()

        # 2. Field extraction (customise based on raw_alert structure)
        # ...

        # 3. Artifact extraction
        artifacts: List[ArtifactModel] = []
        # artifacts.append(ArtifactModel(type=..., role=..., value=..., name=...))

        # 4. Compute correlation_uid
        # Choose keys and time window based on alert semantics; do not reuse fixed fields mechanically.
        correlation_uid = Correlation.generate_correlation_uid(
            rule_id=self.module_name,
            time_window=...,  # e.g. user-reported phishing mail can use "12h"
            keys=[...],  # stable attack-activity invariants; avoid random request/session IDs
            timestamp=event_time_formatted
        )

        # 5. Assemble AlertModel
        alert_model = AlertModel(
            title=...,
            severity=...,
            status=AlertStatus.NEW,
            disposition=...,
            action=...,
            rule_id=self.module_name,
            rule_name=...,
            correlation_uid=correlation_uid,
            raw_data=json.dumps(raw_alert),
            unmapped=json.dumps({...}),
            # other fields...
        )
        alert_model.artifacts = artifacts if artifacts else None

        # 6. Create alert
        saved_alert_row_id = Alert.create(alert_model)
        self.logger.info(f"Alert created: {saved_alert_row_id}")

        # 7. Case management
        try:
            existing_case = Case.get_by_correlation_uid(correlation_uid, lazy_load=True)
            if existing_case:
                update_case = CaseModel(
                    alerts=[*existing_case.alerts, saved_alert_row_id],
                    row_id=existing_case.row_id
                )
                Case.update(update_case)
            else:
                new_case = CaseModel(
                    title=...,
                    severity=...,
                    impact=...,
                    priority=...,
                    confidence=Confidence.HIGH,
                    description=...,
                    correlation_uid=correlation_uid,
                    alerts=[saved_alert_row_id]
                )
                Case.create(new_case)
        except Exception as e:
            self.logger.error(f"Case operation failed: {str(e)}")

        return True
```

Framework behaviour note:
- The framework continuously instantiates the Module class and calls `run()`. Each invocation processes exactly one alert — design the module to be stateless; do not accumulate cross-alert state in instance variables.

Field mapping principles:
- `AlertModel.raw_data`: store the full raw alert as a JSON string.
- `AlertModel.unmapped`: store fields that could not be mapped to AlertModel/ArtifactModel standard fields.
- AlertModel field population priority: ① map directly from the raw alert; ② derive via calculation or transformation from raw alert fields; ③ use a sensible default only when both previous steps fail.
- MITRE ATT&CK fields (`tactic`, `technique`, `sub_technique`) should be hardcoded based on the alert type.
- `Alert.create(alert_model)` automatically cascade-creates artifact records, writes the resulting row_id list back to `AlertModel.artifacts`, and then creates the alert record — attach artifacts to `alert_model`, do not call `Artifact.create` separately.
- If fields in `unmapped` (or other high-value fields) need structured storage, create an `EnrichmentModel` record and attach it to the `enrichments` field of ArtifactModel / AlertModel / CaseModel.
- For threat intelligence or Owner attribution on an entity, prefer storing directly in the corresponding `ArtifactModel` fields (`owner`, `reputation_score`, `reputation_provider`); create an EnrichmentModel and attach it to ArtifactModel only when richer structured content is needed.

### Step 6 — Add the Debug Entry Point

Append to the end of the file:

```python
if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    module = Module()
    module.debug_message_id = "<replace with a real stream message ID>"
    module.run()
```

Remind the user to replace `debug_message_id` with a real message ID from the Redis Stream to enable direct script execution for debugging.

If batch validation is useful, add this note as well for testing the earliest alerts in order:

```python
# Batch test the earliest 100 alerts
module = Module()
message_ids = module.read_stream_head_ids(100)
for message_id in message_ids:
    module.debug_message_id = message_id
    module.run()
```

## Clarification Rules

- If the user has not provided a rule name, ask before proceeding — never assume.
- If the MCP stream cannot be read, ask the user to choose Method B or Method C to obtain a sample.
- If the meaning of a raw_alert field is unclear, ask the user or consult relevant documentation before mapping.
- If the user has not specified correlation aggregation keys, infer them from the alert semantics and confirm with the user.

## Output Rules

- Generate complete, directly runnable Python file content.
- Keep code comments concise and in English, consistent with the `-en` convention.
- After generating the code, briefly explain the mapping logic for key fields so the user can review.
- Do not output content unrelated to the module code.
- AlertModel and CaseModel `description` fields support markdown rendering, but are displayed as inline component in the frontend — avoid `#` `##` `###` heading syntax, `---` horizontal rules, HTML tags, and images, as they break the page layout. Other markdown features (bold, inline code, code blocks, lists, tables, links, blockquotes) are supported and should be used to improve readability.

## Failure Handling

- If the ASP MCP cannot be connected and the user cannot provide a raw_alert sample, state that the workflow cannot continue and direct the user to complete the prerequisites first.
- If the raw_alert structure is abnormal (missing fields or excessively nested), describe the issue and ask the user to provide more samples or additional clarification.
- If the rule name provided by the user contains characters that are invalid in a Python filename, prompt the user to verify the name.
