# ASP Alert Processing Architecture

## End-to-End Pipeline

```
Raw Logs
  │
  ▼
SIEM (ELK / Splunk)
  │  Detection Rule fires and produces an alert
  ▼
Forwarding Tool
  │  Writes the alert to a Redis Stack Stream
  │  Stream name = Rule name (hard constraint)
  ▼
Redis Stream: "<rule-name>"
  │
  ▼
ASP Module: MODULES/<rule-name>.py
  │  Framework continuously calls run(); Consumer Group ensures each alert is processed exactly once
  ▼
SIRP (Case / Alert / Artifact / Enrichment)
```

---

## Naming Convention (Hard Constraint)

```
SIEM Rule name
    = Redis Stream name
    = MODULES/<filename>.py  (without .py)
```

All three must be identical (case-sensitive). The framework relies on this convention to route alerts to the correct module. Any mismatch means alerts will not be consumed.

---

## Module Internal Processing Flow

```
self.read_stream_message()
        │
        │  raw_alert: dict
        ▼
┌─────────────────────────────────────────────┐
│ 1. Field Extraction                          │
│    Parse all valuable fields from raw_alert  │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ 2. Artifact Extraction                       │
│    Wrap entities (IP, username, ARN,         │
│    account ID, etc.) as List[ArtifactModel]  │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ 3. correlation_uid Computation               │
│    Select 2-3 aggregation keys + time window │
│    (typically 24h) to determine which alerts │
│    belong to the same Case                   │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ 4. AlertModel Assembly + Alert.create()      │
│    · Attach artifacts to alert_model         │
│    · Alert.create() cascade-creates Artifact │
│      records and writes row_ids back to      │
│      AlertModel                              │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ 5. Case Lookup / Create / Update             │
│    · Look up existing Case by correlation_uid│
│    · Found → append alert row_id to          │
│              Case.alerts and update          │
│    · Not found → create new Case             │
└─────────────────────────────────────────────┘
```

---

## SIRP Data Hierarchy

```
Case  (investigation case, top level)
 │  Aggregates related alerts via correlation_uid
 │
 └── Alert  (single rule-trigger record, second level)
      │  One raw_alert → one Alert record
      │
      └── Artifact  (smallest investigation entity, third level)
               IP addresses, usernames, ARNs, account IDs, etc.
               Can be shared across Alerts


Enrichment  (cross-cutting attachment layer, outside the three-tier hierarchy)
 Can be attached to any level
 ├── → Case.enrichments
 ├── → Alert.enrichments
 └── → Artifact.enrichments
```

### Layer Summary

| Level | Object | Description |
|-------|--------|-------------|
| Top | Case | A complete investigation event containing multiple related Alerts |
| Second | Alert | A single SIEM rule trigger, corresponding to one raw_alert |
| Third | Artifact | The smallest investigation atom (entity); the foundation for threat intel queries and correlation analysis |
| Cross-cutting | Enrichment | Structured supplementary context; independent of the three-tier hierarchy; attach to any level as needed |

---

## correlation_uid Design Principles

`correlation_uid` determines alert aggregation granularity — the most critical design decision in a module.

**Key question:** Do these alerts describe the same attacker targeting the same victim with the same type of behaviour?

| Key granularity | Consequence |
|-----------------|-------------|
| Too broad (e.g. only `account_id`) | Unrelated alerts merge into the same Case, creating investigation noise |
| Too narrow (e.g. includes a random `session_id`) | Alerts from the same attack are split into multiple Cases, losing context |
| Appropriate (e.g. `principal_user + target_user + account_id`) | Alerts from the same attacker targeting the same victim are grouped together |

**Generation:**
```python
correlation_uid = Correlation.generate_correlation_uid(
    rule_id=self.module_name,   # module name, isolates different rules
    time_window="24h",          # time window; a new Case opens after expiry
    keys=[key1, key2, key3],    # aggregation key list
    timestamp=event_time        # event occurrence time
)
```

---

## Artifact Design Principles

- Artifacts are the foundation for downstream investigation (threat intel queries, correlation analysis, Playbook execution); extract as many as possible from raw_alert
- Create one Artifact per valuable entity — do not merge multiple entities into one
- Use the `ArtifactType` enum for the `type` field (IP_ADDRESS, USER_NAME, RESOURCE_UID, etc.)
- Use the `role` field to distinguish the entity's role in the event (ACTOR = attacker side, TARGET = victim side, RELATED = related party)
- Prefer storing threat intelligence and Owner attribution directly in the corresponding `ArtifactModel` fields (`owner`, `reputation_score`, `reputation_provider`); create an EnrichmentModel only when richer structured content is needed

---

## Key File Index

| File | Purpose |
|------|---------|
| `MODULES/<rule-name>.py` | Alert processing module; one file per rule |
| `Lib/basemodule.py` | BaseModule base class; provides `read_stream_message()` and other core capabilities |
| `PLUGINS/SIRP/sirpcoremodel.py` | All data model and enum definitions |
| `PLUGINS/SIRP/sirpapi.py` | Alert / Case CRUD operation interfaces |
| `PLUGINS/SIRP/correlation.py` | `Correlation.generate_correlation_uid()` |
| `MODULES/Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy.py` | Reference implementation |
| `DATA/<rule-name>/raw_alert_*.json` | raw_alert samples for development and debugging |
