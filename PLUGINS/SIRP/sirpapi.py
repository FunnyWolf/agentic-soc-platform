import json
import os
from enum import StrEnum
from typing import TypedDict, List, Optional, Union, Dict, Any, NotRequired, Literal

import requests

from Lib.api import string_to_timestamp, get_current_time_str
from Lib.log import logger
from PLUGINS.Embeddings.embeddings_qdrant import EmbeddingsAPI
from PLUGINS.SIRP.CONFIG import SIRP_NOTICE_WEBHOOK
from PLUGINS.SIRP.grouprule import GroupRule
from PLUGINS.SIRP.nocolyapi import WorksheetRow, OptionSet


class InputCase(TypedDict):
    """
    Need to be consistent with the SIRP Case table structure
    If there are new fields in SIRP, they need to be added here
    """
    title: str
    deduplication_key: str
    case_status: str
    created_date: str
    tags: List[str]
    severity: str
    type: str
    description: str
    workbook: str

    # AI fields
    confidence_ai: NotRequired[str]
    analysis_rationale_ai: NotRequired[str]
    recommended_actions_ai: NotRequired[str]
    recommended_actions_ai: NotRequired[List[str]]

    alert: List[str]


class InputAlert(TypedDict):
    source: str
    rule_id: str
    rule_name: str
    name: str
    alert_date: str
    created_date: str
    tags: List[str]
    severity: str
    reference: NotRequired[str]
    source_data_identifier: NotRequired[str]
    description: str
    summary_ai: NotRequired[Optional[Union[str, Dict[str, Any]]]]
    artifact: List[Dict]
    raw_log: NotRequired[Optional[Union[str, Dict[str, Any]]]]


class InputArtifact(TypedDict):
    type: str
    value: str
    enrichment: NotRequired[Dict[str, Any]]


class Artifact(object):
    WORKSHEET_ID = "artifact"

    def __init__(self):
        pass

    @staticmethod
    def get(rowid, include_system_fields=False):
        artifact = WorksheetRow.get(Artifact.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)
        return artifact

    @staticmethod
    def list(filter: dict):
        result = WorksheetRow.list(Artifact.WORKSHEET_ID, filter)
        return result

    @staticmethod
    def update(rowid, fields: List):
        row_id = WorksheetRow.update(Artifact.WORKSHEET_ID, rowid, fields)
        return row_id

    @staticmethod
    def create(fields: List):
        row_id = WorksheetRow.create(Artifact.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update_or_create(fields: List, filters: dict) -> List:
        rows = Artifact.list(filters)
        if rows:
            row_id_list = []
            for row in rows:
                rowid = row['rowId']
                rowid_updated = Artifact.update(rowid, fields)
                row_id_list.append(rowid_updated)
            return row_id_list
        else:
            rowid_created = Artifact.create(fields)
            return [rowid_created]


class Alert(object):
    WORKSHEET_ID = "alert"
    ARTIFACT_FIELD_ID = "artifact"
    COLLECTION_NAME = "sirp_alert"

    def __init__(self):
        pass

    @staticmethod
    def get(rowid, include_system_fields=False):
        alert = WorksheetRow.get(Alert.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)
        artifacts = WorksheetRow.relations(Alert.WORKSHEET_ID, rowid, Alert.ARTIFACT_FIELD_ID, relation_worksheet_id=Artifact.WORKSHEET_ID,
                                           include_system_fields=False)
        alert[Alert.ARTIFACT_FIELD_ID] = artifacts
        return alert

    @staticmethod
    def update(rowid, fields: list):
        row_id = WorksheetRow.update(Alert.WORKSHEET_ID, rowid, fields)
        return row_id

    @staticmethod
    def create(alert: InputAlert):
        artifact_rowid_list = []
        artifacts: list[dict] = alert.get("artifact", [])
        for artifact in artifacts:
            # if artifact.get("deduplication_key") is None:
            #     artifact["deduplication_key"] = f"{artifact["type"]}-{artifact["value"]}"

            artifact_fields = [
                {"id": "type", "value": artifact.get("type")},
                {"id": "value", "value": artifact.get("value")},
                {"id": "enrichment", "value": artifact.get("enrichment")},
            ]

            artifact_filter = {
                "type": "group",
                "logic": "AND",
                "children": [
                    {
                        "type": "condition",
                        "field": "type",
                        "operator": "eq",
                        "value": artifact.get("type")
                    },
                    {
                        "type": "condition",
                        "field": "value",
                        "operator": "eq",
                        "value": artifact.get("value")
                    }
                ]
            }

            row_id_list = Artifact.update_or_create(artifact_fields, artifact_filter)
            artifact_rowid_list.extend(row_id_list)

        if alert.get("created_date") is None:
            alert["created_date"] = get_current_time_str()

        alert_fields = [
            {"id": "tags", "value": alert.get("tags"), "type": 2},
            {"id": "severity", "value": alert.get("severity")},
            {"id": "source", "value": alert.get("source")},
            {"id": "alert_date", "value": alert.get("alert_date")},
            {"id": "created_date", "value": alert.get("created_date")},
            {"id": "reference", "value": alert.get("reference")},
            {"id": "description", "value": alert.get("description")},
            {"id": "raw_log", "value": alert.get("raw_log")},
            {"id": "rule_id", "value": alert.get("rule_id")},
            {"id": "rule_name", "value": alert.get("rule_name")},
            {"id": "name", "value": alert.get("name")},
            {"id": "summary_ai", "value": alert.get("summary_ai")},
            {"id": "artifact", "value": artifact_rowid_list},
        ]

        # alert
        row_id = WorksheetRow.create(Alert.WORKSHEET_ID, alert_fields)

        return row_id

    # Alert.embeddings_alert(row_id, alert)
    # result = Alert.search_alerts("FIN开头主机的告警", k=3)

    @staticmethod
    def embeddings_alert(row_id: str, alert: InputAlert):
        embeddings_api = EmbeddingsAPI()
        metadata = {}
        for key in alert:
            if isinstance(alert[key], str):
                metadata[key] = alert[key]
            else:
                metadata[key] = json.dumps(alert[key])  # Truncate long text to avoid exceeding the limit

        embeddings_api.add_document(
            collection_name="alert",
            ids=row_id,
            page_content=alert["description"],
            metadata=metadata
        )

    @staticmethod
    def search_alerts(query: str, k: int):
        embeddings_api = EmbeddingsAPI()
        result = embeddings_api.search_documents(collection_name="alert", query=query, k=k)
        return result


class Case(object):
    WORKSHEET_ID = "case"
    ALERT_FIELD_ID = "alert"

    def __init__(self):
        pass

    @staticmethod
    def get(rowid, include_system_fields=False) -> InputCase:
        case = WorksheetRow.get(Case.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)
        # alert id
        alerts = WorksheetRow.relations(Case.WORKSHEET_ID, rowid, Case.ALERT_FIELD_ID, relation_worksheet_id=Alert.WORKSHEET_ID,
                                        include_system_fields=include_system_fields)
        for alert in alerts:
            artifacts = WorksheetRow.relations(Alert.WORKSHEET_ID, alert.get("rowId"), Alert.ARTIFACT_FIELD_ID, relation_worksheet_id=Artifact.WORKSHEET_ID,
                                               include_system_fields=include_system_fields)
            alert[Alert.ARTIFACT_FIELD_ID] = artifacts
        case[Case.ALERT_FIELD_ID] = alerts
        return case

    @staticmethod
    def get_raw_data(rowid, include_system_fields=False) -> Dict:
        """Get the raw data of the case and its associated alarms and work orders, and only keep the fields useful for LLM"""
        case = WorksheetRow.get(Case.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)

        useful_case_fields = ["rowId", "title", 'case_status', 'created_date', 'tags', 'severity', 'type', 'description', 'close_reason', 'alert_date',
                              'case_id',
                              'respond_time', 'note', 'acknowledged_date']

        case_clean = {key: case[key] for key in useful_case_fields if key in case}

        # alert id
        alerts = WorksheetRow.relations(Case.WORKSHEET_ID, rowid, Case.ALERT_FIELD_ID, relation_worksheet_id=Alert.WORKSHEET_ID,
                                        include_system_fields=include_system_fields)
        alerts_clean = []
        for alert in alerts:
            useful_alert_fields = ["rowId", 'severity', 'rule_id', 'rule_name', 'id']
            alert_clean = {key: alert[key] for key in useful_alert_fields if key in alert}

            artifacts = WorksheetRow.relations(Alert.WORKSHEET_ID, alert.get("rowId"), Alert.ARTIFACT_FIELD_ID, relation_worksheet_id=Artifact.WORKSHEET_ID,
                                               include_system_fields=include_system_fields)
            artifacts_clean = []
            for artifact in artifacts:
                useful_artifact_fields = ["rowId", "type", "value", "enrichment", 'is_whitelisted', 'is_evidence']
                artifact_clean = {key: artifact[key] for key in useful_artifact_fields if key in artifact}
                artifacts_clean.append(artifact_clean)

            alert_clean[Alert.ARTIFACT_FIELD_ID] = artifacts_clean
            alerts_clean.append(alert_clean)

        case_clean[Case.ALERT_FIELD_ID] = alerts_clean
        return case_clean

    @staticmethod
    def create(case: InputCase):
        case_fields = [
            {"id": "title", "value": case["title"]},
            {"id": "deduplication_key", "value": case["deduplication_key"]},
            {"id": "alert", "value": case["alert"]},
            {"id": "case_status", "value": case["case_status"]},
            {"id": "created_date", "value": case["created_date"]},
            {"id": "tags", "value": case["tags"], "type": 2},
            {"id": "severity", "value": case["severity"]},
            {"id": "type", "value": case["type"]},
            {"id": "description", "value": case["description"]},
            {"id": "workbook", "value": case["workbook"]},
        ]
        row_id = WorksheetRow.create(Case.WORKSHEET_ID, case_fields)
        return row_id

    @staticmethod
    def update(row_id, fields: list):
        row_id = WorksheetRow.update(Case.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def get_by_deduplication_key(deduplication_key: str):
        filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "deduplication_key",
                    "operator": "eq",
                    "value": deduplication_key
                },
            ]
        }
        rows = WorksheetRow.list(Case.WORKSHEET_ID, filter)
        if rows:
            if len(rows) > 1:
                logger.warning(f"found multiple rows with deduplication_key {deduplication_key}")
            return rows[0]
        else:
            return None

    @staticmethod
    def get_by_case_id(case_id: str):
        filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "case_id",
                    "operator": "eq",
                    "value": case_id
                },
            ]
        }
        rows = WorksheetRow.list(Case.WORKSHEET_ID, filter)
        if rows:
            if len(rows) > 1:
                logger.warning(f"found multiple rows with case_id {case_id}")
            return Case.get(rows[0]['rowId'])
        else:
            return None

    @staticmethod
    def load_workbook_md(workbook_name: str) -> str:
        ## TODO remove this function

        """
        Read the content of DATA/WORKBOOK/{workbook_name}.md according to the workbook name and return a string.
        The path is relative to the project root (two levels up to the asf folder).
        """
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        md_path = os.path.join(base_dir, 'DATA', 'WORKBOOK', f"{workbook_name}.md")
        if not os.path.exists(md_path):
            raise FileNotFoundError(f"workbook md not found: {md_path}")
        with open(md_path, 'r', encoding='utf-8') as f:
            return f.read()


PlaybookStatusType = Literal["Success", "Failed", "Pending", "Running"]


class PlaybookStatus(StrEnum):
    SUCCESS = 'Success'
    FAILED = 'Failed'
    PENDING = 'Pending'
    RUNNING = 'Running'


class Playbook(object):
    WORKSHEET_ID = "playbook"

    def __init__(self):
        pass

    @staticmethod
    def list(filter: dict):
        result = WorksheetRow.list(Playbook.WORKSHEET_ID, filter, include_system_fields=False)
        return result

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(Playbook.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update(row_id, fields: list):
        row_id = WorksheetRow.update(Playbook.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def update_status_and_remark(row_id, status: PlaybookStatusType, remark):
        fields = [
            {"id": "job_status", "value": status},
            {"id": "remark", "value": remark},
        ]
        row_id = WorksheetRow.update(Playbook.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def get_pending_playbooks():
        pending_option_value = OptionSet.get_option_key_by_name_and_value("playbook_status", "Pending")
        artifact_filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "job_status",
                    "operator": "in",
                    "value": [
                        pending_option_value
                    ]
                }
            ]
        }
        result = Playbook.list(artifact_filter)
        return result


KnowledgeAction = Literal["Store", "Remove", "Done"]
KnowledgeUsing = Literal[0, 1]


class Knowledge(object):
    WORKSHEET_ID = "knowledge"
    COLLECTION_NAME = "sirp_knowledge"

    def __init__(self):
        pass

    @staticmethod
    def list(filter: dict):
        result = WorksheetRow.list(Knowledge.WORKSHEET_ID, filter, include_system_fields=False)
        return result

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(Knowledge.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update(row_id, fields: list):
        row_id = WorksheetRow.update(Knowledge.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def update_action_and_using(row_id, action: KnowledgeAction, using: KnowledgeUsing):
        fields = [
            {"id": "action", "value": action},
            {"id": "using", "value": using},
        ]
        row_id = WorksheetRow.update(Knowledge.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def get_undone_actions():
        options = OptionSet.get("knowledge_action")

        action_list = []
        for option in options:
            if option.get("value") != "Done":
                action_list.append(option.get("key"))

        artifact_filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "action",
                    "operator": "in",
                    "value": action_list
                }
            ]
        }
        result = Knowledge.list(artifact_filter)
        return result


class PlaybookMessage(object):
    WORKSHEET_ID = "playbook_message"

    def __init__(self):
        pass

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(PlaybookMessage.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update(row_id, fields: list):
        row_id = WorksheetRow.update(PlaybookMessage.WORKSHEET_ID, row_id, fields)
        return row_id


class Notice(object):
    @staticmethod
    def send(user, title, body=None):
        result = requests.post(SIRP_NOTICE_WEBHOOK, json={"title": title, "body": body, "user": user})
        return result


def create_alert_with_group_rule(alert: InputAlert, rule_def: GroupRule) -> str:
    """
    Create alerts and cases using alert aggregation rules.
    The function will automatically generate a deduplication fingerprint based on the definition of rule_def, and decide whether to create a new case or update an existing case.
    """

    # alert
    row_id_alert = Alert.create(alert)

    artifacts = alert.get("artifact", [])

    # case
    timestamp = string_to_timestamp(alert["alert_date"], "%Y-%m-%dT%H:%M:%SZ")
    deduplication_key = rule_def.generate_deduplication_key(artifacts=artifacts, timestamp=timestamp)

    row = Case.get_by_deduplication_key(deduplication_key)
    if row is None:
        if rule_def.workbook is None:
            workbook = "# There is no workbook for this source."
        else:
            workbook = rule_def.workbook

        case_status_new = OptionSet.get_option_key_by_name_and_value("case_status", "New")

        case: InputCase = {
            "title": rule_def.generate_case_title(artifacts=artifacts),
            "deduplication_key": deduplication_key,
            "alert": [row_id_alert],
            "case_status": case_status_new,
            "created_date": get_current_time_str(),
            "tags": alert["tags"],
            "severity": alert["severity"],
            "type": rule_def.source,
            "description": alert["description"],
            "workbook": workbook,
        }
        row_id_create = Case.create(case)
        return row_id_create
    else:
        row_id_case = row.get("rowId")
        existing_alerts = row.get("alert", [])
        if row_id_alert not in existing_alerts:
            existing_alerts.append(row_id_alert)

        case_field = [
            {"id": "alert", "value": existing_alerts},
        ]

        # change case severity if new alert severity is higher
        if rule_def.follow_alert_severity:
            option_new_score = OptionSet.get_option_by_name_and_value("alert_case_severity", alert["severity"]).get("score", 0)

            severity_value_exist = row.get("severity")
            option_exist_score = OptionSet.get_option_by_name_and_value("alert_case_severity", severity_value_exist).get("score", 0)

            if option_new_score > option_exist_score:
                severity = alert["severity"]
            else:
                severity = severity_value_exist
            case_field.append({"id": "severity", "value": severity})

        # append alert tags to case tags
        if rule_def.append_alert_tags:
            tags_exist = row.get("tags", [])
            for tag in alert["tags"]:
                if tag not in tags_exist:
                    tags_exist.append(tag)
            case_field.append({"id": "tags", "value": tags_exist, "type": 2})

        row_id_updated = Case.update(row_id_case, case_field)
        return row_id_updated
