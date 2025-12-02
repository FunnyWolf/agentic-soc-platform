from Docker.mock.SIRP_MOCK.alert import get_mock_alerts
from Docker.mock.SIRP_MOCK.rule import rule_list
from Lib.api import get_current_time_string, string_to_timestamp, generate_four_random_timestamps
from PLUGINS.SIRP.grouprule import GroupRule
from PLUGINS.SIRP.nocolyapi import OptionSet
from PLUGINS.SIRP.sirpapi import Alert, Artifact, Case, create_alert_with_group_rule


def import_alerts():
    alert_list = get_mock_alerts()
    ALL_RULES = {}
    for rule in rule_list:
        ALL_RULES[rule.rule_id] = rule

    for alert in alert_list:
        rule_def: GroupRule = ALL_RULES.get(alert["rule_id"])
        if rule_def is None:
            print(f"未找到规则定义，跳过处理此告警: {alert['rule_id']}")
            continue

        default_times = generate_four_random_timestamps()
        alert_date = default_times["alert_date"]
        created_date = default_times["created_date"]
        acknowledged_date = default_times["acknowledged_date"]
        closed_date = default_times["closed_date"]

        alert["name"] = alert["rule_name"]
        alert["alert_date"] = alert_date

        case_row_id = create_alert_with_group_rule(alert, rule_def)


def old():
    # print("使用自定义参数生成时间戳:")
    # custom_times = generate_four_random_timestamps(
    #     days_ago_max=5,  # T1 在当前时间前 5 天内
    #     min_delta_2=5,  # T2 在 T1 之后 5 到 15 分钟内
    #     max_delta_2=15,
    #     min_delta_3=10,  # T3 在 T2 之后 10 到 45 分钟内
    #     max_delta_3=45,
    #     min_delta_4=6 * 60,  # T4 在 T3 之后 6 到 24 小时内
    #     max_delta_4=24 * 60,
    # )
    # print(custom_times)

    alert_list = get_mock_alerts()
    ALL_RULES = {}
    for rule in rule_list:
        ALL_RULES[rule.rule_id] = rule

    case_status_new = OptionSet.get_option_key_by_name_and_value("case_status", "New")

    for alert in alert_list:
        rule_def: GroupRule = ALL_RULES.get(alert["rule_id"])
        if rule_def is None:
            print(f"未找到规则定义，跳过处理此告警: {alert['rule_id']}")
            continue

        default_times = generate_four_random_timestamps()
        alert_date = default_times["alert_date"]
        created_date = default_times["created_date"]
        acknowledged_date = default_times["acknowledged_date"]
        closed_date = default_times["closed_date"]

        # artifact
        artifact_rowid_list = []
        artifacts = alert.get("artifact", [])
        for artifact in artifacts:
            artifact_fields = [
                {"id": "type", "value": artifact["type"]},
                {"id": "value", "value": artifact["value"]},
                {"id": "enrichment", "value": {"update_time": get_current_time_string()}},
            ]
            artifact_dict = {"type": artifact["type"], "value": artifact["value"], "enrichment": {"update_time": get_current_time_string()}}

            fields = [
                {"id": "type", "value": artifact["type"], "type": 2},
                {"id": "value", "value": artifact["value"]},
                {"id": "enrichment", "value": {"update_time": get_current_time_string()}},
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

            row_id_list = Artifact.update_or_create(fields, artifact_filter)
            artifact_rowid_list.extend(row_id_list)

        case_row_id = create_alert_with_group_rule(input_alert, rule)

        alert_fields = [
            {"id": "tags", "value": alert["tags"], "type": 2},
            {"id": "severity", "value": alert["severity"]},
            {"id": "source", "value": alert["source"]},
            {"id": "alert_date", "value": alert_date},
            {"id": "created_date", "value": created_date},
            {"id": "reference", "value": alert["reference"]},
            {"id": "description", "value": alert["description"]},
            {"id": "raw_log", "value": alert["raw_log"]},
            {"id": "rule_id", "value": alert["rule_id"]},
            {"id": "rule_name", "value": alert["rule_name"]},
            {"id": "artifact", "value": artifact_rowid_list},
        ]
        # alert
        row_id_alert = Alert.create(alert)
        print(f"create alert: {row_id_alert}")

        # case
        timestamp = string_to_timestamp(alert["alert_date"], "%Y-%m-%dT%H:%M:%SZ")
        deduplication_key = rule_def.generate_deduplication_key(artifacts=artifacts, timestamp=timestamp)
        print(f"deduplication_key: {deduplication_key}")

        row = Case.get_by_deduplication_key(deduplication_key)
        if row is None:
            if rule_def.source == "EDR":
                workbook = Case.load_workbook_md("EDR_L2_WORKBOOK")
            elif rule_def.source == "Email":
                workbook = Case.load_workbook_md("PHISHING_L2_WORKBOOK")
            else:
                workbook = "# There is no workbook for this source."

            case_field = [
                {"id": "deduplication_key", "value": deduplication_key},
                {"id": "title", "value": rule_def.generate_case_title(artifacts=artifacts)},
                {"id": "case_status", "value": case_status_new},
                {"id": "severity", "value": alert["severity"]},
                {"id": "type", "value": rule_def.source},
                {"id": "created_date", "value": created_date},
                {"id": "tags", "value": alert["tags"], "type": 2},
                {"id": "description", "value": alert["description"]},

                {"id": "alert", "value": [row_id_alert]},

                {"id": "workbook", "value": workbook},

                {"id": "acknowledged_date", "value": acknowledged_date},
                {"id": "closed_date", "value": closed_date},

            ]
            try:
                row_id_create = Case.create(case_field)
            except Exception as e:
                print(f"创建工单失败: {e}")
                continue
            print(f"create case: {row_id_create}")
        else:
            row_id_case = row.get("rowId")
            existing_alerts = row.get("alert", [])
            if row_id_alert not in existing_alerts:
                existing_alerts.append(row_id_alert)

            option_new_score = OptionSet.get_option_by_name_and_value("alert_case_severity", alert["severity"]).get("score", 0)

            severity_value_exist = row.get("severity")
            option_exist_score = OptionSet.get_option_by_name_and_value("alert_case_severity", severity_value_exist).get("score", 0)

            if option_new_score > option_exist_score:
                severity = alert["severity"]
            else:
                severity = severity_value_exist

            tags_exist = row.get("tags", [])
            for tag in alert["tags"]:
                if tag not in tags_exist:
                    tags_exist.append(tag)

            case_field = [
                {"id": "alert", "value": existing_alerts},
                {"id": "severity", "value": severity},
                {"id": "tags", "value": tags_exist, "type": 2}
            ]
            row_id_updated = Case.update(row_id_case, case_field)
            print(f"update case: {row_id_updated}")


if __name__ == "__main__":
    import_alerts()
