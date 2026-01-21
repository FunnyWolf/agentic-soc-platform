
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
        row_id_case = row.get("rowid")
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
