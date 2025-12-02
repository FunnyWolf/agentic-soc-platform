from PLUGINS.SIRP.nocolyapi import WorksheetRow

if __name__ == "__main__":
    filter = {
        # "type": "group",
        # "logic": "OR",
        # "children": [
        #     {
        #         "type": "condition",
        #         "field": "deduplication_key",
        #         "operator": "isnotempty",
        #     },
        # ]
    }
    worksheet_id_list = ["artifact", "alert", "case"]
    for worksheet_id in worksheet_id_list:
        row_ids = []
        rows = WorksheetRow.list(worksheet_id, filter=filter)
        for row in rows:
            row_ids.append(row["rowId"])
        if row_ids:
            WorksheetRow.delete(worksheet_id=worksheet_id, row_ids=row_ids)
