import os
import time

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
django.setup()

from PLUGINS.SIRP.nocolyapi import Worksheet

print(time.time())
if __name__ == "__main__":
    worksheet_id = "ticket"
    fields = Worksheet.get_fields(worksheet_id)
    fields_clean = {}

    for field_name in fields:
        field = fields[field_name]
        options = []
        for option in field.get("options", []):
            options.append(option.get("value"))

        fields_clean[field_name] = {
            "type": field.get("type"),
            "name": field.get("alias"),
            "required": field.get("required"),

        }
        if options:
            fields_clean[field_name]["options"] = options

    print(fields_clean)
