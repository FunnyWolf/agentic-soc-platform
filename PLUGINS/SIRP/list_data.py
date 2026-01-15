import os
import time

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
django.setup()

from PLUGINS.SIRP.sirpapi import Alert
from PLUGINS.SIRP.sirptype import AlertModel

print(time.time())
if __name__ == "__main__":
    data = Alert.get("8c91dd23-3965-4847-85cd-af66acdc1eb4", include_system_fields=True)
    alert_obj = AlertModel(**data)
    print(alert_obj)
