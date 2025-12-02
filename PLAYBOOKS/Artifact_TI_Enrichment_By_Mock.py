import json
import time

from Lib.baseplaybook import BasePlaybook
from PLUGINS.SIRP.nocolyapi import WorksheetRow
from PLUGINS.SIRP.sirpapi import Playbook as SIRPPlaybook


class Playbook(BasePlaybook):
    TYPE = "ARTIFACT"
    NAME = "TI Enrichment By Mock"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        try:
            worksheet = self.param("worksheet")
            rowid = self.param("rowid")

            artifact = WorksheetRow.get(worksheet, rowid, include_system_fields=False)
            self.logger.info(f"Querying threat intelligence for : {artifact}")

            # 模拟查询威胁情报数据库,在实际应用中，这里应该调用外部API或数据库进行查询
            time.sleep(5)
            if artifact.get("type") not in ["ip", "domain", "hash", "vm_ip"]:
                ti_result = {"error": "Unsupported type. Please use 'ip', 'domain', or 'hash'."}
            else:
                ti_result = {"malicious": True, "score": 85, "description": "This IP is associated with known malicious activities.", "source": "ThreatIntelDB",
                             "last_seen": "2024-10-01T12:34:56Z"}

            fields = [{"id": "enrichment", "value": json.dumps(ti_result)}]
            WorksheetRow.update(worksheet, rowid, fields)

            SIRPPlaybook.update_status_and_remark(self.param("playbook_rowid"), "Success", "Threat intelligence enrichment completed.")  # Success/Failed
        except Exception as e:
            self.logger.exception(e)
            SIRPPlaybook.update_status_and_remark(self.param("playbook_rowid"), "Failed", f"Error during TI enrichment: {e}")  # Success/Failed
        return


if __name__ == "__main__":
    params_debug = {'rowid': 'a966036e-b29e-4449-be48-23293bacac5d', 'worksheet': 'Artifact'}
    module = Playbook()
    module._params = params_debug
    module.run()
