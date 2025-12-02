import json

from Lib.api import is_ipaddress
from Lib.baseplaybook import BasePlaybook
from PLUGINS.AlienVaultOTX.alienvaultotx import AlienVaultOTX
from PLUGINS.SIRP.nocolyapi import WorksheetRow
from PLUGINS.SIRP.sirpapi import Playbook as SIRPPlaybook


class Playbook(BasePlaybook):
    TYPE = "ARTIFACT"
    NAME = "TI Enrichment By AlienVaultOTX"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        try:
            worksheet = self.param("worksheet")
            rowid = self.param("rowid")

            artifact = WorksheetRow.get(worksheet, rowid, include_system_fields=False)
            self.logger.info(f"Querying threat intelligence for : {artifact}")

            if "ip" in artifact.get("type"):
                ip = artifact.get("value")
                if is_ipaddress(ip):
                    ti_result = AlienVaultOTX().query_ip(ip)
                else:
                    ti_result = {"error": "Invalid IP address format."}
            elif artifact.get("type") == "hash":
                ti_result = AlienVaultOTX().query_file(artifact.get("value"))
            else:
                ti_result = {"error": "Unsupported type. Please use 'ip', 'vm_ip', or 'hash'."}

            fields = [{"id": "enrichment", "value": json.dumps(ti_result)}]
            WorksheetRow.update(worksheet, rowid, fields)

            SIRPPlaybook.update_status_and_remark(self.param("playbook_rowid"), "Success", "Threat intelligence enrichment completed.")  # Success/Failed
        except Exception as e:
            self.logger.exception(e)
            SIRPPlaybook.update_status_and_remark(self.param("playbook_rowid"), "Failed", f"Error during TI enrichment: {e}")  # Success/Failed
        return


if __name__ == "__main__":
    params_debug = {'rowid': '54725ee3-c85d-49e7-ac09-4cb982dab957', 'worksheet': 'Artifact'}
    module = Playbook()
    module._params = params_debug
    module.run()
