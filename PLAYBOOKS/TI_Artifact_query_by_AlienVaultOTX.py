import json

from Lib.baseplaybook import BasePlaybook
from PLUGINS.AlienVaultOTX.alienvaultotx import AlienVaultOTX
from PLUGINS.SIRP.nocolyapi import WorksheetRow


class Playbook(BasePlaybook):
    RUN_AS_JOB = False

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        worksheet = self.param("worksheet")
        rowid = self.param("rowid")
        artifact = WorksheetRow.get(worksheet, rowid)
        self.logger.info(f"Querying threat intelligence for : {artifact}")

        if artifact.get("type") == "ip" or artifact.get("type") == "vm_ip":
            ti_result = AlienVaultOTX().query_ip(artifact.get("value"))
        elif artifact.get("type") == "hash":
            ti_result = AlienVaultOTX().query_file(artifact.get("value"))
        else:
            ti_result = {"error": "Unsupported type. Please use 'ip', 'vm_ip', or 'hash'."}

        enrichment = {"enrichment": json.dumps(ti_result)}
        return enrichment


if __name__ == "__main__":
    params_debug = {'rowid': 'a966036e-b29e-4449-be48-23293bacac5d', 'worksheet': 'Artifact'}
    module = Playbook()
    module._params = params_debug
    result = module.run()
