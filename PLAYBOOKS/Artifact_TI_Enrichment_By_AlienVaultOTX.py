import json

from Lib.api import is_ipaddress
from Lib.baseplaybook import BasePlaybook
from PLUGINS.AlienVaultOTX.alienvaultotx import AlienVaultOTX
from PLUGINS.SIRP.sirpapi import Artifact
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus


class Playbook(BasePlaybook):
    TYPE = "ARTIFACT"
    NAME = "TI Enrichment By AlienVaultOTX"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        try:
            artifact = Artifact.get(self.param_source_rowid)
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

            Artifact.update(self.param_source_rowid, fields)
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Threat intelligence enrichment completed.")
        except Exception as e:
            self.logger.exception(e)
            self.update_playbook_status(PlaybookJobStatus.FAILED, f"Error during TI enrichment: {e}")
        return


if __name__ == "__main__":
    params_debug = {'source_rowid': '54725ee3-c85d-49e7-ac09-4cb982dab957', 'source_worksheet': 'Artifact'}
    module = Playbook()
    # module._params = params_debug
    module.run()
