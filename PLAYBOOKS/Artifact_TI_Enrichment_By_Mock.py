import json
import time

from Lib.baseplaybook import BasePlaybook
from PLUGINS.SIRP.sirpapi import Artifact
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus


class Playbook(BasePlaybook):
    TYPE = "ARTIFACT"
    NAME = "TI Enrichment By Mock"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        try:
            artifact = Artifact.get(self.param_source_rowid)
            self.logger.info(f"Querying threat intelligence for : {artifact}")

            # Simulate querying a threat intelligence database. In a real application, this should call an external API or database.
            time.sleep(5)
            if artifact.get("type") not in ["ip", "domain", "hash", "vm_ip"]:
                ti_result = {"error": "Unsupported type. Please use 'ip', 'domain', or 'hash'."}
            else:
                ti_result = {"malicious": True, "score": 85, "description": "This IP is associated with known malicious activities.", "source": "ThreatIntelDB",
                             "last_seen": "2024-10-01T12:34:56Z"}

            fields = [{"id": "enrichment", "value": json.dumps(ti_result)}]
            Artifact.update(self.param_source_rowid, fields)
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Threat intelligence enrichment completed.")
        except Exception as e:
            self.logger.exception(e)
            self.update_playbook_status(PlaybookJobStatus.FAILED, f"Error during TI enrichment: {e}")
        return


if __name__ == "__main__":
    params_debug = {'source_rowid': 'a966036e-b29e-4449-be48-23293bacac5d', 'source_worksheet': 'Artifact'}
    module = Playbook()
    # module._params = params_debug
    module.run()
