import json
import time

from Lib.baseplaybook import BasePlaybook
from PLUGINS.SIRP.sirpapi import Artifact
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus, PlaybookModel


class Playbook(BasePlaybook):
    TYPE = "ARTIFACT"
    NAME = "TI Enrichment By Mock"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        artifact = Artifact.get(self.param_source_rowid)

        # Simulate querying a threat intelligence database. In a real application, this should call an external API or database.
        time.sleep(1)

        if artifact.type not in ["IP Address", "Hash"]:
            self.update_playbook_status(PlaybookJobStatus.FAILED, "Unsupported type. Please use 'IP Address', 'Hash'.")
        else:
            ti_result = {"malicious": True, "score": 85, "description": "This IP is associated with known malicious activities.", "source": "ThreatIntelDB",
                         "last_seen": "2024-10-01T12:34:56Z"}

        fields = [{"id": "enrichment", "value": json.dumps(ti_result)}]
        # Artifact.update(self.param_source_rowid, fields)
        self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Threat intelligence enrichment completed.")
        return


if __name__ == "__main__":
    PlaybookModel(source_worksheet='Artifact', source_rowid='a966036e-b29e-4449-be48-23293bacac5d')
    module = Playbook()
    module.run()
