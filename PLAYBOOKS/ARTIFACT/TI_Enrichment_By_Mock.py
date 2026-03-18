import json

from Lib.baseplaybook import BasePlaybook
from PLUGINS.SIRP.sirpapi import Artifact
from PLUGINS.SIRP.sirpmodel import PlaybookModel, PlaybookJobStatus, EnrichmentModel, ArtifactModel


class Playbook(BasePlaybook):
    NAME = "TI Enrichment By Mock"
    DESC = "Simulate threat intelligence enrichment. This playbook is for testing and demonstration purposes only. It does not perform real threat intelligence queries."

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        artifact = Artifact.get(self.param_source_rowid)

        # Simulate querying a threat intelligence database. In a real application, this should call an external API or database.
        if artifact.type not in ["IP Address", "Hash"]:
            self.update_playbook_status(PlaybookJobStatus.FAILED, "Unsupported type. Please use 'IP Address', 'Hash'.")
            return
        else:
            ti_result = {"malicious": True, "score": 85, "description": "This IP is associated with known malicious activities.", "source": "ThreatIntelDB",
                         "last_seen": "2024-10-01T12:34:56Z"}
        enrichments = artifact.enrichments
        for enrichment in enrichments:
            if enrichment.type == "Threat Intelligence" and enrichment.provider == "MockTIProvider":
                enrichment.data = json.dumps(ti_result)
                break
        else:
            enrichment = EnrichmentModel(name="Mock TI Enrichment", type="Mock Threat Intelligence", provider="MockTIProvider", value=artifact.value,
                                         data=json.dumps(ti_result))
            enrichments.append(enrichment)
        model_tmp = ArtifactModel(rowid=artifact.rowid, enrichments=enrichments)
        Artifact.update(model_tmp)
        self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Threat intelligence enrichment completed.")
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    model = PlaybookModel(source_rowid='a966036e-b29e-4449-be48-23293bacac5d')
    module = Playbook()
    module._playbook_model = model
    module.run()
