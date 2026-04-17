import json

from Lib.api import is_ipaddress
from Lib.baseplaybook import BasePlaybook
from PLUGINS.AlienVaultOTX.alienvaultotx import AlienVaultOTX
from PLUGINS.SIRP.sirpapi import Artifact
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus, EnrichmentModel, ArtifactModel, PlaybookModel


class Playbook(BasePlaybook):
    NAME = "TI Enrichment By AlienVaultOTX"
    DESC = "TI Enrichment By AlienVaultOTX"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        try:
            artifact = Artifact.get(self.param_source_row_id)
            self.logger.info(f"Querying threat intelligence for : {artifact}")

            if artifact.type in ["IP Address"]:
                if is_ipaddress(artifact.value):
                    ti_result = AlienVaultOTX().query_ip(artifact.value)
                else:
                    ti_result = {"error": "Invalid IP address format."}
            elif artifact.type in ["Hash"]:
                ti_result = AlienVaultOTX().query_file(artifact.value)
            else:
                ti_result = {"error": "Unsupported type."}

            enrichments = artifact.enrichments
            for enrichment in enrichments:
                if enrichment.type == "Threat Intelligence" and enrichment.provider == "OTX":
                    enrichment.data = json.dumps(ti_result)
                    break
            else:
                enrichment = EnrichmentModel(name="TI Enrichment", type="Threat Intelligence", provider="OTX", value=artifact.value,
                                             data=json.dumps(ti_result))
                enrichments.append(enrichment)
            model_tmp = ArtifactModel(row_id=artifact.row_id, enrichments=enrichments)
            Artifact.update(model_tmp)

            self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Threat intelligence enrichment completed.")
        except Exception as e:
            self.logger.exception(e)
            self.update_playbook_status(PlaybookJobStatus.FAILED, f"Error during TI enrichment: {e}")
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    model = PlaybookModel(source_row_id='73ed8a06-38e9-4d03-8d17-74b578f0cafa')
    module = Playbook()
    module._playbook_model = model

    module.run()
