import json

from Lib.baseplaybook import BasePlaybook
from PLUGINS.SIRP.sirpapi import Artifact, Case
from PLUGINS.SIRP.sirpcoremodel import EnrichmentModel, ArtifactModel, EnrichmentType, EnrichmentProvider
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus
from PLUGINS.ThreatIntelligence.tools import TIToolKit

TI_ENRICHMENT_TYPE = EnrichmentType.THREAT_INTELLIGENCE
TI_PROVIDER = EnrichmentProvider.ALIENVAULT_OTX


class Playbook(BasePlaybook):
    NAME = "Threat Intelligence Enrichment"
    DESC = "Threat Intelligence Enrichment"

    def __init__(self):
        super().__init__()  # do not delete this code

    def _query_ti(self, artifact) -> dict:
        output = TIToolKit.query(artifact.value or "", provider=TI_PROVIDER)
        if output.results:
            return output.results[0].raw
        return {"error": "No result from provider.", "indicator": artifact.value}

    @staticmethod
    def _update_artifact_enrichment(artifact, ti_result: dict):
        enrichments = artifact.enrichments or []
        for enrichment in enrichments:
            if enrichment.type == TI_ENRICHMENT_TYPE and enrichment.provider == TI_PROVIDER:
                enrichment.data = json.dumps(ti_result)
                break
        else:
            enrichment = EnrichmentModel(
                name="Threat Intelligence",
                type=TI_ENRICHMENT_TYPE,
                provider=TI_PROVIDER,
                value=artifact.value,
                data=json.dumps(ti_result),
            )
            enrichments.append(enrichment)
        model_tmp = ArtifactModel(row_id=artifact.row_id, enrichments=enrichments)
        Artifact.update(model_tmp)

    @staticmethod
    def _collect_unique_artifacts(case):
        artifacts = {}
        artifact_refs = 0
        for alert in case.alerts or []:
            for artifact in alert.artifacts or []:
                artifact_refs += 1
                if artifact and artifact.row_id and artifact.row_id not in artifacts:
                    artifacts[artifact.row_id] = artifact
        return artifact_refs, artifacts

    def run(self):
        try:
            case_row_id = self.param_source_row_id
            case = Case.get(case_row_id, lazy_load=False)
            if not case:
                message = f"Case not found. row_id: {case_row_id}"
                self.logger.error(message)
                self.update_playbook_status(PlaybookJobStatus.FAILED, message)
                return

            artifact_refs, artifacts = self._collect_unique_artifacts(case)
            stats = {
                "alerts": len(case.alerts or []),
                "artifacts": artifact_refs,
                "unique": len(artifacts),
                "enriched": 0,
                "unsupported": 0,
                "invalid": 0,
                "errors": 0,
            }

            for artifact in artifacts.values():
                try:
                    self.logger.info(f"Querying threat intelligence for artifact: {artifact}")
                    ti_result = self._query_ti(artifact)
                    if ti_result.get("error") == "Unsupported type.":
                        stats["unsupported"] += 1
                    elif ti_result.get("error") == "Invalid IP address format.":
                        stats["invalid"] += 1
                    self._update_artifact_enrichment(artifact, ti_result)
                    stats["enriched"] += 1
                except Exception as e:
                    stats["errors"] += 1
                    self.logger.exception(
                        f"Error during TI enrichment for artifact row_id={artifact.row_id}, "
                        f"type={artifact.type}, value={artifact.value}: {e}"
                    )

            message = (
                "Threat intelligence enrichment completed. "
                f"alerts={stats['alerts']}, artifacts={stats['artifacts']}, unique={stats['unique']}, "
                f"enriched={stats['enriched']}, unsupported={stats['unsupported']}, "
                f"invalid={stats['invalid']}, errors={stats['errors']}"
            )
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, message)
        except Exception as e:
            self.logger.exception(e)
            self.update_playbook_status(PlaybookJobStatus.FAILED, f"Error during TI enrichment: {e}")
        return
