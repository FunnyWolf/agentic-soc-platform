import json
from datetime import datetime, timedelta, timezone

from PLUGINS.SIRP.nocolymodel import Condition, Group, Operator
from PLUGINS.SIRP.sirpapi import Enrichment, Artifact, Alert, Knowledge
from PLUGINS.SIRP.sirpmodel import ArtifactModel, EnrichmentModel, KnowledgeModel

now = datetime.now(timezone.utc)
past_10m = now - timedelta(minutes=10)
past_5m = now - timedelta(minutes=5)


def test_enrichment():
    enrichment_to_convert = EnrichmentModel(
        name="OTX Pulse for evil-domain.com",
        type="Other",
        provider="Other",
        created_time=now,
        value="evil-domain.com",
        src_url="https://otx.alienvault.com/indicator/domain/evil-domain.com",
        desc="This domain is associated with the 'Gootkit' malware family.",
        data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
    )
    #
    # rowid = Enrichment.create(enrichment_to_convert)
    # enrichment_to_convert.rowid = rowid
    # Enrichment.get(rowid="761bf560-15d9-4137-8a18-62e243cb1ee9")

    filter_model = Group(
        logic="AND",
        children=[
            Condition(
                field="type",
                operator=Operator.IN,
                value=["Other"]
            )
        ]
    )

    Enrichment.list(filter_model)


def test_alert():
    alert = Alert.get("ae83212e-5064-42dd-9e3f-f95b0aeded2d")

    artifact = Artifact.get("0e4527f9-a0b9-4d71-a805-95a7d8d3267e")

    artifact_model = ArtifactModel(
        rowid="0e4527f9-a0b9-4d71-a805-95a7d8d3267e",
        name="http://fake-payroll-login.com1",
        type="URL String",
        role="Related",
        owner="admin",
        value="http://fake-payroll-login.com",
        reputation_provider="OTX",
        reputation_score="Suspicious/Risky",
        enrichments=[
            EnrichmentModel(
                rowid="761bf560-15d9-4137-8a18-62e243cb1ee9",
                name="OTX Pulse for evil-domain.com update",
                type="TI",
                provider="OTX",
                created_time=now,
                value="evil-domain.com",
                src_url="https://otx.alienvault.com/indicator/domain/evil-domain.com",
                desc="This domain is associated with the 'Gootkit' malware family.",
                data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
            ),
            EnrichmentModel(
                name="OTX Pulse for fake-payroll-login.com",
                type="Other",
                provider="Other",
                created_time=now,
                value="fake-payroll-login.com",
                src_url="https://otx.alienvault.com/indicator/domain/fake-payroll-login.com",
                desc="This domain is associated with the 'Gootkit' malware family.",
                data=json.dumps({"pulse_count": 42, "tags": ["malware", "c2", "gootkit"]})
            )

        ]
    )
    rowid = Artifact.update_or_create(artifact_model)
    print(rowid)


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    # models = Knowledge.list_undone_actions()
    model = KnowledgeModel()
    model.rowid = "32284c3d-e4c1-40b1-b4a3-1bf2daa0b6c5"
    model.using = False
    model.source = "Case"
    model.tags = ["test", "updated"]
    Knowledge.update_or_create(model)
