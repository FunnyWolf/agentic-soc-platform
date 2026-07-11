from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from apps.artifacts.models import Artifact, ArtifactName, ArtifactRole, ArtifactType
from apps.enrichments.models import Enrichment, EnrichmentProvider, EnrichmentType
from .models import AuditLog


class AuditDeleteCascadeTests(TestCase):
    def test_deleting_parent_with_fk_relation_audit_child_does_not_query_deleted_parent(self):
        artifact = Artifact.objects.create(
            name=ArtifactName.HOSTNAME,
            type=ArtifactType.HOSTNAME,
            role=ArtifactRole.RELATED,
            value="audit-delete-repro.example",
        )
        enrichment = Enrichment.objects.create(
            artifact=artifact,
            name="audit delete repro enrichment",
            type=EnrichmentType.OBSERVATION,
            provider=EnrichmentProvider.INTERNAL,
            uid="audit-delete-repro",
            value="audit-delete-repro.example",
        )

        artifact_id = artifact.id
        enrichment_id = enrichment.id

        artifact.delete()

        artifact_content_type = ContentType.objects.get_for_model(Artifact)
        self.assertTrue(
            AuditLog.objects.filter(
                content_type=artifact_content_type,
                object_id=str(artifact_id),
                action="deleted",
                metadata__relation="enrichments",
                metadata__related_id=str(enrichment_id),
            ).exists()
        )
