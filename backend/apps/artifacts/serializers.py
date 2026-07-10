from rest_framework import serializers

from .models import Artifact


class ArtifactDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Artifact
        fields = (
            "id",
            "artifact_id",
            "name",
            "type",
            "role",
            "value",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "artifact_id", "created_at", "updated_at")


class ArtifactListSerializer(ArtifactDetailSerializer):
    alert_count = serializers.IntegerField(read_only=True, default=0)
    enrichment_count = serializers.IntegerField(read_only=True, default=0)

    class Meta(ArtifactDetailSerializer.Meta):
        fields = (
            "id",
            "artifact_id",
            "name",
            "type",
            "role",
            "value",
            "alert_count",
            "enrichment_count",
            "created_at",
            "updated_at",
        )
