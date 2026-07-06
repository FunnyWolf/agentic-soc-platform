from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models


class AuditLog(models.Model):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.CharField(max_length=255, db_index=True)
    content_object = GenericForeignKey("content_type", "object_id")

    action = models.CharField(max_length=20)  # create / update / delete
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="audit_logs"
    )
    changes = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "-id"], name="audit_time_idx"),
            models.Index(fields=["content_type", "object_id", "-created_at", "-id"], name="audit_obj_time_idx"),
            models.Index(fields=["actor", "-created_at", "-id"], name="audit_actor_time_idx"),
            models.Index(fields=["action", "-created_at", "-id"], name="audit_action_time_idx"),
        ]

    def __str__(self):
        return f"{self.action} by {self.actor} on {self.content_type}:{self.object_id}"
