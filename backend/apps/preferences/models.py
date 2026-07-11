from django.conf import settings
from django.db import models


class UserTablePreference(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="table_preferences")
    table_key = models.CharField(max_length=120)
    page_size = models.PositiveIntegerField(null=True, blank=True)
    column_settings = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_table_preferences"
        constraints = [
            models.UniqueConstraint(fields=["user", "table_key"], name="utp_user_table_uniq"),
        ]
        indexes = [
            models.Index(fields=["user", "table_key"], name="utp_user_table_idx"),
        ]

    def __str__(self):
        return f"{self.user_id}:{self.table_key}"


class SavedTableFilter(models.Model):
    class Visibility(models.TextChoices):
        PRIVATE = "private", "Private"
        SHARED = "shared", "Shared"

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="saved_table_filters")
    table_key = models.CharField(max_length=120)
    name = models.CharField(max_length=120)
    state = models.JSONField(default=dict)
    visibility = models.CharField(max_length=20, choices=Visibility.choices, default=Visibility.PRIVATE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "saved_table_filters"
        ordering = ["-updated_at", "-id"]
        indexes = [
            models.Index(fields=["table_key", "visibility"], name="stf_table_visibility_idx"),
            models.Index(fields=["owner", "table_key"], name="stf_owner_table_idx"),
        ]

    def __str__(self):
        return f"{self.name} ({self.table_key})"
