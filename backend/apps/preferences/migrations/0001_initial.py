from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="SavedTableFilter",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("table_key", models.CharField(max_length=120)),
                ("name", models.CharField(max_length=120)),
                ("state", models.JSONField(default=dict)),
                ("visibility", models.CharField(choices=[("private", "Private"), ("shared", "Shared")], default="private", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("owner", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="saved_table_filters", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "db_table": "saved_table_filters",
                "ordering": ["-updated_at", "-id"],
            },
        ),
        migrations.CreateModel(
            name="UserTablePreference",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("table_key", models.CharField(max_length=120)),
                ("page_size", models.PositiveIntegerField(blank=True, null=True)),
                ("column_settings", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="table_preferences", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "db_table": "user_table_preferences",
            },
        ),
        migrations.AddIndex(
            model_name="savedtablefilter",
            index=models.Index(fields=["table_key", "visibility"], name="stf_table_visibility_idx"),
        ),
        migrations.AddIndex(
            model_name="savedtablefilter",
            index=models.Index(fields=["owner", "table_key"], name="stf_owner_table_idx"),
        ),
        migrations.AddIndex(
            model_name="usertablepreference",
            index=models.Index(fields=["user", "table_key"], name="utp_user_table_idx"),
        ),
        migrations.AddConstraint(
            model_name="usertablepreference",
            constraint=models.UniqueConstraint(fields=("user", "table_key"), name="utp_user_table_uniq"),
        ),
    ]
