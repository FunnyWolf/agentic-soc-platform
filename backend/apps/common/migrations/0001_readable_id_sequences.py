from django.db import migrations


READABLE_ID_TARGETS = (
    ("case", "cases", "case_id", "readable_id_case_seq"),
    ("alert", "alerts", "alert_id", "readable_id_alert_seq"),
    ("artifact", "artifacts", "artifact_id", "readable_id_artifact_seq"),
    ("enrichment", "enrichments", "enrichment_id", "readable_id_enrichment_seq"),
    ("playbook", "playbooks", "playbook_id", "readable_id_playbook_seq"),
    ("knowledge", "knowledge", "knowledge_id", "readable_id_knowledge_seq"),
)


def create_and_sync_sequences(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        for prefix, table_name, field_name, sequence_name in READABLE_ID_TARGETS:
            cursor.execute(f"CREATE SEQUENCE IF NOT EXISTS {sequence_name}")
            cursor.execute(
                f"""
                SELECT COALESCE(MAX(substring({field_name} FROM %s)::bigint), 0)
                FROM {table_name}
                WHERE {field_name} ~ %s
                """,
                [f"^{prefix}_([0-9]+)$", f"^{prefix}_[0-9]+$"],
            )
            max_number = cursor.fetchone()[0]
            if max_number:
                cursor.execute("SELECT setval(%s::regclass, %s, true)", [sequence_name, max_number])
            else:
                cursor.execute("SELECT setval(%s::regclass, 1, false)", [sequence_name])


def drop_sequences(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        for _prefix, _table_name, _field_name, sequence_name in reversed(READABLE_ID_TARGETS):
            cursor.execute(f"DROP SEQUENCE IF EXISTS {sequence_name}")


class Migration(migrations.Migration):

    dependencies = [
        ("cases", "0002_case_case_created_id_idx"),
        ("alerts", "0002_alert_alert_created_id_idx_and_more"),
        ("artifacts", "0002_artifact_artifact_created_id_idx"),
        ("enrichments", "0002_remove_mcp_provider_choice"),
        ("playbooks", "0001_initial"),
        ("knowledge", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_and_sync_sequences, reverse_code=drop_sequences),
    ]
