from django.db import IntegrityError, connection, transaction


READABLE_ID_WIDTH = 6
READABLE_ID_RETRIES = 3
READABLE_ID_SEQUENCES = {
    "case": "readable_id_case_seq",
    "alert": "readable_id_alert_seq",
    "artifact": "readable_id_artifact_seq",
    "enrichment": "readable_id_enrichment_seq",
    "playbook": "readable_id_playbook_seq",
    "knowledge": "readable_id_knowledge_seq",
}


def format_readable_id(prefix: str, number: int) -> str:
    return f"{prefix}_{number:0{READABLE_ID_WIDTH}d}"


def parse_readable_id_number(value: str | None, prefix: str) -> int:
    if not value:
        return 0
    marker = f"{prefix}_"
    if not value.startswith(marker):
        return 0
    suffix = value[len(marker):]
    return int(suffix) if suffix.isdigit() else 0


def readable_id_sequence_name(prefix: str) -> str:
    try:
        return READABLE_ID_SEQUENCES[prefix]
    except KeyError as exc:
        raise ValueError(f"Unsupported readable ID prefix: {prefix}") from exc


def next_readable_id(prefix: str) -> str:
    sequence_name = readable_id_sequence_name(prefix)
    with connection.cursor() as cursor:
        cursor.execute("SELECT nextval(%s::regclass)", [sequence_name])
        number = cursor.fetchone()[0]
    return format_readable_id(prefix, number)


def sync_readable_id_sequence(prefix: str, minimum_value: int) -> None:
    if minimum_value < 1:
        return
    sequence_name = readable_id_sequence_name(prefix)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT last_value
            FROM pg_sequences
            WHERE schemaname = current_schema()
              AND sequencename = %s
            """,
            [sequence_name],
        )
        row = cursor.fetchone()
        current_value = row[0] if row and row[0] is not None else 0
        if current_value < minimum_value:
            cursor.execute("SELECT setval(%s::regclass, %s, true)", [sequence_name, minimum_value])


def assign_readable_id(instance, field_name: str, prefix: str) -> None:
    if getattr(instance, field_name):
        return
    setattr(instance, field_name, next_readable_id(prefix))


def save_with_readable_id(instance, field_name: str, prefix: str, *args, **kwargs):
    for attempt in range(READABLE_ID_RETRIES):
        assign_readable_id(instance, field_name, prefix)
        try:
            with transaction.atomic():
                return super(type(instance), instance).save(*args, **kwargs)
        except IntegrityError:
            if attempt == READABLE_ID_RETRIES - 1:
                raise
            setattr(instance, field_name, "")
    return super(type(instance), instance).save(*args, **kwargs)
