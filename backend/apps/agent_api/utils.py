from datetime import timezone as datetime_timezone

from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import ValidationError


def bool_param(value, *, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if not normalized:
        return default
    return normalized not in {"0", "false", "no", "off"}


def list_param(query_params, name):
    values = []
    for raw_value in query_params.getlist(name):
        if raw_value is None:
            continue
        for item in str(raw_value).split(","):
            item = item.strip()
            if item:
                values.append(item)
    return values


def parse_tags(query_params):
    return list_param(query_params, "tag") + list_param(query_params, "tags")


def parse_timezone_aware_datetime(value, field_name):
    if value in (None, ""):
        return None
    parsed = parse_datetime(str(value).strip())
    if parsed is None:
        raise ValidationError({field_name: "Must be ISO 8601 datetime with timezone."})
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError({field_name: "Must include timezone, e.g. 2026-06-23T12:00:00Z."})
    return parsed.astimezone(datetime_timezone.utc)
