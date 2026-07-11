import base64
import binascii
import json
from dataclasses import dataclass

from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import ValidationError


DEFAULT_CURSOR_PAGE_SIZE = 20
MAX_CURSOR_PAGE_SIZE = 100


@dataclass
class CursorPage:
    results: list
    next_cursor: str | None
    has_more: bool


def cursor_page_size(request, *, default=DEFAULT_CURSOR_PAGE_SIZE, maximum=MAX_CURSOR_PAGE_SIZE):
    raw_value = request.query_params.get("page_size")
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return default
    return min(max(value, 1), maximum)


def encode_cursor(record):
    payload = {
        "created_at": record.created_at.isoformat(),
        "id": str(record.id),
    }
    raw_value = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw_value).decode("ascii").rstrip("=")


def decode_cursor(cursor):
    try:
        padded = cursor + ("=" * (-len(cursor) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        created_at = parse_datetime(str(payload.get("created_at", "")))
        record_id = str(payload.get("id") or "")
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error, AttributeError):
        raise ValidationError({"cursor": "Invalid cursor."})

    if created_at is None:
        raise ValidationError({"cursor": "Invalid cursor."})
    if not record_id:
        raise ValidationError({"cursor": "Invalid cursor."})
    if timezone.is_naive(created_at):
        created_at = timezone.make_aware(created_at)
    return created_at, record_id


def paginate_created_at_cursor(queryset, request, *, default_page_size=DEFAULT_CURSOR_PAGE_SIZE):
    cursor = request.query_params.get("cursor")
    if cursor:
        created_at, record_id = decode_cursor(cursor)
        queryset = queryset.filter(
            Q(created_at__lt=created_at)
            | Q(created_at=created_at, id__lt=record_id)
        )

    page_size = cursor_page_size(request, default=default_page_size)
    rows = list(queryset.order_by("-created_at", "-id")[:page_size + 1])
    has_more = len(rows) > page_size
    results = rows[:page_size]
    next_cursor = encode_cursor(results[-1]) if has_more and results else None
    return CursorPage(results=results, next_cursor=next_cursor, has_more=has_more)


def cursor_response_payload(page, results):
    return {
        "results": results,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
    }
