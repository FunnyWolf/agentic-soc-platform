from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dateutil import parser as dateutil_parser

UTC_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def normalize_time_input(value: Any, relative_base: datetime) -> str:
    system_timezone = relative_base.tzinfo or timezone.utc
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = dateutil_parser.parse(str(value), default=relative_base)
        except (ValueError, OverflowError):
            raise ValueError(f"Unable to parse time value: {value}")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=system_timezone)
    parsed = parsed.astimezone(timezone.utc)

    return parsed.strftime(UTC_TIME_FORMAT)


def normalize_time_range_inputs(data: Any) -> Any:
    if not isinstance(data, dict):
        return data

    normalized = dict(data)
    relative_base = datetime.now(datetime.now().astimezone().tzinfo or timezone.utc)
    for field_name in ("time_range_start", "time_range_end"):
        if field_name in normalized and normalized[field_name] is not None:
            normalized[field_name] = normalize_time_input(normalized[field_name], relative_base)
    return normalized


def validate_time_range_order(start: str, end: str) -> None:
    start_dt = datetime.strptime(start, UTC_TIME_FORMAT).replace(tzinfo=timezone.utc)
    end_dt = datetime.strptime(end, UTC_TIME_FORMAT).replace(tzinfo=timezone.utc)
    if end_dt <= start_dt:
        raise ValueError("time_range_end must be later than time_range_start")
