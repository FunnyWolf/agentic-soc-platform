from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from integrations.siem.clients import get_elk_client
from integrations.siem.models import SAMPLE_COUNT

logger = logging.getLogger(__name__)


def normalize_keywords(keyword_input: str | list[str]) -> list[str]:
    if isinstance(keyword_input, str):
        return [keyword_input]
    return keyword_input


def parse_time_range(time_range_start: str, time_range_end: str) -> tuple[float, float]:
    utc_format = "%Y-%m-%dT%H:%M:%SZ"
    try:
        start = datetime.strptime(time_range_start, utc_format).replace(tzinfo=timezone.utc)
        end = datetime.strptime(time_range_end, utc_format).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("Invalid UTC format.") from exc
    return start.timestamp(), end.timestamp()


def build_time_range_clause(time_field: str, time_range_start: str, time_range_end: str) -> dict[str, Any]:
    return {
        "range": {
            time_field: {
                "gte": time_range_start,
                "lt": time_range_end,
            }
        }
    }


def build_elk_keyword_clauses(keyword_input: str | list[str]) -> list[dict[str, Any]]:
    return [
        {"multi_match": {"query": keyword, "type": "best_fields", "fuzziness": "AUTO"}}
        for keyword in normalize_keywords(keyword_input)
    ]


def format_splunk_keyword(keyword: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9._:@/\\-]+", keyword):
        return keyword
    escaped_keyword = keyword.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped_keyword}"'


def build_splunk_keyword_clause(keyword_input: str | list[str]) -> str:
    return " AND ".join(format_splunk_keyword(keyword) for keyword in normalize_keywords(keyword_input))


# Splunk index names are restricted to lowercase letters, digits, underscores,
# and hyphens (Splunk enforces a max length of 80). We also allow the bare
# wildcard "*" as a sentinel used by keyword_search when no index is provided.
# Rejecting anything else prevents SPL injection through the `search index="..."`
# clause, e.g. an index_name like `main" | delete index=* | search index="x`.
_SPLUNK_INDEX_RE = re.compile(r"[a-zA-Z0-9_.:-]{1,80}")


def format_splunk_index(index_name: str) -> str:
    """Return ``index_name`` if it is a safe Splunk index token.

    Raises ``ValueError`` for values that could break out of the surrounding
    ``search index="..."`` clause. The allow-list matches the character set
    Splunk permits for real index names plus the ``*`` wildcard sentinel used
    internally when the caller intentionally targets all indices.
    """
    if index_name == "*":
        return "*"
    if not isinstance(index_name, str) or not _SPLUNK_INDEX_RE.fullmatch(index_name):
        raise ValueError(f"Invalid Splunk index name: {index_name!r}")
    return index_name


def extract_field_types(properties: dict[str, Any], prefix: str, result: dict[str, str]) -> None:
    for field_name, field_info in properties.items():
        full_name = f"{prefix}{field_name}" if prefix else field_name
        if "type" in field_info:
            result[full_name] = field_info["type"]
        if "properties" in field_info:
            extract_field_types(field_info["properties"], f"{full_name}.", result)


@lru_cache(maxsize=64)
def get_elk_field_types(index_name: str) -> dict[str, str]:
    client = get_elk_client()
    field_types: dict[str, str] = {}
    try:
        mapping_resp = client.indices.get_mapping(index=index_name)
    except Exception as exc:
        logger.warning(f"Failed to get ELK field types for {index_name}")
        logger.exception(exc)
        return field_types
    for _, index_mapping in mapping_resp.items():
        properties = index_mapping.get("mappings", {}).get("properties", {})
        extract_field_types(properties, "", field_types)
    return field_types


def build_safe_aggs(agg_fields: list[str], index_name: str) -> dict[str, Any]:
    field_types = get_elk_field_types(index_name)
    safe_aggs: dict[str, Any] = {}
    for field in agg_fields:
        field_type = field_types.get(field)
        if field_type in (None, "text"):
            agg_field = f"{field}.keyword"
            agg_key = agg_field
        else:
            agg_field = field
            agg_key = field
        safe_aggs[agg_key] = {"terms": {"field": agg_field, "size": SAMPLE_COUNT}}
    return safe_aggs
