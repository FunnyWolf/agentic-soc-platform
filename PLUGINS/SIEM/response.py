from __future__ import annotations

from typing import Any, Literal, Optional

from PLUGINS.SIEM.backends import BackendQueryResult
from PLUGINS.SIEM.models import (
    AdaptiveQueryInput,
    KeywordSearchInput,
    QueryOutput,
    SAMPLE_COUNT,
    SAMPLE_THRESHOLD,
)
from PLUGINS.SIEM.registry import get_default_agg_fields


def resolve_status(total_hits: int) -> Literal["records", "summary"]:
    if total_hits > SAMPLE_THRESHOLD:
        return "summary"
    return "records"


def build_query_output(
        input_data: AdaptiveQueryInput | KeywordSearchInput,
        result: BackendQueryResult,
        *,
        index_distribution: Optional[dict[str, int]] = None,
) -> QueryOutput:
    status = resolve_status(result.total_hits)
    explicit_fields = _get_explicit_fields(input_data, result)
    record_limit = SAMPLE_THRESHOLD if status == "records" else SAMPLE_COUNT
    raw_slice = result.raw_records[:record_limit]

    records = project_records(
        raw_slice,
        index_name=result.index_name,
        time_field=input_data.time_field,
        explicit_fields=explicit_fields,
    )
    return QueryOutput(
        backend=result.backend,
        index_name=result.index_name,
        status=status,
        total_hits=result.total_hits,
        returned_records=len(records),
        truncated=result.total_hits > len(records),
        message=f"Matched {result.total_hits} events in {result.index_name} ({result.backend}). "
                + ("Returning projected records." if status == "records" else "Returning statistics and samples."),
        index_distribution=index_distribution,
        statistics=result.statistics,
        records=records,
    )


def _get_explicit_fields(
        input_data: AdaptiveQueryInput | KeywordSearchInput,
        result: BackendQueryResult,
) -> list[str]:
    if isinstance(input_data, AdaptiveQueryInput):
        return list(input_data.filters.keys()) + result.aggregation_fields
    return result.aggregation_fields


def project_records(
        records: list[dict[str, Any]],
        *,
        index_name: str,
        time_field: str,
        explicit_fields: list[str],
) -> list[dict[str, Any]]:
    projection_fields = build_projection_fields(
        index_name=index_name, time_field=time_field, explicit_fields=explicit_fields,
    )
    return [project_record(record, projection_fields) for record in records]


def build_projection_fields(*, index_name: str, time_field: str, explicit_fields: list[str]) -> list[str]:
    ordered_fields: list[str] = []
    for field in [time_field, *explicit_fields, *get_default_agg_fields(index_name)]:
        if field and field not in ordered_fields:
            ordered_fields.append(field)
    return ordered_fields


def project_record(record: dict[str, Any], projection_fields: list[str]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    for field in projection_fields:
        found, value = extract_field_value(record, field)
        if found:
            projected[field] = value

    if "_index" in record:
        projected["_index"] = record["_index"]

    return projected


def extract_field_value(record: dict[str, Any], field_path: str) -> tuple[bool, Any]:
    if field_path in record:
        return True, record[field_path]

    current: Any = record
    for segment in field_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return False, None
        current = current[segment]
    return True, current
