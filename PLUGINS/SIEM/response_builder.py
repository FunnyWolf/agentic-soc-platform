from __future__ import annotations

from typing import Any, Literal

from PLUGINS.SIEM.models import (
    AdaptiveQueryInput,
    AdaptiveQueryOutput,
    KeywordSearchInput,
    KeywordSearchOutput,
    SAMPLE_COUNT,
    SAMPLE_THRESHOLD,
    SUMMARY_THRESHOLD,
)
from PLUGINS.SIEM.query_backends import BackendQueryResult
from PLUGINS.SIEM.registry import get_default_agg_fields


def resolve_status(total_hits: int) -> Literal["records", "sample", "summary"]:
    if total_hits > SUMMARY_THRESHOLD:
        return "summary"
    if total_hits > SAMPLE_THRESHOLD:
        return "sample"
    return "records"


def build_adaptive_output(input_data: AdaptiveQueryInput, result: BackendQueryResult) -> AdaptiveQueryOutput:
    status = resolve_status(result.total_hits)
    records = _project_records(
        result.raw_records[: _record_limit_for_status(status)],
        index_name=result.index_name,
        time_field=input_data.time_field,
        explicit_fields=list(input_data.filters.keys()) + result.aggregation_fields,
    )
    return AdaptiveQueryOutput(
        backend=result.backend,
        index_name=result.index_name,
        status=status,
        total_hits=result.total_hits,
        returned_records=len(records),
        truncated=_is_truncated(result.raw_records, records, result.total_hits, status),
        message=_build_message(result.backend, result.index_name, result.total_hits, status),
        statistics=result.statistics,
        records=records,
    )


def build_keyword_output(input_data: KeywordSearchInput, result: BackendQueryResult) -> KeywordSearchOutput:
    status = resolve_status(result.total_hits)
    records = _project_records(
        result.raw_records[: _record_limit_for_status(status)],
        index_name=result.index_name,
        time_field=input_data.time_field,
        explicit_fields=result.aggregation_fields,
    )
    index_distribution = result.index_distribution or {result.index_name: result.total_hits}
    return KeywordSearchOutput(
        backend=result.backend,
        index_name=result.index_name,
        status=status,
        total_hits=result.total_hits,
        returned_records=len(records),
        truncated=_is_truncated(result.raw_records, records, result.total_hits, status),
        message=_build_message(result.backend, result.index_name, result.total_hits, status),
        index_distribution=index_distribution,
        statistics=result.statistics,
        records=records,
    )


def _record_limit_for_status(status: Literal["records", "sample", "summary"]) -> int:
    if status == "records":
        return SAMPLE_THRESHOLD
    if status == "sample":
        return SAMPLE_COUNT
    return SAMPLE_COUNT


def _build_message(backend: str, index_name: str, total_hits: int, status: str) -> str:
    if status == "summary":
        return f"Matched {total_hits} events in {index_name} ({backend}). Returning statistics only."
    if status == "sample":
        return f"Matched {total_hits} events in {index_name} ({backend}). Returning statistics and projected samples."
    return f"Matched {total_hits} events in {index_name} ({backend}). Returning projected records."


def _is_truncated(
        raw_records: list[dict[str, Any]],
        projected_records: list[dict[str, Any]],
        total_hits: int,
        status: str,
) -> bool:
    if status != "records":
        return total_hits > len(projected_records)
    if total_hits > len(projected_records):
        return True
    return any(len(projected) < len(raw) for raw, projected in zip(raw_records[: len(projected_records)], projected_records))


def _project_records(
        records: list[dict[str, Any]],
        *,
        index_name: str,
        time_field: str,
        explicit_fields: list[str],
) -> list[dict[str, Any]]:
    projection_fields = _build_projection_fields(index_name=index_name, time_field=time_field, explicit_fields=explicit_fields)
    return [_project_record(record, projection_fields) for record in records]


def _build_projection_fields(*, index_name: str, time_field: str, explicit_fields: list[str]) -> list[str]:
    ordered_fields: list[str] = []
    for field in [time_field, *explicit_fields, *get_default_agg_fields(index_name)]:
        if field and field not in ordered_fields:
            ordered_fields.append(field)
    return ordered_fields


def _project_record(record: dict[str, Any], projection_fields: list[str]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    for field in projection_fields:
        found, value = _extract_field_value(record, field)
        if found:
            projected[field] = value

    if "_index" in record:
        projected["_index"] = record["_index"]

    if projected:
        return projected

    fallback_fields = list(record.keys())[: min(len(record), SAMPLE_COUNT)]
    return {field: record[field] for field in fallback_fields}


def _extract_field_value(record: dict[str, Any], field_path: str) -> tuple[bool, Any]:
    if field_path in record:
        return True, record[field_path]

    current: Any = record
    for segment in field_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return False, None
        current = current[segment]
    return True, current
