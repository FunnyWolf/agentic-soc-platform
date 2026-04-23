from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Literal

from splunklib.results import JSONResultsReader

from PLUGINS.ELK.client import ELKClient
from PLUGINS.SIEM.models import (
    AdaptiveQueryInput,
    FieldStat,
    KeywordSearchInput,
    SAMPLE_COUNT,
    SAMPLE_THRESHOLD,
)
from PLUGINS.SIEM.registry import get_default_agg_fields
from PLUGINS.Splunk.client import SplunkClient


@dataclass(slots=True)
class BackendQueryResult:
    backend: Literal["ELK", "Splunk"]
    index_name: str
    total_hits: int
    aggregation_fields: list[str]
    statistics: list[FieldStat]
    raw_records: list[dict[str, Any]]
    index_distribution: dict[str, int] = field(default_factory=dict)


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


def _extract_elk_records(hits: list[dict[str, Any]], include_index: bool = False) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for hit in hits:
        record = hit["_source"].copy() if include_index else hit["_source"]
        if include_index:
            record["_index"] = hit["_index"]
        records.append(record)
    return records


def _extract_elk_stats(response: dict[str, Any], agg_fields: list[str]) -> list[FieldStat]:
    stats_output: list[FieldStat] = []
    aggregations = response.get("aggregations", {})
    for field in agg_fields:
        agg_key = f"{field}.keyword" if f"{field}.keyword" in aggregations else field
        if agg_key not in aggregations:
            continue
        buckets = aggregations[agg_key].get("buckets", [])
        if buckets:
            stats_output.append(
                FieldStat(field_name=field, top_values={bucket["key"]: bucket["doc_count"] for bucket in buckets})
            )
    return stats_output


def _build_time_range_clause(time_field: str, time_range_start: str, time_range_end: str) -> dict[str, Any]:
    return {
        "range": {
            time_field: {
                "gte": time_range_start,
                "lt": time_range_end,
            }
        }
    }


def _build_elk_keyword_clauses(keyword_input: str | list[str]) -> list[dict[str, Any]]:
    return [
        {"multi_match": {"query": keyword, "type": "best_fields", "fuzziness": "AUTO"}}
        for keyword in normalize_keywords(keyword_input)
    ]


def _format_splunk_keyword(keyword: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9._:@/\\-]+", keyword):
        return keyword
    escaped_keyword = keyword.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped_keyword}"'


def _build_splunk_keyword_clause(keyword_input: str | list[str]) -> str:
    return " AND ".join(_format_splunk_keyword(keyword) for keyword in normalize_keywords(keyword_input))


def _clean_splunk_record(log: dict[str, Any]) -> dict[str, Any]:
    clean_record: dict[str, Any] = {}
    for key, value in log.items():
        if not key.startswith("_") and key not in ["splunk_server", "host", "source", "sourcetype"]:
            clean_record[key] = value
    if "_time" in log:
        clean_record["@timestamp"] = log["_time"]
    if "_raw" in log:
        try:
            raw_parsed = json.loads(log["_raw"])
        except (json.JSONDecodeError, TypeError):
            raw_parsed = None
        if isinstance(raw_parsed, dict):
            for key, value in raw_parsed.items():
                if key not in clean_record:
                    clean_record[key] = value
    return clean_record


def _fetch_splunk_records(job, count: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    results = job.results(count=count, output_mode="json")
    for result in results:
        payload = json.loads(result)
        for log in payload.get("results", []):
            records.append(_clean_splunk_record(log))
    return records


def _fetch_splunk_top_stats(service, search_query: str, start_time: float, end_time: float, agg_fields: list[str]) -> list[FieldStat]:
    stats_output: list[FieldStat] = []
    for field in agg_fields:
        stats_query = f"{search_query} | top limit={SAMPLE_COUNT} {field}"
        oneshot = service.jobs.oneshot(stats_query, earliest_time=start_time, latest_time=end_time, output_mode="json")
        reader = JSONResultsReader(oneshot)
        top_values: dict[str | int, int] = {}
        for item in reader:
            if isinstance(item, dict) and field in item:
                top_values[item[field]] = int(item["count"])
        if top_values:
            stats_output.append(FieldStat(field_name=field, top_values=top_values))
    return stats_output


def _create_and_wait_splunk_job(service, search_query: str, start_time: float, end_time: float):
    job = service.jobs.create(search_query, earliest_time=start_time, latest_time=end_time, exec_mode="normal")
    while not job.is_done():
        time.sleep(0.2)
    return job


def _extract_field_types(properties: dict[str, Any], prefix: str, result: dict[str, str]) -> None:
    for field_name, field_info in properties.items():
        full_name = f"{prefix}{field_name}" if prefix else field_name
        if "type" in field_info:
            result[full_name] = field_info["type"]
        if "properties" in field_info:
            _extract_field_types(field_info["properties"], f"{full_name}.", result)


@lru_cache(maxsize=64)
def _get_elk_field_types(index_name: str) -> dict[str, str]:
    client = ELKClient.get_client()
    field_types: dict[str, str] = {}
    try:
        mapping_resp = client.indices.get_mapping(index=index_name)
    except Exception:
        return field_types
    for _, index_mapping in mapping_resp.items():
        properties = index_mapping.get("mappings", {}).get("properties", {})
        _extract_field_types(properties, "", field_types)
    return field_types


def _build_safe_aggs(agg_fields: list[str], index_name: str) -> dict[str, Any]:
    field_types = _get_elk_field_types(index_name)
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


class ELKQueryBackend:
    backend_name = "ELK"

    @classmethod
    def execute_structured_query(cls, input_data: AdaptiveQueryInput) -> BackendQueryResult:
        client = ELKClient.get_client()
        aggregation_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)

        must_clauses: list[dict[str, Any]] = [
            _build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end)
        ]
        for field, value in input_data.filters.items():
            if isinstance(value, list):
                must_clauses.append({"terms": {field: value}})
            else:
                must_clauses.append({"term": {field: value}})

        query_body = {"bool": {"must": must_clauses}}
        response = client.search(
            index=input_data.index_name,
            query=query_body,
            aggs=_build_safe_aggs(aggregation_fields, input_data.index_name),
            size=SAMPLE_THRESHOLD,
            track_total_hits=True,
        )

        return BackendQueryResult(
            backend=cls.backend_name,
            index_name=input_data.index_name,
            total_hits=response["hits"]["total"]["value"],
            aggregation_fields=aggregation_fields,
            statistics=_extract_elk_stats(response, aggregation_fields),
            raw_records=_extract_elk_records(response["hits"]["hits"]),
        )

    @classmethod
    def execute_keyword_query(cls, input_data: KeywordSearchInput) -> BackendQueryResult:
        client = ELKClient.get_client()
        effective_index = input_data.index_name or "*"
        aggregation_fields = get_default_agg_fields(input_data.index_name) if input_data.index_name else []

        query_body = {
            "bool": {
                "must": [
                    _build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end),
                    *_build_elk_keyword_clauses(input_data.keyword),
                ]
            }
        }

        aggs = {"_index": {"terms": {"field": "_index", "size": 50}}}
        if aggregation_fields:
            aggs.update(_build_safe_aggs(aggregation_fields, effective_index))

        response = client.search(
            index=effective_index,
            query=query_body,
            aggs=aggs,
            size=SAMPLE_THRESHOLD,
            track_total_hits=True,
        )

        buckets = response.get("aggregations", {}).get("_index", {}).get("buckets", [])
        index_distribution = {bucket["key"]: bucket["doc_count"] for bucket in buckets}
        if input_data.index_name and input_data.index_name not in index_distribution:
            index_distribution[input_data.index_name] = response["hits"]["total"]["value"]

        return BackendQueryResult(
            backend=cls.backend_name,
            index_name=input_data.index_name or effective_index,
            total_hits=response["hits"]["total"]["value"],
            aggregation_fields=aggregation_fields,
            statistics=_extract_elk_stats(response, aggregation_fields),
            raw_records=_extract_elk_records(response["hits"]["hits"], include_index=True),
            index_distribution=index_distribution,
        )

    @classmethod
    def discover_keyword_hit_indices(cls, input_data: KeywordSearchInput, indices: list[str]) -> list[str]:
        if not indices:
            return []

        client = ELKClient.get_client()
        response = client.search(
            index=",".join(indices),
            query={
                "bool": {
                    "must": [
                        _build_time_range_clause(
                            input_data.time_field,
                            input_data.time_range_start,
                            input_data.time_range_end,
                        ),
                        *_build_elk_keyword_clauses(input_data.keyword),
                    ]
                }
            },
            aggs={"_index": {"terms": {"field": "_index", "size": 50}}},
            size=0,
            track_total_hits=True,
        )
        buckets = response.get("aggregations", {}).get("_index", {}).get("buckets", [])
        return [bucket["key"] for bucket in buckets if bucket["doc_count"] > 0]


class SplunkQueryBackend:
    backend_name = "Splunk"

    @classmethod
    def execute_structured_query(cls, input_data: AdaptiveQueryInput) -> BackendQueryResult:
        service = SplunkClient.get_service()
        start_time, end_time = parse_time_range(input_data.time_range_start, input_data.time_range_end)

        search_query = f"search index=\"{input_data.index_name}\""
        for field, value in input_data.filters.items():
            if isinstance(value, list):
                or_clause = " OR ".join(f'{field}=\"{item}\"' for item in value)
                search_query += f" ({or_clause})"
            else:
                search_query += f" {field}=\"{value}\""

        job = _create_and_wait_splunk_job(service, search_query, start_time, end_time)
        total_hits = int(job["eventCount"])
        aggregation_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)

        return BackendQueryResult(
            backend=cls.backend_name,
            index_name=input_data.index_name,
            total_hits=total_hits,
            aggregation_fields=aggregation_fields,
            statistics=_fetch_splunk_top_stats(service, search_query, start_time, end_time, aggregation_fields)
            if total_hits > 0
            else [],
            raw_records=_fetch_splunk_records(job, SAMPLE_THRESHOLD) if total_hits > 0 else [],
        )

    @classmethod
    def execute_keyword_query(cls, input_data: KeywordSearchInput) -> BackendQueryResult:
        service = SplunkClient.get_service()
        start_time, end_time = parse_time_range(input_data.time_range_start, input_data.time_range_end)

        effective_index = input_data.index_name or "*"
        search_query = f"search index=\"{effective_index}\" ({_build_splunk_keyword_clause(input_data.keyword)})"
        job = _create_and_wait_splunk_job(service, search_query, start_time, end_time)
        total_hits = int(job["eventCount"])

        index_distribution: dict[str, int] = {}
        if total_hits > 0:
            stats_query = f"{search_query} | stats count by index"
            oneshot = service.jobs.oneshot(stats_query, earliest_time=start_time, latest_time=end_time, output_mode="json")
            reader = JSONResultsReader(oneshot)
            for item in reader:
                if isinstance(item, dict) and "index" in item and "count" in item:
                    index_distribution[item["index"]] = int(item["count"])

        if input_data.index_name and input_data.index_name not in index_distribution:
            index_distribution[input_data.index_name] = total_hits

        aggregation_fields = get_default_agg_fields(input_data.index_name) if input_data.index_name else []
        statistics = (
            _fetch_splunk_top_stats(service, search_query, start_time, end_time, aggregation_fields)
            if total_hits > 0 and aggregation_fields
            else []
        )

        return BackendQueryResult(
            backend=cls.backend_name,
            index_name=input_data.index_name or effective_index,
            total_hits=total_hits,
            aggregation_fields=aggregation_fields,
            statistics=statistics,
            raw_records=_fetch_splunk_records(job, SAMPLE_THRESHOLD) if total_hits > 0 else [],
            index_distribution=index_distribution,
        )

    @classmethod
    def discover_keyword_hit_indices(cls, input_data: KeywordSearchInput, indices: list[str]) -> list[str]:
        if not indices:
            return []

        service = SplunkClient.get_service()
        start_time, end_time = parse_time_range(input_data.time_range_start, input_data.time_range_end)
        index_clause = " OR ".join(f'index=\"{index}\"' for index in indices)
        search_query = f"search ({index_clause}) ({_build_splunk_keyword_clause(input_data.keyword)}) | stats count by index"

        oneshot = service.jobs.oneshot(search_query, earliest_time=start_time, latest_time=end_time, output_mode="json")
        reader = JSONResultsReader(oneshot)
        hit_indices: list[str] = []
        for item in reader:
            if isinstance(item, dict) and "index" in item and "count" in item and int(item["count"]) > 0:
                hit_indices.append(item["index"])
        return hit_indices
