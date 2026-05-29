from __future__ import annotations

import json
import time
from typing import Any

from splunklib.results import JSONResultsReader

from PLUGINS.SIEM.models import FieldStat, SAMPLE_COUNT


def extract_elk_records(hits: list[dict[str, Any]], include_index: bool = False) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for hit in hits:
        record = hit["_source"].copy() if include_index else hit["_source"]
        if include_index:
            record["_index"] = hit["_index"]
        records.append(record)
    return records


def extract_elk_stats(response: dict[str, Any], agg_fields: list[str]) -> list[FieldStat]:
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


def clean_splunk_record(log: dict[str, Any]) -> dict[str, Any]:
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


def fetch_splunk_records(job, count: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    results = job.results(count=count, output_mode="json")
    for result in results:
        payload = json.loads(result)
        for log in payload.get("results", []):
            records.append(clean_splunk_record(log))
    return records


def fetch_splunk_top_stats(service, search_query: str, start_time: float, end_time: float, agg_fields: list[str]) -> list[FieldStat]:
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


def create_and_wait_splunk_job(service, search_query: str, start_time: float, end_time: float):
    job = service.jobs.create(search_query, earliest_time=start_time, latest_time=end_time, exec_mode="normal")
    while not job.is_done():
        time.sleep(0.2)
    return job


def get_nested_value(source: dict[str, Any], field_name: str) -> Any:
    parts = field_name.split(".")
    current = source
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current
