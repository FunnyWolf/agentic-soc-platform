from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from splunklib.results import JSONResultsReader

from PLUGINS.ELK.client import ELKClient
from PLUGINS.SIEM.data_extractors import (
    create_and_wait_splunk_job,
    extract_elk_records,
    extract_elk_stats,
    fetch_splunk_records,
    fetch_splunk_top_stats,
    get_nested_value,
)
from PLUGINS.SIEM.models import (
    AdaptiveQueryInput,
    DiscoveredFieldInfo,
    DiscoverIndexFieldsOutput,
    FieldStat,
    KeywordSearchInput,
    SAMPLE_THRESHOLD,
)
from PLUGINS.SIEM.query_builders import (
    build_elk_keyword_clauses,
    build_safe_aggs,
    build_splunk_keyword_clause,
    build_time_range_clause,
    parse_time_range,
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


class ELKQueryBackend:
    backend_name: Literal["ELK", "Splunk"] = "ELK"

    @classmethod
    def execute_structured_query(cls, input_data: AdaptiveQueryInput) -> BackendQueryResult:
        client = ELKClient.get_client()
        aggregation_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)

        must_clauses: list[dict[str, Any]] = [
            build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end)
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
            aggs=build_safe_aggs(aggregation_fields, input_data.index_name),
            size=SAMPLE_THRESHOLD,
            track_total_hits=True,
        )

        return BackendQueryResult(
            backend=cls.backend_name,
            index_name=input_data.index_name,
            total_hits=response["hits"]["total"]["value"],
            aggregation_fields=aggregation_fields,
            statistics=extract_elk_stats(response, aggregation_fields),
            raw_records=extract_elk_records(response["hits"]["hits"]),
        )

    @classmethod
    def execute_keyword_query(cls, input_data: KeywordSearchInput) -> BackendQueryResult:
        client = ELKClient.get_client()
        effective_index = input_data.index_name or "*"
        aggregation_fields = get_default_agg_fields(input_data.index_name) if input_data.index_name else []

        query_body = {
            "bool": {
                "must": [
                    build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end),
                    *build_elk_keyword_clauses(input_data.keyword),
                ]
            }
        }

        aggs = {"_index": {"terms": {"field": "_index", "size": 50}}}
        if aggregation_fields:
            aggs.update(build_safe_aggs(aggregation_fields, effective_index))

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
            statistics=extract_elk_stats(response, aggregation_fields),
            raw_records=extract_elk_records(response["hits"]["hits"], include_index=True),
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
                        build_time_range_clause(
                            input_data.time_field,
                            input_data.time_range_start,
                            input_data.time_range_end,
                        ),
                        *build_elk_keyword_clauses(input_data.keyword),
                    ]
                }
            },
            aggs={"_index": {"terms": {"field": "_index", "size": 50}}},
            size=0,
            track_total_hits=True,
        )
        buckets = response.get("aggregations", {}).get("_index", {}).get("buckets", [])
        return [bucket["key"] for bucket in buckets if bucket["doc_count"] > 0]

    @classmethod
    def discover_index_fields(cls, index_name: str) -> DiscoverIndexFieldsOutput:
        from PLUGINS.SIEM.query_builders import get_elk_field_types

        field_types = get_elk_field_types(index_name)
        if not field_types:
            return DiscoverIndexFieldsOutput(
                backend=cls.backend_name, index_name=index_name, total_fields=0, fields=[],
            )

        all_fields = [f for f in field_types if not f.startswith("_")]

        client = ELKClient.get_client()
        response = client.search(
            index=index_name, query={"match_all": {}}, size=10000,
            request_timeout=60,
        )
        hits = response.get("hits", {}).get("hits", [])

        field_values: dict[str, list] = {}
        for hit in hits:
            source = hit.get("_source", {})
            for field_name in all_fields:
                if len(field_values.get(field_name, [])) >= 5:
                    continue
                value = get_nested_value(source, field_name)
                if value is None:
                    continue
                str_value = str(value) if not isinstance(value, str) else value
                if field_name not in field_values:
                    field_values[field_name] = []
                if str_value not in field_values[field_name]:
                    field_values[field_name].append(str_value)

        discovered = [
            DiscoveredFieldInfo(
                name=f, type=field_types[f], sample_values=field_values.get(f, []),
            )
            for f in all_fields
        ]

        return DiscoverIndexFieldsOutput(
            backend=cls.backend_name,
            index_name=index_name,
            total_fields=len(discovered),
            fields=discovered,
        )


class SplunkQueryBackend:
    backend_name: Literal["ELK", "Splunk"] = "Splunk"

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

        job = create_and_wait_splunk_job(service, search_query, start_time, end_time)
        total_hits = int(job["eventCount"])
        aggregation_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)

        return BackendQueryResult(
            backend=cls.backend_name,
            index_name=input_data.index_name,
            total_hits=total_hits,
            aggregation_fields=aggregation_fields,
            statistics=fetch_splunk_top_stats(service, search_query, start_time, end_time, aggregation_fields)
            if total_hits > 0
            else [],
            raw_records=fetch_splunk_records(job, SAMPLE_THRESHOLD) if total_hits > 0 else [],
        )

    @classmethod
    def execute_keyword_query(cls, input_data: KeywordSearchInput) -> BackendQueryResult:
        service = SplunkClient.get_service()
        start_time, end_time = parse_time_range(input_data.time_range_start, input_data.time_range_end)

        effective_index = input_data.index_name or "*"
        search_query = f"search index=\"{effective_index}\" ({build_splunk_keyword_clause(input_data.keyword)})"
        job = create_and_wait_splunk_job(service, search_query, start_time, end_time)
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
            fetch_splunk_top_stats(service, search_query, start_time, end_time, aggregation_fields)
            if total_hits > 0 and aggregation_fields
            else []
        )

        return BackendQueryResult(
            backend=cls.backend_name,
            index_name=input_data.index_name or effective_index,
            total_hits=total_hits,
            aggregation_fields=aggregation_fields,
            statistics=statistics,
            raw_records=fetch_splunk_records(job, SAMPLE_THRESHOLD) if total_hits > 0 else [],
            index_distribution=index_distribution,
        )

    @classmethod
    def discover_keyword_hit_indices(cls, input_data: KeywordSearchInput, indices: list[str]) -> list[str]:
        if not indices:
            return []

        service = SplunkClient.get_service()
        start_time, end_time = parse_time_range(input_data.time_range_start, input_data.time_range_end)
        index_clause = " OR ".join(f'index=\"{index}\"' for index in indices)
        search_query = f"search ({index_clause}) ({build_splunk_keyword_clause(input_data.keyword)}) | stats count by index"

        oneshot = service.jobs.oneshot(search_query, earliest_time=start_time, latest_time=end_time, output_mode="json")
        reader = JSONResultsReader(oneshot)
        hit_indices: list[str] = []
        for item in reader:
            if isinstance(item, dict) and "index" in item and "count" in item and int(item["count"]) > 0:
                hit_indices.append(item["index"])
        return hit_indices

    @classmethod
    def discover_index_fields(cls, index_name: str) -> DiscoverIndexFieldsOutput:
        service = SplunkClient.get_service()
        summary_query = f'search index="{index_name}" | head 10000 | fieldsummary maxvals=5'
        oneshot = service.jobs.oneshot(summary_query, output_mode="json")
        reader = JSONResultsReader(oneshot)

        skip_fields = {"_time", "_raw", "_indextime", "_cd", "_serial", "_bkt", "_si",
                       "splunk_server", "host", "source", "sourcetype", "index",
                       "linecount", "punct", "splunk_server_group", "timeendpos", "timestartpos"}

        discovered: list[DiscoveredFieldInfo] = []
        for item in reader:
            if not isinstance(item, dict) or "field" not in item:
                continue
            fname = item["field"]
            if fname in skip_fields or fname.startswith("date_"):
                continue

            count = int(item.get("count", 0))
            numeric_count = int(item.get("numeric_count", 0))
            if count > 0 and numeric_count / count > 0.8:
                ftype = "long"
            else:
                ftype = "keyword"

            sample_values: list = []
            raw_values = item.get("values", "")
            if raw_values:
                try:
                    parsed = json.loads(raw_values)
                    if isinstance(parsed, list):
                        for entry in parsed:
                            val = entry.get("value") if isinstance(entry, dict) else entry
                            if val is not None and ftype == "long":
                                try:
                                    val = int(val)
                                except (ValueError, TypeError):
                                    try:
                                        val = float(val)
                                    except (ValueError, TypeError):
                                        pass
                            sample_values.append(val)
                except (json.JSONDecodeError, TypeError):
                    pass

            discovered.append(DiscoveredFieldInfo(
                name=fname, type=ftype, sample_values=sample_values,
            ))

        return DiscoverIndexFieldsOutput(
            backend=cls.backend_name,
            index_name=index_name,
            total_fields=len(discovered),
            fields=discovered,
        )
