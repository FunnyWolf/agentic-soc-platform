from __future__ import annotations

import json
import re
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
    ESQLQueryInput,
    FieldStat,
    KeywordSearchInput,
    SAMPLE_THRESHOLD,
    SPLQueryInput,
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


def _build_filter_must_clauses(time_field: str, time_start: str, time_end: str, filters: dict) -> list[dict[str, Any]]:
    clauses: list[dict[str, Any]] = [build_time_range_clause(time_field, time_start, time_end)]
    for field, value in filters.items():
        clauses.append({"terms": {field: value}} if isinstance(value, list) else {"term": {field: value}})
    return clauses


def _extract_index_distribution(response: dict, index_name: str | None) -> dict[str, int]:
    buckets = response.get("aggregations", {}).get("_index", {}).get("buckets", [])
    distribution = {b["key"]: b["doc_count"] for b in buckets}
    if index_name and index_name not in distribution:
        distribution[index_name] = response["hits"]["total"]["value"]
    return distribution


class ELKQueryBackend:
    backend_name: Literal["ELK", "Splunk"] = "ELK"

    @classmethod
    def execute_structured_query(cls, input_data: AdaptiveQueryInput) -> BackendQueryResult:
        must_clauses = _build_filter_must_clauses(input_data.time_field, input_data.time_range_start, input_data.time_range_end, input_data.filters)
        aggregation_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)
        response = cls._search(input_data.index_name, {"bool": {"must": must_clauses}},
                               build_safe_aggs(aggregation_fields, input_data.index_name))
        return BackendQueryResult(
            backend=cls.backend_name, index_name=input_data.index_name,
            total_hits=response["hits"]["total"]["value"],
            aggregation_fields=aggregation_fields,
            statistics=extract_elk_stats(response, aggregation_fields),
            raw_records=extract_elk_records(response["hits"]["hits"]),
        )

    @classmethod
    def execute_keyword_query(cls, input_data: KeywordSearchInput) -> BackendQueryResult:
        effective_index = input_data.index_name or "*"
        aggregation_fields = get_default_agg_fields(input_data.index_name) if input_data.index_name else []

        must_clauses = [
            build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end),
            *build_elk_keyword_clauses(input_data.keyword),
        ]
        aggs: dict[str, Any] = {"_index": {"terms": {"field": "_index", "size": 50}}}
        if aggregation_fields:
            aggs.update(build_safe_aggs(aggregation_fields, effective_index))

        response = cls._search(effective_index, {"bool": {"must": must_clauses}}, aggs)
        index_distribution = _extract_index_distribution(response, input_data.index_name)

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
        must_clauses = [
            build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end),
            *build_elk_keyword_clauses(input_data.keyword),
        ]
        response = cls._search(",".join(indices), {"bool": {"must": must_clauses}},
                               {"_index": {"terms": {"field": "_index", "size": 50}}}, size=0)
        buckets = response.get("aggregations", {}).get("_index", {}).get("buckets", [])
        return [b["key"] for b in buckets if b["doc_count"] > 0]

    @classmethod
    def discover_index_fields(cls, index_name: str, time_start: str | None = None,
                              time_end: str | None = None, doc_limit: int = 10000,
                              max_samples: int = 20) -> DiscoverIndexFieldsOutput:
        from PLUGINS.SIEM.query_builders import get_elk_field_types
        field_types = get_elk_field_types(index_name)
        if not field_types:
            return DiscoverIndexFieldsOutput(backend=cls.backend_name, index_name=index_name, total_fields=0, fields=[])

        all_fields = [f for f in field_types if not f.startswith("_")]
        if time_start and time_end:
            query: dict = {"bool": {"must": [build_time_range_clause("@timestamp", time_start, time_end)]}}
        else:
            query = {"match_all": {}}
        response = cls._search(index_name, query, size=doc_limit, request_timeout=60)
        hits = response.get("hits", {}).get("hits", [])

        field_values: dict[str, list] = {}
        for hit in hits:
            source = hit.get("_source", {})
            for fname in all_fields:
                if len(field_values.get(fname, [])) >= max_samples:
                    continue
                value = get_nested_value(source, fname)
                if value is None:
                    continue
                str_value = str(value) if not isinstance(value, str) else value
                if fname not in field_values:
                    field_values[fname] = []
                if str_value not in field_values[fname]:
                    field_values[fname].append(str_value)

        return DiscoverIndexFieldsOutput(
            backend=cls.backend_name, index_name=index_name,
            total_fields=len(all_fields),
            fields=[DiscoveredFieldInfo(name=f, type=field_types[f], sample_values=field_values.get(f, [])) for f in all_fields],
        )

    @classmethod
    def _search(cls, index: str, query: dict, aggs: dict | None = None, **kwargs) -> dict:
        client = ELKClient.get_client()
        params = {"index": index, "query": query, "size": SAMPLE_THRESHOLD, "track_total_hits": True, **kwargs}
        if aggs:
            params["aggs"] = aggs
        return client.search(**params)

    @classmethod
    def execute_esql_query(cls, input_data: ESQLQueryInput) -> BackendQueryResult:
        client = ELKClient.get_client()
        query = input_data.query

        if input_data.time_range_start and input_data.time_range_end:
            time_clause = (
                f'| WHERE {input_data.time_field} >= "{input_data.time_range_start}"'
                f' AND {input_data.time_field} < "{input_data.time_range_end}"'
            )
            limit_match = re.search(r'\|\s*LIMIT\s+\d+', query, re.IGNORECASE)
            if limit_match:
                query = query[:limit_match.start()] + time_clause + " " + query[limit_match.start():]
            else:
                query = query + " " + time_clause

        if not re.search(r'\|\s*LIMIT\s+\d+', query, re.IGNORECASE):
            query = f"{query} | LIMIT {input_data.limit}"

        response = client.esql.query(query=query)
        body = response.body
        columns = [col["name"] for col in body.get("columns", [])]
        rows = body.get("values", [])
        raw_records = [dict(zip(columns, row)) for row in rows]

        return BackendQueryResult(
            backend="ELK",
            index_name=input_data.index_name or "unknown",
            total_hits=len(raw_records),
            aggregation_fields=[],
            statistics=[],
            raw_records=raw_records,
        )


class SplunkQueryBackend:
    backend_name: Literal["ELK", "Splunk"] = "Splunk"

    @classmethod
    def execute_structured_query(cls, input_data: AdaptiveQueryInput) -> BackendQueryResult:
        search_query = f"search index=\"{input_data.index_name}\""
        for field, value in input_data.filters.items():
            if isinstance(value, list):
                search_query += f" ({' OR '.join(f'{field}=\"{v}\"' for v in value)})"
            else:
                search_query += f" {field}=\"{value}\""

        return cls._execute_and_build(input_data.index_name, search_query,
                                      input_data.time_range_start, input_data.time_range_end,
                                      input_data.aggregation_fields or get_default_agg_fields(input_data.index_name))

    @classmethod
    def execute_keyword_query(cls, input_data: KeywordSearchInput) -> BackendQueryResult:
        effective_index = input_data.index_name or "*"
        search_query = f"search index=\"{effective_index}\" ({build_splunk_keyword_clause(input_data.keyword)})"
        aggregation_fields = get_default_agg_fields(input_data.index_name) if input_data.index_name else []

        result = cls._execute_and_build(input_data.index_name or effective_index, search_query,
                                        input_data.time_range_start, input_data.time_range_end,
                                        aggregation_fields, include_index_dist=True)
        return result

    @classmethod
    def _execute_and_build(
            cls, index_name: str, search_query: str,
            time_start: str, time_end: str,
            aggregation_fields: list[str],
            include_index_dist: bool = False,
    ) -> BackendQueryResult:
        service = SplunkClient.get_service()
        start_time, end_time = parse_time_range(time_start, time_end)
        job = create_and_wait_splunk_job(service, search_query, start_time, end_time)
        total_hits = int(job["eventCount"])

        index_distribution: dict[str, int] = {}
        if include_index_dist and total_hits > 0:
            oneshot = service.jobs.oneshot(
                f"{search_query} | stats count by index",
                earliest_time=start_time, latest_time=end_time, output_mode="json",
            )
            for item in JSONResultsReader(oneshot):
                if isinstance(item, dict) and "index" in item and "count" in item:
                    index_distribution[item["index"]] = int(item["count"])
            if index_name not in index_distribution:
                index_distribution[index_name] = total_hits

        return BackendQueryResult(
            backend=cls.backend_name,
            index_name=index_name,
            total_hits=total_hits,
            aggregation_fields=aggregation_fields,
            statistics=fetch_splunk_top_stats(service, search_query, start_time, end_time, aggregation_fields)
            if total_hits > 0 and aggregation_fields else [],
            raw_records=fetch_splunk_records(job, SAMPLE_THRESHOLD) if total_hits > 0 else [],
            index_distribution=index_distribution,
        )

    @classmethod
    def discover_keyword_hit_indices(cls, input_data: KeywordSearchInput, indices: list[str]) -> list[str]:
        if not indices:
            return []
        service = SplunkClient.get_service()
        start_time, end_time = parse_time_range(input_data.time_range_start, input_data.time_range_end)
        index_clause = " OR ".join(f'index="{i}"' for i in indices)
        search_query = f"search ({index_clause}) ({build_splunk_keyword_clause(input_data.keyword)}) | stats count by index"

        oneshot = service.jobs.oneshot(search_query, earliest_time=start_time, latest_time=end_time, output_mode="json")
        return [item["index"] for item in JSONResultsReader(oneshot)
                if isinstance(item, dict) and "index" in item and "count" in item and int(item["count"]) > 0]

    @classmethod
    def discover_index_fields(cls, index_name: str, time_start: str | None = None,
                              time_end: str | None = None, doc_limit: int = 10000,
                              max_samples: int = 20) -> DiscoverIndexFieldsOutput:
        service = SplunkClient.get_service()
        time_kwargs = {}
        if time_start and time_end:
            start_time, end_time = parse_time_range(time_start, time_end)
            time_kwargs["earliest_time"] = start_time
            time_kwargs["latest_time"] = end_time
        oneshot = service.jobs.oneshot(
            f'search index="{index_name}" | head {doc_limit} | fieldsummary maxvals={max_samples}',
            output_mode="json", **time_kwargs,
        )

        skip_fields = {"_time", "_raw", "_indextime", "_cd", "_serial", "_bkt", "_si",
                       "splunk_server", "host", "source", "sourcetype", "index",
                       "linecount", "punct", "splunk_server_group", "timeendpos", "timestartpos"}

        discovered: list[DiscoveredFieldInfo] = []
        for item in JSONResultsReader(oneshot):
            if not isinstance(item, dict) or "field" not in item:
                continue
            fname = item["field"]
            if fname in skip_fields or fname.startswith("date_"):
                continue

            count = int(item.get("count", 0))
            numeric_count = int(item.get("numeric_count", 0))
            ftype = "long" if count > 0 and numeric_count / count > 0.8 else "keyword"

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

            discovered.append(DiscoveredFieldInfo(name=fname, type=ftype, sample_values=sample_values))

        return DiscoverIndexFieldsOutput(
            backend=cls.backend_name, index_name=index_name,
            total_fields=len(discovered), fields=discovered,
        )

    @classmethod
    def execute_spl_query(cls, input_data: SPLQueryInput) -> BackendQueryResult:
        service = SplunkClient.get_service()
        if input_data.time_range_start and input_data.time_range_end:
            start_time, end_time = parse_time_range(input_data.time_range_start, input_data.time_range_end)
        else:
            start_time, end_time = None, None

        job = create_and_wait_splunk_job(service, input_data.query, start_time, end_time)
        total_hits = int(job["eventCount"])

        return BackendQueryResult(
            backend="Splunk",
            index_name=input_data.index_name or "unknown",
            total_hits=total_hits,
            aggregation_fields=[],
            statistics=[],
            raw_records=fetch_splunk_records(job, input_data.limit) if total_hits > 0 else [],
        )
