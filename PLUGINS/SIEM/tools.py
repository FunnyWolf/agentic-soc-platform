import json
import time
from datetime import datetime, timezone
from typing import List

from splunklib.results import JSONResultsReader

from PLUGINS.ELK.client import ELKClient
from PLUGINS.SIEM.models import (
    SchemaExplorerInput,
    AdaptiveQueryInput,
    KeywordSearchInput,
    AdaptiveQueryOutput,
    KeywordSearchOutput,
    FieldStat,
    SUMMARY_THRESHOLD,
    SAMPLE_THRESHOLD, SAMPLE_COUNT
)
from PLUGINS.SIEM.registry import _load_yaml_configs, get_default_agg_fields, get_backend_type
from PLUGINS.Splunk.client import SplunkClient


def get_indices_by_backend() -> dict:
    registry = _load_yaml_configs()
    result = {"ELK": [], "Splunk": []}
    for idx_name, idx_info in registry.items():
        if idx_info.backend in result:
            result[idx_info.backend].append(idx_name)
    return result


class SIEMToolKit(object):

    @classmethod
    def explore_schema(cls, input_data: SchemaExplorerInput = SchemaExplorerInput(target_index=None)):
        """
        Explore available SIEM indices and their field schemas.

        This tool helps agents discover what data sources are available and what fields they contain.
        It supports two modes based on the target_index parameter in SchemaExplorerInput:
        1. List all indices (when target_index is None)
        2. Get detailed field information for a specific index

        See SchemaExplorerInput for detailed parameter documentation.

        Raises:
            ValueError: If the specified target_index is not found in the registry.

        Example Usage by Agent:
            # List all indices
            explore_schema()

            # Get details on "logs-security" index
            explore_schema(SchemaExplorerInput(target_index="logs-security"))
        """
        if not input_data.target_index:
            registry = _load_yaml_configs()
            result = [
                {"name": k, "description": v.description}
                for k, v in registry.items()
            ]
            return result

        registry = _load_yaml_configs()
        if input_data.target_index not in registry:
            raise ValueError(f"Index {input_data.target_index} not found.")

        idx_info = registry[input_data.target_index]
        result = [f.model_dump() for f in idx_info.fields]
        return result

    @classmethod
    def execute_adaptive_query(cls, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        """
        Execute adaptive queries against SIEM backends (ELK or Splunk) with intelligent response formatting.

        This tool executes queries with automatic backend detection and response optimization:
        - Automatically adjusts response format based on result volume:
            * Full logs: Complete log records (for < 20 results)
            * Sample: Statistics + sample records (for 20-1000 results)
            * Summary: Statistics only (for > 1000 results)
        - Provides top-N statistics for specified aggregation fields
        - Handles time range filtering with UTC ISO8601 timestamps

        Raises:
            ValueError: If time format is invalid or backend is unsupported
            ConnectionError: If SIEM backend is unreachable

        Example Usage by Agent:
            # Query security logs from last hour
            input_data = AdaptiveQueryInput(
                index_name="logs-security",
                time_range_start="2026-02-04T06:00:00Z",
                time_range_end="2026-02-04T07:00:00Z",
                filters={"event.outcome": "failure"},
                aggregation_fields=["event.action", "user.name"]
            )
            result = execute_adaptive_query(input_data)

            # Agent can then analyze result.statistics for patterns
            # and if needed, drill down with result.records
        """
        backend = get_backend_type(input_data.index_name)

        if backend == "ELK":
            result = cls._execute_elk(input_data)
            return result
        elif backend == "Splunk":
            result = cls._execute_splunk(input_data)
            return result
        else:
            raise ValueError(f"Unsupported backend: {backend}")

    @classmethod
    def keyword_search(cls, input_data: KeywordSearchInput) -> List[KeywordSearchOutput]:
        """
        Execute keyword-based search across SIEM backends with intelligent response formatting.

        This tool performs full-text search using a keyword across all fields (or specified index):
        - Supports searching by IP, hostname, username, or any arbitrary string
        - When index_name is not specified, searches BOTH ELK and Splunk backends and returns results from each
        - Applies the same adaptive response strategy as execute_adaptive_query:
            * Full logs: < 20 results
            * Sample: 20-1000 results (statistics + samples)
            * Summary: > 1000 results (statistics only)
        - Provides top-N statistics for specified aggregation fields
        - Handles time range filtering with UTC ISO8601 timestamps

        Raises:
            ValueError: If time format is invalid or backend is unsupported
            ConnectionError: If SIEM backend is unreachable

        Example Usage by Agent:
            # Search for an IP across all indices (returns results from both ELK and Splunk)
            input_data = KeywordSearchInput(
                keyword="192.168.1.100",
                time_range_start="2026-02-04T06:00:00Z",
                time_range_end="2026-02-04T07:00:00Z",
                aggregation_fields=["event.action", "source.ip"]
            )
            result = keyword_search(input_data)

            # Search for hostname in specific index
            input_data = KeywordSearchInput(
                keyword="DESKTOP-ABC123",
                time_range_start="2026-02-04T06:00:00Z",
                time_range_end="2026-02-04T07:00:00Z",
                index_name="logs-endpoint"
            )
            result = keyword_search(input_data)
        """
        if input_data.index_name:
            backend = get_backend_type(input_data.index_name)
            if backend == "ELK":
                return [cls._keyword_search_elk(input_data)]
            elif backend == "Splunk":
                return [cls._keyword_search_splunk(input_data)]
            else:
                raise ValueError(f"Unsupported backend: {backend}")

        indices_by_backend = get_indices_by_backend()
        results = []

        elk_indices = indices_by_backend.get("ELK", [])
        if elk_indices:
            hit_indices = cls._discover_elk_hit_indices(input_data, elk_indices)
            for idx_name in hit_indices:
                modified_input = KeywordSearchInput(
                    keyword=input_data.keyword,
                    time_range_start=input_data.time_range_start,
                    time_range_end=input_data.time_range_end,
                    time_field=input_data.time_field,
                    index_name=idx_name
                )
                result = cls._keyword_search_elk(modified_input)
                result.backend = "ELK"
                results.append(result)

        splunk_indices = indices_by_backend.get("Splunk", [])
        if splunk_indices:
            hit_indices = cls._discover_splunk_hit_indices(input_data, splunk_indices)
            for idx_name in hit_indices:
                modified_input = KeywordSearchInput(
                    keyword=input_data.keyword,
                    time_range_start=input_data.time_range_start,
                    time_range_end=input_data.time_range_end,
                    time_field=input_data.time_field,
                    index_name=idx_name
                )
                result = cls._keyword_search_splunk(modified_input)
                result.backend = "Splunk"
                results.append(result)

        return results

    @classmethod
    def _build_time_range_clause(cls, time_field: str, time_range_start: str, time_range_end: str) -> dict:
        return {
            "range": {
                time_field: {
                    "gte": time_range_start,
                    "lt": time_range_end
                }
            }
        }

    @classmethod
    def _extract_elk_records(cls, hits: list, include_index: bool = False) -> list[dict]:
        records = []
        for hit in hits:
            record = hit["_source"].copy() if include_index else hit["_source"]
            if include_index:
                record["_index"] = hit["_index"]
            records.append(record)
        return records

    @classmethod
    def _extract_elk_stats(cls, response: dict, agg_fields: list) -> list[FieldStat]:
        stats_output = []
        if "aggregations" not in response:
            return stats_output

        for field in agg_fields:
            agg_key = f"{field}.keyword" if f"{field}.keyword" in response["aggregations"] else field
            if agg_key in response["aggregations"]:
                buckets = response["aggregations"][agg_key]["buckets"]
                if buckets:
                    stats_output.append(FieldStat(
                        field_name=field,
                        top_values={b["key"]: b["doc_count"] for b in buckets}
                    ))
        return stats_output

    @classmethod
    def _parse_time_range(cls, time_range_start: str, time_range_end: str) -> tuple[float, float]:
        utc_format = "%Y-%m-%dT%H:%M:%SZ"
        try:
            dt_start = datetime.strptime(time_range_start, utc_format).replace(tzinfo=timezone.utc)
            dt_end = datetime.strptime(time_range_end, utc_format).replace(tzinfo=timezone.utc)
            return dt_start.timestamp(), dt_end.timestamp()
        except ValueError:
            raise ValueError("Invalid UTC format.")

    @classmethod
    def _clean_splunk_record(cls, log: dict) -> dict:
        clean_record = {}
        for k, v in log.items():
            if not k.startswith("_") and k not in ["_raw", "splunk_server", "host", "source", "sourcetype"]:
                clean_record[k] = v
        if "_time" in log:
            clean_record["@timestamp"] = log["_time"]
        if "_raw" in log:
            try:
                raw_parsed = json.loads(log["_raw"])
                if isinstance(raw_parsed, dict):
                    for rk, rv in raw_parsed.items():
                        if rk not in clean_record:
                            clean_record[rk] = rv
            except (json.JSONDecodeError, TypeError):
                pass
        return clean_record

    @classmethod
    def _fetch_splunk_records(cls, job, count: int) -> list[dict]:
        records = []
        results = job.results(count=count, output_mode="json")
        for result in results:
            result = json.loads(result)
            for log in result.get("results", []):
                records.append(cls._clean_splunk_record(log))
        return records

    @classmethod
    def _fetch_splunk_top_stats(cls, service, search_query: str, t_start: float, t_end: float, agg_fields: list) -> list[FieldStat]:
        stats_output = []
        for field in agg_fields:
            stats_spl = f"{search_query} | top limit={SAMPLE_COUNT} {field}"
            rr = service.jobs.oneshot(stats_spl, earliest_time=t_start, latest_time=t_end, output_mode="json")
            reader = JSONResultsReader(rr)
            top_vals = {}
            for item in reader:
                if isinstance(item, dict) and field in item:
                    top_vals[item[field]] = int(item['count'])
            if top_vals:
                stats_output.append(FieldStat(field_name=field, top_values=top_vals))
        return stats_output

    @classmethod
    def _create_and_wait_splunk_job(cls, service, search_query: str, t_start: float, t_end: float):
        job = service.jobs.create(search_query, earliest_time=t_start, latest_time=t_end, exec_mode="normal")
        while not job.is_done():
            time.sleep(0.2)
        return job

    @classmethod
    def _execute_elk(cls, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        client = ELKClient.get_client()

        must_clauses = [cls._build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end)]
        for k, v in input_data.filters.items():
            if isinstance(v, list):
                must_clauses.append({"terms": {k: v}})
            else:
                must_clauses.append({"term": {k: v}})

        query_body = {"bool": {"must": must_clauses}}
        agg_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)
        aggs_dsl = cls._build_safe_aggs(agg_fields, input_data.index_name)

        response = client.search(
            index=input_data.index_name, query=query_body, aggs=aggs_dsl, size=SAMPLE_COUNT, track_total_hits=True
        )

        total_hits = response["hits"]["total"]["value"]
        hits_data = cls._extract_elk_records(response["hits"]["hits"])
        stats_output = cls._extract_elk_stats(response, agg_fields)

        return cls._apply_funnel_strategy(total_hits, stats_output, hits_data, input_data, client, query_body)

    @classmethod
    def _keyword_search_elk(cls, input_data: KeywordSearchInput) -> KeywordSearchOutput:
        client = ELKClient.get_client()
        effective_index = input_data.index_name or "*"

        must_clauses = [
            cls._build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end),
            {"query_string": {"query": input_data.keyword, "default_operator": "AND"}}
        ]
        query_body = {"bool": {"must": must_clauses}}

        aggs_dsl = {"_index": {"terms": {"field": "_index", "size": 50}}}
        agg_fields = []
        if input_data.index_name:
            agg_fields = get_default_agg_fields(input_data.index_name)
            field_aggs = cls._build_safe_aggs(agg_fields, input_data.index_name)
            aggs_dsl.update(field_aggs)

        response = client.search(
            index=effective_index, query=query_body, aggs=aggs_dsl, size=SAMPLE_COUNT, track_total_hits=True
        )

        total_hits = response["hits"]["total"]["value"]
        hits_data = cls._extract_elk_records(response["hits"]["hits"], include_index=True)

        index_distribution = {}
        if "aggregations" in response and "_index" in response["aggregations"]:
            buckets = response["aggregations"]["_index"]["buckets"]
            index_distribution = {b["key"]: b["doc_count"] for b in buckets}

        stats_output = cls._extract_elk_stats(response, agg_fields)
        status = cls._resolve_funnel_status(total_hits)
        idx_count = len(index_distribution)

        if status == "summary":
            return KeywordSearchOutput(
                status=status, total_hits=total_hits, index_distribution=index_distribution,
                statistics=stats_output, records=[],
                message=f"Found {total_hits} events across {idx_count} index(es). Showing statistics only."
            )
        elif status == "sample":
            return KeywordSearchOutput(
                status=status, total_hits=total_hits, index_distribution=index_distribution,
                statistics=stats_output, records=hits_data,
                message=f"Found {total_hits} events across {idx_count} index(es). Showing statistics + samples."
            )
        else:
            final_records = hits_data
            if total_hits > SAMPLE_COUNT:
                resp = client.search(index=effective_index, query=query_body, size=SAMPLE_THRESHOLD)
                final_records = cls._extract_elk_records(resp["hits"]["hits"], include_index=True)
            return KeywordSearchOutput(
                status=status, total_hits=total_hits, index_distribution=index_distribution,
                statistics=stats_output, records=final_records,
                message=f"Found {total_hits} events. Returning full logs."
            )

    @classmethod
    def _execute_splunk(cls, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        service = SplunkClient.get_service()
        t_start, t_end = cls._parse_time_range(input_data.time_range_start, input_data.time_range_end)

        search_query = f"search index=\"{input_data.index_name}\""
        for k, v in input_data.filters.items():
            if isinstance(v, list):
                or_clause = " OR ".join([f'{k}="{val}"' for val in v])
                search_query += f" ({or_clause})"
            else:
                search_query += f" {k}=\"{v}\""

        job = cls._create_and_wait_splunk_job(service, search_query, t_start, t_end)
        total_hits = int(job["eventCount"])

        agg_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)
        stats_output = cls._fetch_splunk_top_stats(service, search_query, t_start, t_end, agg_fields) if total_hits > 0 else []
        hits_data = cls._fetch_splunk_records(job, SAMPLE_COUNT) if total_hits > 0 else []

        status = cls._resolve_funnel_status(total_hits)
        if status == "summary":
            return AdaptiveQueryOutput(
                status=status, total_hits=total_hits, statistics=stats_output, records=[],
                message=f"Found {total_hits} events in Splunk. Showing statistics only."
            )
        elif status == "sample":
            return AdaptiveQueryOutput(
                status=status, total_hits=total_hits, statistics=stats_output, records=hits_data,
                message=f"Found {total_hits} events in Splunk. Showing statistics + samples."
            )
        else:
            final_records = cls._fetch_splunk_records(job, SAMPLE_THRESHOLD)
            return AdaptiveQueryOutput(
                status=status, total_hits=total_hits, statistics=stats_output, records=final_records,
                message="Low volume. Returning full logs."
            )

    @classmethod
    def _keyword_search_splunk(cls, input_data: KeywordSearchInput) -> KeywordSearchOutput:
        service = SplunkClient.get_service()
        t_start, t_end = cls._parse_time_range(input_data.time_range_start, input_data.time_range_end)

        effective_index = input_data.index_name or "*"
        search_query = f"search index=\"{effective_index}\" {input_data.keyword}"

        job = cls._create_and_wait_splunk_job(service, search_query, t_start, t_end)
        total_hits = int(job["eventCount"])

        index_distribution = {}
        if total_hits > 0:
            index_stats_query = f"{search_query} | stats count by index"
            rr = service.jobs.oneshot(index_stats_query, earliest_time=t_start, latest_time=t_end, output_mode="json")
            reader = JSONResultsReader(rr)
            for item in reader:
                if isinstance(item, dict) and "index" in item and "count" in item:
                    index_distribution[item["index"]] = int(item["count"])

        agg_fields = []
        stats_output = []
        if input_data.index_name:
            agg_fields = get_default_agg_fields(input_data.index_name)
            if total_hits > 0:
                stats_output = cls._fetch_splunk_top_stats(service, search_query, t_start, t_end, agg_fields)

        hits_data = cls._fetch_splunk_records(job, SAMPLE_COUNT) if total_hits > 0 else []

        status = cls._resolve_funnel_status(total_hits)
        idx_count = len(index_distribution)

        if status == "summary":
            return KeywordSearchOutput(
                status=status, total_hits=total_hits, index_distribution=index_distribution,
                statistics=stats_output, records=[],
                message=f"Found {total_hits} events across {idx_count} index(es) in Splunk. Showing statistics only."
            )
        elif status == "sample":
            return KeywordSearchOutput(
                status=status, total_hits=total_hits, index_distribution=index_distribution,
                statistics=stats_output, records=hits_data,
                message=f"Found {total_hits} events across {idx_count} index(es) in Splunk. Showing statistics + samples."
            )
        else:
            final_records = cls._fetch_splunk_records(job, SAMPLE_THRESHOLD)
            return KeywordSearchOutput(
                status=status, total_hits=total_hits, index_distribution=index_distribution,
                statistics=stats_output, records=final_records,
                message=f"Found {total_hits} events in Splunk. Returning full logs."
            )

    @classmethod
    def _discover_elk_hit_indices(cls, input_data: KeywordSearchInput, elk_indices: list) -> list:
        client = ELKClient.get_client()
        index_pattern = ",".join(elk_indices)

        must_clauses = [
            cls._build_time_range_clause(input_data.time_field, input_data.time_range_start, input_data.time_range_end),
            {"query_string": {"query": input_data.keyword, "default_operator": "AND"}}
        ]
        query_body = {"bool": {"must": must_clauses}}
        aggs_dsl = {"_index": {"terms": {"field": "_index", "size": 50}}}

        response = client.search(
            index=index_pattern, query=query_body, aggs=aggs_dsl, size=0, track_total_hits=True
        )

        hit_indices = []
        if "aggregations" in response and "_index" in response["aggregations"]:
            buckets = response["aggregations"]["_index"]["buckets"]
            hit_indices = [b["key"] for b in buckets if b["doc_count"] > 0]

        return hit_indices

    @classmethod
    def _discover_splunk_hit_indices(cls, input_data: KeywordSearchInput, splunk_indices: list) -> list:
        service = SplunkClient.get_service()
        t_start, t_end = cls._parse_time_range(input_data.time_range_start, input_data.time_range_end)

        index_clause = " OR ".join([f'index="{idx}"' for idx in splunk_indices])
        search_query = f"search ({index_clause}) {input_data.keyword} | stats count by index"

        rr = service.jobs.oneshot(search_query, earliest_time=t_start, latest_time=t_end, output_mode="json")
        reader = JSONResultsReader(rr)

        hit_indices = []
        for item in reader:
            if isinstance(item, dict) and "index" in item and "count" in item:
                if int(item["count"]) > 0:
                    hit_indices.append(item["index"])

        return hit_indices

    @classmethod
    def _build_safe_aggs(cls, agg_fields, index_name="*"):
        client = ELKClient.get_client()

        field_types = {}
        try:
            mapping_resp = client.indices.get_mapping(index=index_name)
            for idx_name, idx_mapping in mapping_resp.items():
                properties = idx_mapping.get("mappings", {}).get("properties", {})
                cls._extract_field_types(properties, "", field_types)
        except Exception:
            pass

        safe_aggs = {}
        for f in agg_fields:
            field_type = field_types.get(f)

            if field_type == "text":
                agg_field = f"{f}.keyword"
                agg_key = f"{f}.keyword"
            elif field_type in (None,):
                agg_field = f"{f}.keyword"
                agg_key = f"{f}.keyword"
            else:
                agg_field = f
                agg_key = f

            safe_aggs[agg_key] = {"terms": {"field": agg_field, "size": 5}}

        return safe_aggs

    @classmethod
    def _extract_field_types(cls, properties: dict, prefix: str, result: dict):
        for field_name, field_info in properties.items():
            full_name = f"{prefix}{field_name}" if prefix else field_name

            if "type" in field_info:
                result[full_name] = field_info["type"]

            if "properties" in field_info:
                cls._extract_field_types(field_info["properties"], f"{full_name}.", result)

    @classmethod
    def _apply_funnel_strategy(cls, total, stats, initial_hits, input_data, client, query_body, index_name=None):
        effective_index = index_name if index_name is not None else input_data.index_name
        status = cls._resolve_funnel_status(total)
        if status == "summary":
            return AdaptiveQueryOutput(
                status="summary", total_hits=total, statistics=stats, records=[],
                message=f"Matches {total} records (ELK). High volume."
            )
        if status == "sample":
            return AdaptiveQueryOutput(
                status="sample", total_hits=total, statistics=stats, records=initial_hits,
                message=f"Matches {total} records (ELK). Showing samples."
            )
        final_recs = initial_hits
        if total > SAMPLE_COUNT:
            resp = client.search(index=effective_index, query=query_body, size=SAMPLE_THRESHOLD)
            final_recs = [h["_source"] for h in resp["hits"]["hits"]]
        return AdaptiveQueryOutput(
            status="full", total_hits=total, statistics=stats, records=final_recs,
            message="Low volume. Returning full logs."
        )

    @classmethod
    def _resolve_funnel_status(cls, total_hits: int) -> str:
        if total_hits > SUMMARY_THRESHOLD:
            return "summary"
        if SAMPLE_THRESHOLD < total_hits <= SUMMARY_THRESHOLD:
            return "sample"
        return "full"
