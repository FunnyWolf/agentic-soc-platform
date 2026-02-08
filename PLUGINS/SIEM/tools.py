import json
import time
from datetime import datetime, timezone

import splunklib.client
from elasticsearch import Elasticsearch
from splunklib.results import JSONResultsReader

from PLUGINS.SIEM.CONFIG import ELK_HOST, ELK_USER, ELK_PASS, SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASS
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


class ELKClient:
    _instance = None

    @classmethod
    def get_client(cls):
        if cls._instance is None:
            cls._instance = Elasticsearch(
                ELK_HOST,
                basic_auth=(ELK_USER, ELK_PASS),
                verify_certs=False,
                request_timeout=30
            )
        return cls._instance


class SplunkClient:
    """Splunk 连接单例工厂 (新增)"""
    _instance = None

    @classmethod
    def get_service(cls):
        if cls._instance is None:
            cls._instance = splunklib.client.connect(
                host=SPLUNK_HOST,
                port=SPLUNK_PORT,
                username=SPLUNK_USER,
                password=SPLUNK_PASS,
                scheme="https",
                verify=False
            )
        return cls._instance


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
    def keyword_search(cls, input_data: KeywordSearchInput) -> KeywordSearchOutput:
        """
        Execute keyword-based search across SIEM backends with intelligent response formatting.

        This tool performs full-text search using a keyword across all fields (or specified index):
        - Supports searching by IP, hostname, username, or any arbitrary string
        - Automatically searches across all indices when index_name is not specified
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
            # Search for an IP across all indices
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
        effective_index = input_data.index_name or "*"

        if effective_index == "*":
            registry = _load_yaml_configs()
            if not registry:
                raise ValueError("No SIEM indices configured in registry")
            first_index = next(iter(registry.keys()))
            backend = get_backend_type(first_index)
        else:
            backend = get_backend_type(effective_index)

        if backend == "ELK":
            result = cls._keyword_search_elk(input_data)
            return result
        elif backend == "Splunk":
            result = cls._keyword_search_splunk(input_data)
            return result
        else:
            raise ValueError(f"Unsupported backend: {backend}")

    @classmethod
    def _execute_elk(cls, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        client = ELKClient.get_client()
        must_clauses = []
        must_clauses.append({
            "range": {
                input_data.time_field: {
                    "gte": input_data.time_range_start,
                    "lt": input_data.time_range_end
                }
            }
        })
        for k, v in input_data.filters.items():
            must_clauses.append({"term": {k: v}})

        query_body = {"bool": {"must": must_clauses}}

        agg_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)
        aggs_dsl = cls._build_safe_aggs(agg_fields, input_data.index_name)

        response = client.search(
            index=input_data.index_name, query=query_body, aggs=aggs_dsl, size=SAMPLE_COUNT, track_total_hits=True
        )

        total_hits = response["hits"]["total"]["value"]
        hits_data = [hit["_source"] for hit in response["hits"]["hits"]]

        stats_output = []
        if "aggregations" in response:
            for field in agg_fields:
                agg_key = f"{field}.keyword" if f"{field}.keyword" in response["aggregations"] else field
                if agg_key in response["aggregations"]:
                    buckets = response["aggregations"][agg_key]["buckets"]
                    if buckets:
                        stats_output.append(FieldStat(
                            field_name=field,
                            top_values={b["key"]: b["doc_count"] for b in buckets}
                        ))

        return cls._apply_funnel_strategy(total_hits, stats_output, hits_data, input_data, client, query_body)

    @classmethod
    def _execute_splunk(cls, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        service = SplunkClient.get_service()

        try:
            utc_format = "%Y-%m-%dT%H:%M:%SZ"
            dt_start_utc = datetime.strptime(input_data.time_range_start, utc_format).replace(tzinfo=timezone.utc)
            dt_end_utc = datetime.strptime(input_data.time_range_end, utc_format).replace(tzinfo=timezone.utc)

            t_start = dt_start_utc.timestamp()
            t_end = dt_end_utc.timestamp()
        except ValueError:
            raise ValueError("Invalid UTC format.")

        search_query = f"search index=\"{input_data.index_name}\""

        for k, v in input_data.filters.items():
            search_query += f" {k}=\"{v}\""

        job = service.jobs.create(
            search_query,
            earliest_time=t_start,
            latest_time=t_end,
            exec_mode="normal"
        )

        while not job.is_done():
            time.sleep(0.2)

        total_hits = int(job["eventCount"])

        agg_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)
        stats_output = []

        if total_hits > 0:
            # Splunk 获取统计需要额外的开销，这里简化处理：
            # 如果数据量大，我们发一个新的快速统计查询
            # 使用 "| top limit=5 field"
            for field in agg_fields:
                stats_spl = f"{search_query} | top limit={SAMPLE_COUNT} {field}"
                # oneshot is blocking but fast for stats
                rr = service.jobs.oneshot(stats_spl, earliest_time=t_start, latest_time=t_end, output_mode="json")
                reader = JSONResultsReader(rr)
                top_vals = {}
                for item in reader:
                    if isinstance(item, dict) and field in item:
                        top_vals[item[field]] = int(item['count'])
                if top_vals:
                    stats_output.append(FieldStat(field_name=field, top_values=top_vals))

        hits_data = []
        # Splunk 的 result 是扁平的或者带 _raw，我们需要尽量让它看起来像 ELK 的 dict
        if total_hits > 0:
            # 获取前 3 条作为样本
            results = job.results(count=3, output_mode="json")
            for result in results:
                # 清洗 Splunk 的内部字段 (以_开头的)
                result = json.loads(result)
                logs = result["results"]
                clean_record = {}
                for log in logs:
                    log: dict
                    clean_record = {k: v for k, v in log.items() if not k.startswith("_")}
                    # 保留关键的时间字段，映射回 @timestamp 以保持一致性
                    if "_time" in log.keys():
                        clean_record["@timestamp"] = log["_time"]
                hits_data.append(clean_record)

        status = cls._resolve_funnel_status(total_hits)

        if status == "summary":
            msg = f"Found {total_hits} events in Splunk. Showing statistics only."
            final_records = []

        elif status == "sample":
            msg = f"Found {total_hits} events in Splunk. Showing statistics + samples."
            final_records = hits_data

        else:
            msg = "Low volume. Returning full logs."
            # Fetch up to SAMPLE_THRESHOLD
            final_records = []
            results = job.results(count=SAMPLE_THRESHOLD, output_mode="json")
            for result in results:
                result = json.loads(result)
                logs = result["results"]
                clean_record = {}
                for log in logs:
                    log: dict
                    clean_record = {k: v for k, v in log.items() if not k.startswith("_")}
                    # 保留关键的时间字段，映射回 @timestamp 以保持一致性
                    if "_time" in log.keys():
                        clean_record["@timestamp"] = log["_time"]
                final_records.append(clean_record)

        return AdaptiveQueryOutput(
            status=status,
            total_hits=total_hits,
            message=msg,
            statistics=stats_output,
            records=final_records
        )

    @classmethod
    def _keyword_search_elk(cls, input_data: KeywordSearchInput) -> KeywordSearchOutput:
        client = ELKClient.get_client()

        must_clauses = []
        must_clauses.append({
            "range": {
                input_data.time_field: {
                    "gte": input_data.time_range_start,
                    "lt": input_data.time_range_end
                }
            }
        })

        must_clauses.append({
            "query_string": {
                "query": input_data.keyword,
                "default_operator": "AND"
            }
        })

        query_body = {"bool": {"must": must_clauses}}

        effective_index = input_data.index_name or "*"

        aggs_dsl = {}
        aggs_dsl["_index"] = {"terms": {"field": "_index", "size": 50}}

        agg_fields = []
        if input_data.index_name:
            agg_fields = input_data.aggregation_fields
            if not agg_fields:
                agg_fields = get_default_agg_fields(input_data.index_name)

            field_aggs = cls._build_safe_aggs(agg_fields, input_data.index_name)
            aggs_dsl.update(field_aggs)

        response = client.search(
            index=effective_index, query=query_body, aggs=aggs_dsl, size=3, track_total_hits=True
        )

        total_hits = response["hits"]["total"]["value"]
        hits_data = []
        for hit in response["hits"]["hits"]:
            record = hit["_source"].copy()
            record["_index"] = hit["_index"]
            hits_data.append(record)

        index_distribution = {}
        if "aggregations" in response and "_index" in response["aggregations"]:
            buckets = response["aggregations"]["_index"]["buckets"]
            index_distribution = {b["key"]: b["doc_count"] for b in buckets}

        stats_output = []
        if "aggregations" in response and agg_fields:
            for field in agg_fields:
                agg_key = f"{field}.keyword" if f"{field}.keyword" in response["aggregations"] else field
                if agg_key in response["aggregations"]:
                    buckets = response["aggregations"][agg_key]["buckets"]
                    if buckets:
                        stats_output.append(FieldStat(
                            field_name=field,
                            top_values={b["key"]: b["doc_count"] for b in buckets}
                        ))

        status = cls._resolve_funnel_status(total_hits)

        if status == "summary":
            msg = f"Found {total_hits} events across {len(index_distribution)} index(es). Showing statistics only."
            final_records = []
        elif status == "sample":
            msg = f"Found {total_hits} events across {len(index_distribution)} index(es). Showing statistics + samples."
            final_records = hits_data
        else:
            msg = f"Found {total_hits} events. Returning full logs."
            final_records = hits_data
            if total_hits > 3:
                resp = client.search(index=effective_index, query=query_body, size=SAMPLE_THRESHOLD)
                final_records = []
                for hit in resp["hits"]["hits"]:
                    record = hit["_source"].copy()
                    record["_index"] = hit["_index"]
                    final_records.append(record)

        return KeywordSearchOutput(
            status=status,
            total_hits=total_hits,
            message=msg,
            index_distribution=index_distribution,
            statistics=stats_output,
            records=final_records
        )

    @classmethod
    def _keyword_search_splunk(cls, input_data: KeywordSearchInput) -> KeywordSearchOutput:
        service = SplunkClient.get_service()

        try:
            utc_format = "%Y-%m-%dT%H:%M:%SZ"
            dt_start_utc = datetime.strptime(input_data.time_range_start, utc_format).replace(tzinfo=timezone.utc)
            dt_end_utc = datetime.strptime(input_data.time_range_end, utc_format).replace(tzinfo=timezone.utc)

            t_start = dt_start_utc.timestamp()
            t_end = dt_end_utc.timestamp()
        except ValueError:
            raise ValueError("Invalid UTC format.")

        effective_index = input_data.index_name or "*"
        search_query = f"search index=\"{effective_index}\" {input_data.keyword}"

        job = service.jobs.create(
            search_query,
            earliest_time=t_start,
            latest_time=t_end,
            exec_mode="normal"
        )

        while not job.is_done():
            time.sleep(0.2)

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
            agg_fields = input_data.aggregation_fields
            if not agg_fields:
                agg_fields = get_default_agg_fields(input_data.index_name)

            if total_hits > 0:
                for field in agg_fields:
                    stats_spl = f"{search_query} | top limit=5 {field}"
                    rr = service.jobs.oneshot(stats_spl, earliest_time=t_start, latest_time=t_end, output_mode="json")
                    reader = JSONResultsReader(rr)
                    top_vals = {}
                    for item in reader:
                        if isinstance(item, dict) and field in item:
                            top_vals[item[field]] = int(item['count'])
                    if top_vals:
                        stats_output.append(FieldStat(field_name=field, top_values=top_vals))

        hits_data = []
        if total_hits > 0:
            results = job.results(count=3, output_mode="json")
            for result in results:
                result = json.loads(result)
                logs = result["results"]
                for log in logs:
                    log: dict
                    clean_record = {k: v for k, v in log.items() if not k.startswith("_") or k == "_index"}
                    if "_time" in log.keys():
                        clean_record["@timestamp"] = log["_time"]
                    if "index" in log.keys():
                        clean_record["_index"] = log["index"]
                    elif "_index" not in clean_record:
                        clean_record["_index"] = effective_index
                    hits_data.append(clean_record)

        status = cls._resolve_funnel_status(total_hits)

        if status == "summary":
            msg = f"Found {total_hits} events across {len(index_distribution)} index(es) in Splunk. Showing statistics only."
            final_records = []

        elif status == "sample":
            msg = f"Found {total_hits} events across {len(index_distribution)} index(es) in Splunk. Showing statistics + samples."
            final_records = hits_data

        else:
            msg = f"Found {total_hits} events in Splunk. Returning full logs."
            final_records = []
            results = job.results(count=SAMPLE_THRESHOLD, output_mode="json")
            for result in results:
                result = json.loads(result)
                logs = result["results"]
                for log in logs:
                    log: dict
                    clean_record = {k: v for k, v in log.items() if not k.startswith("_") or k == "_index"}
                    if "_time" in log.keys():
                        clean_record["@timestamp"] = log["_time"]
                    if "index" in log.keys():
                        clean_record["_index"] = log["index"]
                    elif "_index" not in clean_record:
                        clean_record["_index"] = effective_index
                    final_records.append(clean_record)

        return KeywordSearchOutput(
            status=status,
            total_hits=total_hits,
            message=msg,
            index_distribution=index_distribution,
            statistics=stats_output,
            records=final_records
        )

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

    # ==========================================
    # Helper: Shared Logic for ELK (Refactored)
    # ==========================================
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
