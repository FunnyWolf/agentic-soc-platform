import json
import time
from datetime import datetime, timezone

from splunklib.results import JSONResultsReader

from PLUGINS.SIEM.clients import ELKClient, SplunkClient
from models import (
    SchemaExplorerInput,
    AdaptiveQueryInput,
    AdaptiveQueryOutput,
    FieldStat
)
from registry import STATIC_SCHEMA_REGISTRY, get_default_agg_fields, get_backend_type

SUMMARY_THRESHOLD = 1000
SAMPLE_THRESHOLD = 20


class SIEMToolKit(object):
    @classmethod
    def explore_schema(cls, input_data: SchemaExplorerInput = SchemaExplorerInput(target_index=None)):
        try:
            if not input_data.target_index:
                # Agent 看到的是统一的列表，不关心 Backend
                return [
                    {"name": k, "description": v.description}
                    for k, v in STATIC_SCHEMA_REGISTRY.items()
                ]

            if input_data.target_index not in STATIC_SCHEMA_REGISTRY:
                raise ValueError(f"Index {input_data.target_index} not found.")

            idx_info = STATIC_SCHEMA_REGISTRY[input_data.target_index]
            return [f.model_dump() for f in idx_info.fields]

        except Exception as e:
            raise e

    @classmethod
    def execute_adaptive_query(cls, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        # --- 路由层 (Router Layer) ---
        backend = get_backend_type(input_data.index_name)

        if backend == "ELK":
            return cls._execute_elk(input_data)
        elif backend == "Splunk":
            return cls._execute_splunk(input_data)
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
        aggs_dsl = {f: {"terms": {"field": f, "size": 5}} for f in agg_fields}

        response = client.search(
            index=input_data.index_name, query=query_body, aggs=aggs_dsl, size=3, track_total_hits=True
        )

        total_hits = response["hits"]["total"]["value"]
        hits_data = [hit["_source"] for hit in response["hits"]["hits"]]

        stats_output = []
        if "aggregations" in response:
            for field in agg_fields:
                if field in response["aggregations"]:
                    buckets = response["aggregations"][field]["buckets"]
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
                stats_spl = f"{search_query} | top limit=5 {field}"
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

        if total_hits > SUMMARY_THRESHOLD:
            status = "summary"
            msg = f"Found {total_hits} events in Splunk. Showing statistics only."
            final_records = []

        elif SUMMARY_THRESHOLD < total_hits <= SUMMARY_THRESHOLD:
            status = "sample"
            msg = f"Found {total_hits} events in Splunk. Showing statistics + samples."
            final_records = hits_data

        else:
            status = "full"
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

    # ==========================================
    # Helper: Shared Logic for ELK (Refactored)
    # ==========================================
    @classmethod
    def _apply_funnel_strategy(cls, total, stats, initial_hits, input_data, client, query_body):
        # 这是一个辅助函数，用于处理 ELK 的返回逻辑，保持代码整洁
        if total > SUMMARY_THRESHOLD:
            return AdaptiveQueryOutput(
                status="summary", total_hits=total, statistics=stats, records=[],
                message=f"Matches {total} records (ELK). High volume."
            )
        elif SAMPLE_THRESHOLD < total <= SUMMARY_THRESHOLD:
            return AdaptiveQueryOutput(
                status="sample", total_hits=total, statistics=stats, records=initial_hits,
                message=f"Matches {total} records (ELK). Showing samples."
            )
        else:
            final_recs = initial_hits
            if total > 3:
                resp = client.search(index=input_data.index_name, query=query_body, size=SAMPLE_THRESHOLD)
                final_recs = [h["_source"] for h in resp["hits"]["hits"]]
            return AdaptiveQueryOutput(
                status="full", total_hits=total, statistics=stats, records=final_recs,
                message="Low volume. Returning full logs."
            )
