import time
from datetime import datetime

import splunklib.results as results

from config import ELKClient, SplunkClient
from models import (
    SchemaExplorerInput,
    AdaptiveQueryInput,
    AdaptiveQueryOutput,
    FieldStat
)
from registry import STATIC_SCHEMA_REGISTRY, get_default_agg_fields, get_backend_type


class SIEMToolKit:

    def explore_schema(self, input_data: SchemaExplorerInput):
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

    def execute_adaptive_query(self, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        # --- 路由层 (Router Layer) ---
        backend = get_backend_type(input_data.index_name)

        if backend == "ELK":
            return self._execute_elk(input_data)
        elif backend == "Splunk":
            return self._execute_splunk(input_data)
        else:
            raise ValueError(f"Unsupported backend: {backend}")

    # ==========================================
    # ELK Implementation (Existing)
    # ==========================================
    def _execute_elk(self, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
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

        return self._apply_funnel_strategy(total_hits, stats_output, hits_data, input_data, client, query_body)

    # ==========================================
    # Splunk Implementation (New)
    # ==========================================
    def _execute_splunk(self, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        service = SplunkClient.get_service()

        # 1. Time Conversion (ISO8601 -> Epoch)
        try:
            t_start = datetime.strptime(input_data.time_range_start, "%Y-%m-%dT%H:%M:%SZ").timestamp()
            t_end = datetime.strptime(input_data.time_range_end, "%Y-%m-%dT%H:%M:%SZ").timestamp()
        except ValueError:
            raise ValueError("Invalid UTC format.")

        # 2. Build SPL (Search Processing Language)
        # 你的样本是 JSON 格式，Splunk 搜索通常是: search index=idx source.ip="1.1.1.1"
        # spath 是用来自动解析 JSON 的，虽然 Splunk 通常会自动解析，但显式写更安全
        search_query = f"search index=\"{input_data.index_name}\""

        # Add Filters
        for k, v in input_data.filters.items():
            search_query += f" {k}=\"{v}\""

        # 3. Create Async Job (to check count first)
        job = service.jobs.create(
            search_query,
            earliest_time=t_start,
            latest_time=t_end,
            exec_mode="normal"
        )

        # Wait for job (Polling)
        while not job.is_done():
            time.sleep(0.1)

        total_hits = int(job["eventCount"])

        # 4. Get Statistics (if needed)
        agg_fields = input_data.aggregation_fields or get_default_agg_fields(input_data.index_name)
        stats_output = []

        if total_hits > 0:
            # Splunk 获取统计需要额外的开销，这里简化处理：
            # 如果数据量大，我们发一个新的快速统计查询
            # 使用 "| top limit=5 field"
            for field in agg_fields[:3]:  # 限制只统计前3个关键字段以保证速度
                stats_spl = f"{search_query} | top limit=5 {field}"
                # oneshot is blocking but fast for stats
                rr = service.jobs.oneshot(stats_spl, earliest_time=t_start, latest_time=t_end, output_mode="json")
                reader = results.JSONResultsReader(rr)
                top_vals = {}
                for item in reader:
                    if isinstance(item, dict) and field in item:
                        top_vals[item[field]] = int(item['count'])
                if top_vals:
                    stats_output.append(FieldStat(field_name=field, top_values=top_vals))

        # 5. Fetch Samples (Normalization)
        hits_data = []
        # Splunk 的 result 是扁平的或者带 _raw，我们需要尽量让它看起来像 ELK 的 dict
        if total_hits > 0:
            # 获取前 3 条作为样本
            for result in job.results(count=3, output_mode="json"):
                # 清洗 Splunk 的内部字段 (以_开头的)
                clean_record = {k: v for k, v in result.items() if not k.startswith("_")}
                # 保留关键的时间字段，映射回 @timestamp 以保持一致性
                if "_time" in result:
                    clean_record["@timestamp"] = result["_time"]
                hits_data.append(clean_record)

        # 6. Re-use the same Funnel Logic
        # 注意：这里我们不需要像 ELK 那样传 client 回去，因为 Splunk 翻页逻辑不同
        # 为了简化，我们在 Splunk 分支里直接处理 full logic

        status = ""
        msg = ""
        final_records = []

        if total_hits > 1000:
            status = "summary"
            msg = f"Found {total_hits} events in Splunk. Showing statistics only."
            final_records = []

        elif 20 < total_hits <= 1000:
            status = "sample"
            msg = f"Found {total_hits} events in Splunk. Showing statistics + samples."
            final_records = hits_data

        else:
            status = "full"
            msg = "Low volume. Returning full logs."
            # Fetch up to 20
            final_records = []
            for result in job.results(count=20, output_mode="json"):
                clean_record = {k: v for k, v in result.items() if not k.startswith("_")}
                if "_time" in result:
                    clean_record["@timestamp"] = result["_time"]
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
    def _apply_funnel_strategy(self, total, stats, initial_hits, input_data, client, query_body):
        # 这是一个辅助函数，用于处理 ELK 的返回逻辑，保持代码整洁
        if total > 1000:
            return AdaptiveQueryOutput(
                status="summary", total_hits=total, statistics=stats, records=[],
                message=f"Matches {total} records (ELK). High volume."
            )
        elif 20 < total <= 1000:
            return AdaptiveQueryOutput(
                status="sample", total_hits=total, statistics=stats, records=initial_hits,
                message=f"Matches {total} records (ELK). Showing samples."
            )
        else:
            final_recs = initial_hits
            if total > 3:
                resp = client.search(index=input_data.index_name, query=query_body, size=20)
                final_recs = [h["_source"] for h in resp["hits"]["hits"]]
            return AdaptiveQueryOutput(
                status="full", total_hits=total, statistics=stats, records=final_recs,
                message="Low volume. Returning full logs."
            )
