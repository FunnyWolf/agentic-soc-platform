from config import ELKClient
from models import (
    SchemaExplorerInput,
    AdaptiveQueryInput,
    AdaptiveQueryOutput,
    FieldStat
)
from registry import STATIC_SCHEMA_REGISTRY, get_default_agg_fields


class SIEMToolKit:

    def explore_schema(self, input_data: SchemaExplorerInput):
        # ... (保持不变) ...
        try:
            if not input_data.target_index:
                return [
                    {"name": k, "description": v.description}
                    for k, v in STATIC_SCHEMA_REGISTRY.items()
                ]

            if input_data.target_index not in STATIC_SCHEMA_REGISTRY:
                raise ValueError(f"Index {input_data.target_index} not found in registry.")

            idx_info = STATIC_SCHEMA_REGISTRY[input_data.target_index]
            return [f.model_dump() for f in idx_info.fields]

        except Exception as e:
            raise e

    def execute_adaptive_query(self, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        try:
            client = ELKClient.get_client()

            # 1. Build Query DSL
            must_clauses = []

            # Time Range (修改点：使用动态的 time_field)
            must_clauses.append({
                "range": {
                    input_data.time_field: {  # 这里使用了变量
                        "gte": input_data.time_range_start,
                        "lt": input_data.time_range_end
                    }
                }
            })

            # Filters (Term Match)
            for k, v in input_data.filters.items():
                must_clauses.append({"term": {k: v}})

            query_body = {"bool": {"must": must_clauses}}

            # 2. Determine Aggregation Fields
            agg_fields = input_data.aggregation_fields
            if not agg_fields:
                agg_fields = get_default_agg_fields(input_data.index_name)

            aggs_dsl = {}
            for field in agg_fields:
                aggs_dsl[field] = {
                    "terms": {"field": field, "size": 5}
                }

            # 3. Execute Search (Initial Probe: Size 3)
            response = client.search(
                index=input_data.index_name,
                query=query_body,
                aggs=aggs_dsl,
                size=3,
                track_total_hits=True
            )

            total_hits = response["hits"]["total"]["value"]
            hits_data = [hit["_source"] for hit in response["hits"]["hits"]]

            # Parse Aggregations
            stats_output = []
            if "aggregations" in response:
                for field in agg_fields:
                    if field in response["aggregations"]:
                        buckets = response["aggregations"][field]["buckets"]
                        stats_output.append(FieldStat(
                            field_name=field,
                            top_values={b["key"]: b["doc_count"] for b in buckets}
                        ))

            # 4. Funnel Strategy Implementation
            if total_hits > 1000:
                return AdaptiveQueryOutput(
                    status="summary",
                    total_hits=total_hits,
                    message=f"Matches {total_hits} records. High volume. Showing statistics only.",
                    statistics=stats_output,
                    records=[]
                )

            elif 20 < total_hits <= 1000:
                return AdaptiveQueryOutput(
                    status="sample",
                    total_hits=total_hits,
                    message=f"Matches {total_hits} records. Showing statistics and 3 samples.",
                    statistics=stats_output,
                    records=hits_data
                )

            else:
                if total_hits > 3:
                    full_response = client.search(
                        index=input_data.index_name,
                        query=query_body,
                        size=20
                    )
                    final_records = [hit["_source"] for hit in full_response["hits"]["hits"]]
                else:
                    final_records = hits_data

                return AdaptiveQueryOutput(
                    status="full",
                    total_hits=total_hits,
                    message="Low volume. Returning full logs.",
                    statistics=stats_output,
                    records=final_records
                )

        except Exception as e:
            raise e
