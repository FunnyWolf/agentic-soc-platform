from typing import List, Union

from PLUGINS.SIEM.backends import ELKQueryBackend, SplunkQueryBackend
from PLUGINS.SIEM.models import (
    AdaptiveQueryInput,
    AdaptiveQueryOutput,
    KeywordSearchInput,
    KeywordSearchOutput,
    SchemaExplorerInput,
    SchemaIndexSummary, IndexInfo,
)
from PLUGINS.SIEM.registry import get_backend_type, get_default_agg_fields, get_index_info, list_indices
from PLUGINS.SIEM.response import build_adaptive_output, build_keyword_output


class SIEMToolKit:
    @classmethod
    def explore_schema(cls, input_data: SchemaExplorerInput) -> Union[IndexInfo, List[SchemaIndexSummary]]:
        """
        Explore registered SIEM indices and their declared schemas.

        When `target_index` is omitted, the tool returns summaries for all registered indices.
        When `target_index` is provided, the tool returns the field definitions for that index.

        Raises:
            ValueError: If `target_index` is not present in the SIEM registry.
        """
        if not input_data.target_index:
            return [
                SchemaIndexSummary(
                    name=index_info.name,
                    backend=index_info.backend,
                    description=index_info.description,
                    default_aggregation_fields=get_default_agg_fields(index_info.name),
                )
                for index_info in list_indices()
            ]

        index_info = get_index_info(input_data.target_index)
        return index_info

    @classmethod
    def execute_adaptive_query(cls, input_data: AdaptiveQueryInput) -> AdaptiveQueryOutput:
        """
        Execute an exact-match SIEM query and return an LLM-safe response.

        The response uses three status levels:
        - `records`: returns projected records when result volume is small
        - `sample`: returns statistics and projected sample records
        - `summary`: returns statistics only
        """
        backend = get_backend_type(input_data.index_name)
        query_backend = cls._get_query_backend(backend)
        backend_result = query_backend.execute_structured_query(input_data)
        return build_adaptive_output(input_data, backend_result)

    @classmethod
    def keyword_search(cls, input_data: KeywordSearchInput) -> List[KeywordSearchOutput]:
        """
        Execute keyword search against SIEM data and return one result per matched index.

        If `index_name` is provided, the tool queries only that index and returns a single-item list.
        If `index_name` is omitted, the tool first discovers hit indices across the registered backends and then
        runs per-index searches so each response stays small and attributable to a single source.
        """
        if input_data.index_name:
            backend = get_backend_type(input_data.index_name)
            backend_result = cls._get_query_backend(backend).execute_keyword_query(input_data)
            return [build_keyword_output(input_data, backend_result)]

        results: list[KeywordSearchOutput] = []
        indices_by_backend = cls.get_indices_by_backend()

        for backend_name, indices in indices_by_backend.items():
            query_backend = cls._get_query_backend(backend_name)
            for index_name in query_backend.discover_keyword_hit_indices(input_data, indices):
                per_index_input = KeywordSearchInput(
                    keyword=input_data.keyword,
                    time_range_start=input_data.time_range_start,
                    time_range_end=input_data.time_range_end,
                    time_field=input_data.time_field,
                    index_name=index_name,
                )
                backend_result = query_backend.execute_keyword_query(per_index_input)
                results.append(build_keyword_output(per_index_input, backend_result))

        return results

    @staticmethod
    def _get_query_backend(backend: str):
        if backend == "ELK":
            return ELKQueryBackend
        if backend == "Splunk":
            return SplunkQueryBackend
        raise ValueError(f"Unsupported backend: {backend}")

    @staticmethod
    def get_indices_by_backend() -> dict:
        result = {"ELK": [], "Splunk": []}
        for index_info in list_indices():
            result.setdefault(index_info.backend, []).append(index_info.name)
        return result
