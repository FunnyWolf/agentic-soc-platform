from typing import List, Union

from PLUGINS.SIEM.backends import ELKQueryBackend, SplunkQueryBackend
from PLUGINS.SIEM.models import (
    AdaptiveQueryInput,
    DiscoverIndexFieldsInput,
    DiscoverIndexFieldsOutput,
    ESQLQueryInput,
    KeywordSearchInput,
    QueryOutput,
    SchemaExplorerInput,
    SchemaIndexSummary, IndexInfo,
    SPLQueryInput,
)
from PLUGINS.SIEM.registry import get_backend_type, get_default_agg_fields, get_index_info, list_indices
from PLUGINS.SIEM.response import build_query_output, build_raw_query_output


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
    def execute_adaptive_query(cls, input_data: AdaptiveQueryInput) -> QueryOutput:
        """
        Execute an exact-match SIEM query and return an LLM-safe response.

        The response uses two status levels:
        - `records`: returns projected records when result volume is small (<=100)
        - `summary`: returns statistics plus sample records when result volume is large
        """
        backend = get_backend_type(input_data.index_name)
        query_backend = cls._get_query_backend(backend)
        backend_result = query_backend.execute_structured_query(input_data)
        return build_query_output(input_data, backend_result)

    @classmethod
    def keyword_search(cls, input_data: KeywordSearchInput) -> List[QueryOutput]:
        """
        Execute keyword search against SIEM data and return one result per matched index.

        If `index_name` is provided, the tool queries only that index and returns a single-item list.
        If `index_name` is omitted, the tool first discovers hit indices across the registered backends and then
        runs per-index searches so each response stays small and attributable to a single source.
        """
        if input_data.index_name:
            backend = get_backend_type(input_data.index_name)
            backend_result = cls._get_query_backend(backend).execute_keyword_query(input_data)
            return [build_query_output(input_data, backend_result,
                                       index_distribution=backend_result.index_distribution)]

        results: list[QueryOutput] = []
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
                results.append(build_query_output(per_index_input, backend_result,
                                                  index_distribution=backend_result.index_distribution))

        return results

    @classmethod
    def execute_spl(cls, input_data: SPLQueryInput) -> QueryOutput:
        """
        Execute a raw Splunk SPL query and return results.

        The `limit` parameter controls the maximum number of records returned (default 100).
        Time range is optional; if omitted, Splunk defaults to all time.
        """
        query_backend = cls._get_query_backend("Splunk")
        backend_result = query_backend.execute_spl_query(input_data)
        return build_raw_query_output(input_data, backend_result, limit=input_data.limit)

    @classmethod
    def execute_esql(cls, input_data: ESQLQueryInput) -> QueryOutput:
        """
        Execute a raw ELK ES|QL query and return results.

        The `limit` parameter controls the maximum number of records returned (default 100).
        If the query has no LIMIT clause, one is appended automatically.
        Time range is optional; if provided, a WHERE clause is injected into the query.
        """
        query_backend = cls._get_query_backend("ELK")
        backend_result = query_backend.execute_esql_query(input_data)
        return build_raw_query_output(input_data, backend_result, limit=input_data.limit)

    @classmethod
    def discover_index_fields(cls, input_data: DiscoverIndexFieldsInput) -> DiscoverIndexFieldsOutput:
        """
        Discover all fields of a live SIEM index by querying the backend directly.

        Returns field names, types, and top-5 sample values for each field.
        This is intended for generating index YAML configuration files.
        """
        query_backend = cls._get_query_backend(input_data.backend)
        return query_backend.discover_index_fields(
            input_data.index_name,
            time_start=input_data.time_range_start,
            time_end=input_data.time_range_end,
            doc_limit=input_data.doc_limit,
            max_samples=input_data.max_samples_per_field,
        )

    @staticmethod
    def _get_query_backend(backend: str) -> type[ELKQueryBackend | SplunkQueryBackend]:
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
