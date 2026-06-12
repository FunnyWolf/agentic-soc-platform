from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, model_validator, field_validator

from PLUGINS.SIEM.time_utils import normalize_time_range_inputs, validate_time_range_order

SAMPLE_THRESHOLD = 100
SAMPLE_COUNT = 5


class SchemaIndexSummary(BaseModel):
    name: str = Field(..., description="Registered SIEM index/source name")
    backend: Literal["ELK", "Splunk"] = Field(..., description="Backend that owns this index")
    description: str = Field(..., description="Human-readable description of the index")
    default_aggregation_fields: List[str] = Field(
        default_factory=list,
        description="Registry key fields used as default aggregation fields for this index",
    )


class SchemaFieldInfo(BaseModel):
    name: str = Field(..., description="Field name")
    type: str = Field(..., description="Field type declared in the SIEM registry")
    description: str = Field(..., description="Human-readable field description")
    is_key_field: bool = Field(
        default=False,
        description="Whether the field is marked as a key field in the registry",
    )
    sample_values: List[Any] = Field(
        default_factory=list,
        description="Example values observed in the live backend data",
    )


class SchemaExplorerInput(BaseModel):
    target_index: Optional[str] = Field(
        default=None,
        description=(
            "Target index to explore. "
            "If None: returns summaries for all registered indices. "
            "If provided: returns field metadata for that specific index."
        ),
    )


class AdaptiveQueryInput(BaseModel):
    index_name: str = Field(
        ...,
        description="Target SIEM index/source name. Examples: 'logs-security', 'main', 'logs-endpoint'",
    )
    time_field: str = Field(
        default="@timestamp",
        description=(
            "Field used for time range filtering. "
            "The field must exist in the target index and be queryable as a timestamp field."
        ),
    )
    time_range_start: str = Field(
        ...,
        description=(
            "Start time for the query window. Accepts common datetime strings and is normalized to UTC ISO8601."
        ),
    )
    time_range_end: str = Field(
        ...,
        description=(
            "End time for the query window. Accepts common datetime strings and is normalized to UTC ISO8601."
        ),
    )
    filters: Dict[str, Union[str, List[str]]] = Field(
        default_factory=dict,
        description=(
            "Exact-match filters. "
            "String values mean single exact match; list values mean OR semantics within that field."
        ),
    )
    aggregation_fields: List[str] = Field(
        default_factory=list,
        description=(
            "Fields used for top-N aggregation statistics. "
            "If empty, the tool uses the registry key fields for the target index."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_time_range_inputs(cls, data: Any) -> Any:
        return normalize_time_range_inputs(data)

    @model_validator(mode="after")
    def validate_time_range_order(self):
        validate_time_range_order(self.time_range_start, self.time_range_end)
        return self


class KeywordSearchInput(BaseModel):
    keyword: Union[str, List[str]] = Field(
        ...,
        description=(
            "Search keyword or keyword list. "
            "A list uses AND semantics, so every keyword in the list must match."
        ),
    )
    time_range_start: str = Field(
        ...,
        description=(
            "Start time for the query window. Accepts common datetime strings and is normalized to UTC ISO8601."
        ),
    )
    time_range_end: str = Field(
        ...,
        description=(
            "End time for the query window. Accepts common datetime strings and is normalized to UTC ISO8601."
        ),
    )
    time_field: str = Field(
        default="@timestamp",
        description=(
            "Field used for time range filtering. "
            "The field must exist in the target index and be queryable as a timestamp field."
        ),
    )
    index_name: Optional[str] = Field(
        default=None,
        description=(
            "Target SIEM index/source name. "
            "If omitted, the tool first discovers hit indices across the registered backends."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_time_range_inputs(cls, data: Any) -> Any:
        return normalize_time_range_inputs(data)

    @model_validator(mode="after")
    def validate_time_range_order(self):
        validate_time_range_order(self.time_range_start, self.time_range_end)
        return self

    @field_validator("keyword")
    @classmethod
    def validate_keyword(cls, value: Union[str, List[str]]) -> Union[str, List[str]]:
        if isinstance(value, str):
            keyword = value.strip()
            if not keyword:
                raise ValueError("keyword must not be empty")
            return keyword

        if isinstance(value, list):
            if not value:
                raise ValueError("keyword list must not be empty")
            normalized_keywords = []
            for item in value:
                if not isinstance(item, str):
                    raise ValueError("keyword list must contain only strings")
                keyword = item.strip()
                if not keyword:
                    raise ValueError("keyword list must not contain empty values")
                normalized_keywords.append(keyword)
            return normalized_keywords

        raise ValueError("keyword must be a string or a list of strings")


class _RawQueryInput(BaseModel):
    query: str = Field(..., description="Raw query string to execute")
    index_name: Optional[str] = Field(
        default=None,
        description="Index/source name for output labeling. If omitted, defaults to 'unknown' in the response.",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="Maximum number of records to return.",
    )
    time_range_start: Optional[str] = Field(
        default=None,
        description="Optional start time. Accepts common datetime strings, normalized to UTC ISO8601.",
    )
    time_range_end: Optional[str] = Field(
        default=None,
        description="Optional end time. Accepts common datetime strings, normalized to UTC ISO8601.",
    )
    time_field: str = Field(
        default="@timestamp",
        description="Field used for time range filtering when time_range_start/end are provided.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_time_range_inputs(cls, data: Any) -> Any:
        return normalize_time_range_inputs(data)

    @model_validator(mode="after")
    def validate_time_range_order(self):
        if self.time_range_start is not None and self.time_range_end is not None:
            validate_time_range_order(self.time_range_start, self.time_range_end)
        return self

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("query must not be empty")
        return stripped


class SPLQueryInput(_RawQueryInput):
    pass


class ESQLQueryInput(_RawQueryInput):
    pass


class FieldStat(BaseModel):
    field_name: str = Field(..., description="Name of the field for which statistics are computed")
    top_values: Dict[Union[str, int], int] = Field(
        ...,
        description="Top-N value distribution for the field (value -> count)",
    )


class QueryOutput(BaseModel):
    backend: Literal["ELK", "Splunk"] = Field(..., description="Backend that executed the query")
    index_name: str = Field(..., description="Index/source queried by the tool")
    status: Literal["records", "summary"] = Field(
        ...,
        description=(
            "Response type indicator based on result volume. "
            f"'records' returns up to {SAMPLE_THRESHOLD} projected records, "
            f"'summary' returns statistics plus up to {SAMPLE_COUNT} sample records."
        ),
    )
    total_hits: int = Field(..., description="Total number of matching records in the SIEM backend")
    returned_records: int = Field(..., description="Number of records included in the response payload")
    truncated: bool = Field(
        ...,
        description="Whether the tool omitted matching events or record fields to keep the payload LLM-safe",
    )
    message: str = Field(..., description="Human-readable status message describing the response")
    index_distribution: Optional[Dict[str, int]] = Field(
        default=None,
        description="Distribution of hits across indices (only populated for keyword search)",
    )
    statistics: List[FieldStat] = Field(
        default_factory=list,
        description="Top-N value distribution for each aggregation field",
    )
    records: List[Dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Projected log records. "
            "These records may omit non-essential fields to control response size."
        ),
    )


class IndexInfo(BaseModel):
    name: str
    backend: Literal["ELK", "Splunk"]
    description: str
    fields: List[SchemaFieldInfo]


class DiscoverIndexFieldsInput(BaseModel):
    index_name: str = Field(
        ...,
        description="Target SIEM index/source name to discover fields from the live backend.",
    )
    backend: Literal["ELK", "Splunk"] = Field(
        ...,
        description="Backend type that owns this index.",
    )
    time_range_start: Optional[str] = Field(
        default=None,
        description="Optional start time for sampling. Accepts common datetime strings, normalized to UTC ISO8601.",
    )
    time_range_end: Optional[str] = Field(
        default=None,
        description="Optional end time for sampling. Accepts common datetime strings, normalized to UTC ISO8601.",
    )
    doc_limit: int = Field(
        default=10000,
        ge=1,
        le=100000,
        description="Number of documents to scan for field discovery.",
    )
    max_samples_per_field: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of sample values to collect per field.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_time_range_inputs(cls, data: Any) -> Any:
        return normalize_time_range_inputs(data)

    @model_validator(mode="after")
    def validate_time_range_order(self):
        if self.time_range_start is not None and self.time_range_end is not None:
            validate_time_range_order(self.time_range_start, self.time_range_end)
        return self


class DiscoveredFieldInfo(BaseModel):
    name: str = Field(..., description="Field name (dotted path for nested fields)")
    type: str = Field(..., description="Field type reported by the backend")
    sample_values: List[Any] = Field(
        default_factory=list,
        description="Top-5 most frequent values for this field",
    )


class DiscoverIndexFieldsOutput(BaseModel):
    backend: Literal["ELK", "Splunk"] = Field(..., description="Backend that was queried")
    index_name: str = Field(..., description="Index that was inspected")
    total_fields: int = Field(..., description="Total number of discovered fields")
    fields: List[DiscoveredFieldInfo] = Field(
        default_factory=list,
        description="Discovered field definitions with sample values",
    )
