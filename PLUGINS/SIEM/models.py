from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator

SUMMARY_THRESHOLD = 1000
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
        description="Start time in UTC ISO8601 format: YYYY-MM-DDTHH:MM:SSZ",
    )
    time_range_end: str = Field(
        ...,
        description="End time in UTC ISO8601 format: YYYY-MM-DDTHH:MM:SSZ",
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

    @field_validator("time_range_start", "time_range_end")
    @classmethod
    def validate_utc_format(cls, value: str) -> str:
        try:
            if not value.endswith("Z"):
                raise ValueError("Time must end with 'Z' to indicate UTC.")
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError("Invalid format. Must be UTC ISO8601: YYYY-MM-DDTHH:MM:SSZ") from exc
        return value


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
        description="Start time in UTC ISO8601 format: YYYY-MM-DDTHH:MM:SSZ",
    )
    time_range_end: str = Field(
        ...,
        description="End time in UTC ISO8601 format: YYYY-MM-DDTHH:MM:SSZ",
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

    @field_validator("time_range_start", "time_range_end")
    @classmethod
    def validate_utc_format(cls, value: str) -> str:
        try:
            if not value.endswith("Z"):
                raise ValueError("Time must end with 'Z' to indicate UTC.")
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError("Invalid format. Must be UTC ISO8601: YYYY-MM-DDTHH:MM:SSZ") from exc
        return value

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


class FieldStat(BaseModel):
    field_name: str = Field(..., description="Name of the field for which statistics are computed")
    top_values: Dict[Union[str, int], int] = Field(
        ...,
        description="Top-N value distribution for the field (value -> count)",
    )


class AdaptiveQueryOutput(BaseModel):
    backend: Literal["ELK", "Splunk"] = Field(..., description="Backend that executed the query")
    index_name: str = Field(..., description="Index/source queried by the tool")
    status: Literal["records", "sample", "summary"] = Field(
        ...,
        description=(
            "Response type indicator based on result volume. "
            f"'records' returns up to {SAMPLE_THRESHOLD} projected records, "
            f"'sample' returns statistics plus up to {SAMPLE_COUNT} projected records, "
            f"'summary' returns statistics only."
        ),
    )
    total_hits: int = Field(..., description="Total number of matching records in the SIEM backend")
    returned_records: int = Field(..., description="Number of records included in the response payload")
    truncated: bool = Field(
        ...,
        description="Whether the tool omitted matching events or record fields to keep the payload LLM-safe",
    )
    message: str = Field(..., description="Human-readable status message describing the response")
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


class KeywordSearchOutput(BaseModel):
    backend: Literal["ELK", "Splunk"] = Field(..., description="Backend that executed the search")
    index_name: str = Field(..., description="Index/source represented by this result")
    status: Literal["records", "sample", "summary"] = Field(
        ...,
        description=(
            "Response type indicator based on result volume. "
            f"'records' returns up to {SAMPLE_THRESHOLD} projected records, "
            f"'sample' returns statistics plus up to {SAMPLE_COUNT} projected records, "
            f"'summary' returns statistics only."
        ),
    )
    total_hits: int = Field(..., description="Total number of matching records for this result set")
    returned_records: int = Field(..., description="Number of records included in the response payload")
    truncated: bool = Field(
        ...,
        description="Whether the tool omitted matching events or record fields to keep the payload LLM-safe",
    )
    message: str = Field(..., description="Human-readable status message describing the response")
    index_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Distribution of hits across indices seen by this search result",
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
