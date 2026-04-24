from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Union

import dateparser
from pydantic import BaseModel, Field, model_validator, field_validator

SUMMARY_THRESHOLD = 1000
SAMPLE_THRESHOLD = 100
SAMPLE_COUNT = 5
UTC_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _normalize_time_input(value: Any, relative_base: datetime) -> str:
    system_timezone = relative_base.tzinfo or timezone.utc
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = dateparser.parse(
            str(value),
            settings={
                "RELATIVE_BASE": relative_base,
                "RETURN_AS_TIMEZONE_AWARE": True,
            },
        )

    if parsed is None:
        raise ValueError(f"Unable to parse time value: {value}")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=system_timezone)
    parsed = parsed.astimezone(timezone.utc)

    return parsed.strftime(UTC_TIME_FORMAT)


def _normalize_time_range_inputs(data: Any) -> Any:
    if not isinstance(data, dict):
        return data

    normalized = dict(data)
    relative_base = datetime.now(datetime.now().astimezone().tzinfo or timezone.utc)
    for field_name in ("time_range_start", "time_range_end"):
        if field_name in normalized and normalized[field_name] is not None:
            normalized[field_name] = _normalize_time_input(normalized[field_name], relative_base)
    return normalized


def _validate_time_range_order(start: str, end: str) -> None:
    start_dt = datetime.strptime(start, UTC_TIME_FORMAT).replace(tzinfo=timezone.utc)
    end_dt = datetime.strptime(end, UTC_TIME_FORMAT).replace(tzinfo=timezone.utc)
    if end_dt <= start_dt:
        raise ValueError("time_range_end must be later than time_range_start")


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
        return _normalize_time_range_inputs(data)

    @model_validator(mode="after")
    def validate_time_range_order(self):
        _validate_time_range_order(self.time_range_start, self.time_range_end)
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
        return _normalize_time_range_inputs(data)

    @model_validator(mode="after")
    def validate_time_range_order(self):
        _validate_time_range_order(self.time_range_start, self.time_range_end)
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


class DiscoverIndexFieldsInput(BaseModel):
    index_name: str = Field(
        ...,
        description="Target SIEM index/source name to discover fields from the live backend.",
    )
    backend: Literal["ELK", "Splunk"] = Field(
        ...,
        description="Backend type that owns this index.",
    )


class DiscoveredFieldInfo(BaseModel):
    name: str = Field(..., description="Field name (dotted path for nested fields)")
    type: str = Field(..., description="Field type reported by the backend")
    sample_values: List[str] = Field(
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
