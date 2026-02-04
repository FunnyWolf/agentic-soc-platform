from datetime import datetime
from typing import List, Dict, Any, Optional

from pydantic import BaseModel, Field, field_validator

SUMMARY_THRESHOLD = 1000
SAMPLE_THRESHOLD = 20


# --- Input Models ---
class SchemaExplorerInput(BaseModel):
    target_index: Optional[str] = Field(
        default=None,
        description=(
            "Target index to explore. "
            "If None: returns a list of all available indices with descriptions (list of dicts with 'name' and 'description'). "
            "If provided: returns detailed field metadata for that specific index (list of field schemas with 'name', 'type', 'description', etc.)"
        )
    )


class AdaptiveQueryInput(BaseModel):
    index_name: str = Field(
        ...,
        description="Target SIEM index/source name. Examples: 'logs-security', 'main', 'logs-endpoint'"
    )

    time_field: str = Field(
        default="@timestamp",
        description=(
            "The field to apply time range filter on. "
            "Commonly used fields: '@timestamp', 'event.created', '_time'. "
            "Must be a Date/DateTime type in your SIEM."
        )
    )

    time_range_start: str = Field(
        ...,
        description="Start time in UTC ISO8601 format. Format: 'YYYY-MM-DDTHH:MM:SSZ'. Example: '2026-02-04T06:00:00Z'"
    )
    time_range_end: str = Field(
        ...,
        description="End time in UTC ISO8601 format. Format: 'YYYY-MM-DDTHH:MM:SSZ'. Example: '2026-02-04T07:00:00Z'"
    )

    filters: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Key-value pairs for exact matching filters (term/exact match, not full-text search). "
            "Example: {'event.outcome': 'success', 'source.ip': '45.33.22.11'}"
        )
    )
    aggregation_fields: List[str] = Field(
        default_factory=list,
        description=(
            "Fields to get top-N statistics for. "
            "If empty, uses backend-specific default key fields. "
            "Example: ['event.outcome', 'source.ip', 'process.name']"
        )
    )

    @field_validator('time_range_start', 'time_range_end')
    @classmethod
    def validate_utc_format(cls, v):
        try:
            if not v.endswith("Z"):
                raise ValueError("Time must end with 'Z' to indicate UTC.")
            datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise ValueError("Invalid format. Must be UTC ISO8601: YYYY-MM-DDTHH:MM:SSZ")
        return v


# --- Output Models ---
class FieldStat(BaseModel):
    field_name: str = Field(
        ...,
        description="Name of the field for which statistics are computed"
    )
    top_values: Dict[str, int] = Field(
        ...,
        description="Top-N value distribution for the field (key: value, int: count)"
    )


class AdaptiveQueryOutput(BaseModel):
    status: str = Field(
        ...,
        description=(
            "Response type indicator based on result volume. "
            f"Possible values: 'full' (complete logs, < {SAMPLE_THRESHOLD} results), "
            f"'sample' (statistics + sample records, {SAMPLE_THRESHOLD}-{SUMMARY_THRESHOLD} results), "
            f"'summary' (statistics only, > {SUMMARY_THRESHOLD} results)"
        )
    )
    total_hits: int = Field(
        ...,
        description="Total number of matching records in the SIEM backend"
    )
    message: str = Field(
        ...,
        description="Human-readable status message describing the response"
    )
    statistics: List[FieldStat] = Field(
        ...,
        description=(
            "Top-N value distribution for each aggregation field. "
            "Each FieldStat contains field_name and top_values (dict mapping values to their counts)"
        )
    )
    records: List[Dict[str, Any]] = Field(
        ...,
        description=(
            "Actual log records returned based on status: "
            "'full' status returns all records up to SAMPLE_THRESHOLD; "
            "'sample' status returns first 3 representative records; "
            "'summary' status returns empty list"
        )
    )
