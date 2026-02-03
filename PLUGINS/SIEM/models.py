from datetime import datetime
from typing import List, Dict, Any, Optional

from pydantic import BaseModel, Field, field_validator


# --- Input Models ---
class SchemaExplorerInput(BaseModel):
    target_index: Optional[str] = Field(
        default=None,
        description="If None, lists all indices. If provided, details fields."
    )


class AdaptiveQueryInput(BaseModel):
    index_name: str = Field(..., description="Target ES index")

    # 新增：允许指定用于过滤的时间字段，默认为 @timestamp
    time_field: str = Field(
        default="@timestamp",
        description="The field to apply time range filter on (e.g., 'event.created', '@timestamp'). Must be a Date type in ELK."
    )

    time_range_start: str = Field(
        ...,
        description="Start time in UTC ISO8601 format, e.g., '2026-02-04T06:00:00Z'"
    )
    time_range_end: str = Field(
        ...,
        description="End time in UTC ISO8601 format, e.g., '2026-02-04T07:00:00Z'"
    )

    filters: Dict[str, str] = Field(
        default_factory=dict,
        description="Key-value pairs for exact matching (term query)"
    )
    aggregation_fields: List[str] = Field(
        default_factory=list,
        description="Fields to get statistics for. If empty, uses default key fields."
    )

    @field_validator('time_range_start', 'time_range_end')
    def validate_utc_format(cls, v):
        try:
            if not v.endswith("Z"):
                raise ValueError("Time must end with 'Z' to indicate UTC.")
            datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise ValueError("Invalid format. Must be UTC ISO8601: YYYY-MM-DDTHH:MM:SSZ")
        return v


# --- Output Models (保持不变) ---
class FieldStat(BaseModel):
    field_name: str
    top_values: Dict[str, int]


class AdaptiveQueryOutput(BaseModel):
    status: str = Field(..., description="summary | sample | full")
    total_hits: int
    message: str
    statistics: List[FieldStat]
    records: List[Dict[str, Any]]
