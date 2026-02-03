from typing import List, Dict, Literal

from pydantic import BaseModel


# --- Schema Definition Models ---
class FieldInfo(BaseModel):
    name: str
    type: str
    description: str
    is_key_field: bool = False


class IndexInfo(BaseModel):
    name: str
    backend: Literal["ELK", "Splunk"]  # 新增：用于路由判断
    description: str
    fields: List[FieldInfo]


# --- Static Registry Data ---
STATIC_SCHEMA_REGISTRY: Dict[str, IndexInfo] = {
    # 1. ELK Index
    "siem-aws-cloudtrail": IndexInfo(
        name="siem-aws-cloudtrail",
        backend="ELK",
        description="AWS CloudTrail logs via ELK.",
        fields=[
            FieldInfo(name="@timestamp", type="date", description="Event time", is_key_field=False),
            FieldInfo(name="event.action", type="keyword", description="API Action", is_key_field=True),
            FieldInfo(name="event.outcome", type="keyword", description="Result", is_key_field=True),
            FieldInfo(name="source.ip", type="ip", description="Requester IP", is_key_field=True)
        ]
    ),

    # 2. Splunk Index (新增)
    "siem-network-traffic": IndexInfo(
        name="siem-network-traffic",
        backend="Splunk",
        description="Network traffic logs via Splunk.",
        fields=[
            # 根据你提供的 JSON 样本定义
            FieldInfo(name="@timestamp", type="date", description="Event time", is_key_field=False),
            FieldInfo(name="source.ip", type="ip", description="Source IP", is_key_field=True),
            FieldInfo(name="destination.ip", type="ip", description="Destination IP", is_key_field=True),
            FieldInfo(name="destination.port", type="long", description="Dest Port", is_key_field=True),
            FieldInfo(name="event.action", type="keyword", description="Action (allow/block)", is_key_field=True)
        ]
    )
}


def get_default_agg_fields(index_name: str) -> List[str]:
    if index_name not in STATIC_SCHEMA_REGISTRY:
        return []
    return [f.name for f in STATIC_SCHEMA_REGISTRY[index_name].fields if f.is_key_field]


def get_backend_type(index_name: str) -> str:
    """Helper to determine backend"""
    if index_name in STATIC_SCHEMA_REGISTRY:
        return STATIC_SCHEMA_REGISTRY[index_name].backend
    return "ELK"  # Fallback
