from typing import List, Dict

from pydantic import BaseModel


# --- Schema Definition Models ---
class FieldInfo(BaseModel):
    name: str
    type: str
    description: str
    is_key_field: bool = False


class IndexInfo(BaseModel):
    name: str
    description: str
    fields: List[FieldInfo]


# --- Static Registry Data ---
STATIC_SCHEMA_REGISTRY: Dict[str, IndexInfo] = {
    "siem-aws-cloudtrail": IndexInfo(
        name="siem-aws-cloudtrail",
        description="AWS CloudTrail logs recording API calls and user activities.",
        fields=[
            FieldInfo(name="@timestamp", type="date", description="Time of the event", is_key_field=False),
            FieldInfo(name="event.action", type="keyword", description="The API action performed (e.g., CreateUser)", is_key_field=True),
            FieldInfo(name="event.outcome", type="keyword", description="Result of the action (success/failure)", is_key_field=True),
            FieldInfo(name="source.ip", type="ip", description="IP address of the requester", is_key_field=True),
            FieldInfo(name="user.name", type="keyword", description="IAM user or role name", is_key_field=True),
            FieldInfo(name="cloud.region", type="keyword", description="AWS Region", is_key_field=False),
            FieldInfo(name="user_agent", type="text", description="Tool used for the request", is_key_field=False)
        ]
    )
}


def get_default_agg_fields(index_name: str) -> List[str]:
    if index_name not in STATIC_SCHEMA_REGISTRY:
        return []
    return [f.name for f in STATIC_SCHEMA_REGISTRY[index_name].fields if f.is_key_field]
