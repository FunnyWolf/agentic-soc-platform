from typing import List, Dict, Any, Optional

from pydantic import BaseModel


class SplunkPayload(BaseModel):
    """
    Pydantic model for Splunk webhook payload.
    """
    search_name: str
    result: Dict[str, Any]
    sid: Optional[str] = None
    app: Optional[str] = None
    owner: Optional[str] = None
    results_link: Optional[str] = None


class KibanaRule(BaseModel):
    name: str


class KibanaContext(BaseModel):
    hits: List[Dict[str, Any]]


class KibanaPayload(BaseModel):
    """
    Pydantic model for Kibana webhook payload.
    """
    rule: KibanaRule
    context: KibanaContext


class NocolyMailPayload(BaseModel):
    """
    Pydantic model for NocolyMail webhook payload.
    Accepts any valid JSON object.
    """
    data: Dict[str, Any]
