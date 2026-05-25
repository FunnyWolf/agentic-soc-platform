from typing import Annotated, Any, Dict, List

from langgraph.graph import add_messages
from pydantic import BaseModel

from PLUGINS.SIRP.sirpcoremodel import ArtifactModel, AlertModel, CaseModel


class BaseAgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = []
    case: CaseModel = None
    alert: AlertModel = None
    artifact: ArtifactModel = None
    temp_data: Dict[str, Any] = {}
    analyze_result: Dict[str, Any] = {}
