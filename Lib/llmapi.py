from typing import Annotated, Any, Dict, List

from langchain_core.prompts import SystemMessagePromptTemplate, HumanMessagePromptTemplate
from langgraph.graph import add_messages
from pydantic import BaseModel

from Lib.log import logger
from PLUGINS.SIRP.sirpcoremodel import ArtifactModel, AlertModel, CaseModel


class BaseAgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = []
    case: CaseModel = None
    alert: AlertModel = None
    artifact: ArtifactModel = None
    temp_data: Dict[str, Any] = {}
    analyze_result: Dict[str, Any] = {}


def load_system_prompt_template(template_path):
    """Load system prompt template"""
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            system_prompt_template: SystemMessagePromptTemplate = SystemMessagePromptTemplate.from_template(f.read())
            logger.debug(f"Loaded system prompt template from: {template_path}")
            return system_prompt_template
    except Exception as e:
        logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
        raise e


def load_human_prompt_template(template_path):
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            human_prompt_template: HumanMessagePromptTemplate = HumanMessagePromptTemplate.from_template(f.read())
            logger.debug(f"Loaded human prompt template from: {template_path}")
            return human_prompt_template
    except Exception as e:
        logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
        raise e
