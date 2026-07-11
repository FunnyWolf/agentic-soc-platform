import json
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from langchain_core.messages import SystemMessage, HumanMessage

from apps.settings.runtime_config import get_prompt_language
from integrations.llm.llmapi import LLMAPI

INVESTIGATION_SYSTEM_PROMPT = "investigation.system"
INVESTIGATION_KNOWLEDGE_KEYWORD_PROMPT = "investigation.knowledge_keywords"
KNOWLEDGE_EXTRACTION_PROMPT = "knowledge_extraction.system"

ANALYSIS_SYSTEM_PROMPT_PATH = ("investigation", "System")
KNOWLEDGE_KEYWORD_PROMPT_PATH = ("investigation", "KnowledgeKeywords")
KNOWLEDGE_EXTRACTION_PROMPT_PATH = ("knowledge_extraction", "System")


@dataclass(frozen=True)
class PromptSpec:
    directory: str
    name: str


PROMPT_CATALOG = {
    INVESTIGATION_SYSTEM_PROMPT: PromptSpec(*ANALYSIS_SYSTEM_PROMPT_PATH),
    INVESTIGATION_KNOWLEDGE_KEYWORD_PROMPT: PromptSpec(*KNOWLEDGE_KEYWORD_PROMPT_PATH),
    KNOWLEDGE_EXTRACTION_PROMPT: PromptSpec(*KNOWLEDGE_EXTRACTION_PROMPT_PATH),
}


def _prompt_file_path(spec, *, language=None):
    prompt_language = language or get_prompt_language()
    filename = f"{spec.name}_{prompt_language}.md"
    return Path(settings.BASE_DIR) / "data" / "playbooks" / spec.directory / filename


def _prompt_spec(prompt_id):
    try:
        return PROMPT_CATALOG[prompt_id]
    except KeyError:
        raise KeyError(f"Unknown agentic prompt id: {prompt_id}") from None


def read_prompt(prompt_id, *, language=None):
    spec = _prompt_spec(prompt_id)
    return _prompt_file_path(spec, language=language).read_text(encoding="utf-8")


STRUCTURED_OUTPUT_MODEL_TAG = "structured_output"


def invoke_structured_llm(*, prompt_id, payload, output_schema, model_tag=STRUCTURED_OUTPUT_MODEL_TAG):
    model = LLMAPI().get_model(tag=model_tag).with_structured_output(output_schema)
    return model.invoke(
        [
            SystemMessage(content=read_prompt(prompt_id)),
            HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
        ]
    )
