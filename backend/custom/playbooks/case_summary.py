import json

from django.db import transaction
from langchain_core.messages import HumanMessage, SystemMessage

from apps.agentic.analysis.profiles import serialize_case_for_investigation
from apps.agentic.runtime.base import BasePlaybook
from integrations.llm.llmapi import LLMAPI


class Playbook(BasePlaybook):
    NAME = "Case Summary"
    DESC = "Generate a concise analyst-facing summary for the linked Case."
    TAGS = ["Custom", "LLM", "Case"]
    PROMPT_SLUG = "case_summary"

    def run(self):
        if self.case is None:
            raise ValueError("Case Summary playbook requires a linked case.")

        payload = {
            "case": serialize_case_for_investigation(self.case),
            "user_input": self.user_input,
        }
        result = LLMAPI(temperature=0.0).get_model().invoke(
            [
                SystemMessage(content=self.read_prompt("System")),
                HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
            ]
        )
        summary = _content_as_text(result.content).strip()
        if not summary:
            raise ValueError("LLM returned an empty case summary.")

        with transaction.atomic():
            case = type(self.case).objects.select_for_update().get(pk=self.case.pk)
            case.summary = summary
            case.save(update_fields=["summary", "updated_at"])

        return f"Case summary updated: {summary[:160]}"


def _content_as_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text", item)))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)
