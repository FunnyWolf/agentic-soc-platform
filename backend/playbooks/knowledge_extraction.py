from apps.agentic.analysis.knowledge import extract_knowledge_from_case
from apps.agentic.runtime.base import BasePlaybook


class Playbook(BasePlaybook):
    NAME = "Knowledge Extraction"
    DESC = "Extract reusable knowledge from a Case with an analyst verdict."
    TAGS = ["System", "LLM", "Knowledge"]

    def run(self):
        if self.case is None:
            raise ValueError("Knowledge Extraction playbook requires a linked case.")
        result = extract_knowledge_from_case(
            case=self.case,
            user_input=self.user_input,
            source=self.playbook_run,
        )
        return result.remark
