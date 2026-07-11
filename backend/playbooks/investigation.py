from apps.agentic.analysis.analysis import run_case_analysis
from apps.agentic.runtime.base import BasePlaybook


class Playbook(BasePlaybook):
    NAME = "Investigation"
    DESC = "Generate an AI investigation report for the linked case."
    TAGS = ["System", "LLM", "Case"]

    def run(self):
        if self.case is None:
            raise ValueError("Investigation playbook requires a linked case.")
        result = run_case_analysis(
            case=self.case,
            trigger="playbook",
            user_input=self.user_input,
            source=self.playbook_run,
        )
        return f"Investigation completed: {result.report.digest}"
