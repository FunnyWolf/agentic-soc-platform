from datetime import datetime
from pathlib import Path

from langchain_core.messages import HumanMessage

from Lib.baseplaybook import BasePlaybook
from Lib.configs import DATA_DIR
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.analysis import AnalysisRecord, InvestigationReport
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpbasemodel import AI_PROFILE_INVESTIGATION
from PLUGINS.SIRP.sirpcoremodel import CaseModel
from PLUGINS.SIRP.sirpextramodel import PlaybookModel


class Playbook(BasePlaybook):
    NAME = "Investigation"
    DESC = "Investigation"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        trigger = f"playbook:{self.NAME}"
        case_row_id = self.param_source_row_id

        case = Case.get(case_row_id, lazy_load=False)
        if not case:
            self.logger.error(f"Case not found. row_id: {case_row_id}")
            return

        prompt_path = Path(DATA_DIR) / "SYSTEM" / "ANALYSIS" / "System_EN.md"
        content = case.model_dump_json_for_ai(profile=AI_PROFILE_INVESTIGATION)
        system_message = self.load_system_prompt_template(prompt_path).format()

        llm_api = LLMAPI()
        llm = llm_api.get_model(tag="structured_output").with_structured_output(InvestigationReport)

        messages = [
            system_message,
            HumanMessage(content=content)
        ]
        report: InvestigationReport = llm.invoke(messages)

        case_new = CaseModel(
            row_id=case_row_id,
            verdict_ai=report.verdict,
            severity_ai=report.severity,
            impact_ai=report.impact,
            priority_ai=report.priority,
            confidence_ai=report.confidence,
            investigation_report_ai_json=AnalysisRecord(
                trigger=trigger,
                analysis_last_started_at=(
                    case.analysis_last_started_at.isoformat() if case.analysis_last_started_at else None
                ),
                analysis_last_completed_at=datetime.now().astimezone().isoformat(),
                report=report,
            ).model_dump_json(),
        )
        Case.update(case_new)
        self.logger.info(f"Case analysis completed. row_id: {case_row_id}, trigger: {trigger}")


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    model = PlaybookModel(source_row_id='58cac985-341e-4391-814a-c58733a61d35')
    module = Playbook()
    module._playbook_model = model

    module.run()
