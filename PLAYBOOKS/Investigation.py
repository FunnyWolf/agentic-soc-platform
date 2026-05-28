from Lib.baseplaybook import BasePlaybook
from Lib.analysis import (
    build_analysis_input_json,
    build_analysis_record,
    build_case_analysis_patch,
    extract_knowledge_keywords,
    generate_investigation_report,
    search_knowledge_records,
)
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpbasemodel import AI_PROFILE_INVESTIGATION
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus


class Playbook(BasePlaybook):
    NAME = "Investigation"
    DESC = "Investigation"

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        trigger = f"playbook"
        case_row_id = self.param_source_row_id

        case = Case.get(case_row_id, lazy_load=False)
        if not case:
            self.logger.error(f"Case not found. row_id: {case_row_id}")
            return

        case_json = case.model_dump_json_for_ai(profile=AI_PROFILE_INVESTIGATION)
        knowledge_keywords = extract_knowledge_keywords(case_json)
        knowledge_records = search_knowledge_records(knowledge_keywords)
        discussions = Case.get_discussions_by_row_id(case_row_id) or []
        user_input = self.param_user_input or ""
        analysis_input_json = build_analysis_input_json(case_json, knowledge_keywords, knowledge_records, discussions, user_input)
        report = generate_investigation_report(analysis_input_json)
        analysis_record = build_analysis_record(
            trigger=trigger,
            queue_message_id=None,
            next_run_at=None,
            case=case,
            knowledge_keywords=knowledge_keywords,
            knowledge_records=knowledge_records,
            report=report,
        )
        case_patch = build_case_analysis_patch(case_row_id, report, analysis_record)

        Case.update(case_patch)
        self.logger.info(f"Case analysis completed. row_id: {case_row_id}, trigger: {trigger}")
        self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Case Investigation Success.")
