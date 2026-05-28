from Lib.baseplaybook import BasePlaybook
from Lib.analysis import extract_knowledge_from_case
from PLUGINS.SIRP.sirpapi import Case, Knowledge
from PLUGINS.SIRP.sirpbasemodel import AI_PROFILE_INVESTIGATION
from PLUGINS.SIRP.sirpextramodel import KnowledgeModel, KnowledgeSource, PlaybookJobStatus


class Playbook(BasePlaybook):
    NAME = "Knowledge Extraction"
    DESC = "Extract reusable knowledge from a closed Case and store it in the Knowledge worksheet."

    def __init__(self):
        super().__init__()  # do not delete this code

    def run(self):
        case_row_id = self.param_source_row_id

        # 1. Load case
        case = Case.get(case_row_id, lazy_load=False)
        if not case:
            message = f"Case not found. row_id: {case_row_id}"
            self.logger.error(message)
            self.update_playbook_status(PlaybookJobStatus.FAILED, message)
            return

        # 2. Check verdict — skip cases with no verdict
        if not case.verdict:
            message = "Case has no verdict, skipping knowledge extraction."
            self.logger.info(message)
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, message)
            return

        # 3. Serialize case for LLM
        case_json = case.model_dump_json_for_ai(profile=AI_PROFILE_INVESTIGATION)

        # 4. Fetch discussions
        discussions = Case.get_discussions_by_row_id(case_row_id) or []

        # 5. Call LLM to extract knowledge
        user_input = self.param_user_input or ""
        extraction = extract_knowledge_from_case(case.id or "", case_json, discussions, user_input)

        # 6. If no knowledge, log and return success
        if not extraction.has_knowledge:
            message = f"No knowledge extracted: {extraction.reason}"
            self.logger.info(message)
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, message)
            return

        # 7. Create Knowledge record
        knowledge = KnowledgeModel(
            title=extraction.title,
            body=extraction.body,
            source=KnowledgeSource.CASE,
            tags=extraction.tags or [],
        )
        Knowledge.create(knowledge)

        message = f"Knowledge created: {extraction.title}. Reason: {extraction.reason}"
        self.logger.info(message)
        self.update_playbook_status(PlaybookJobStatus.SUCCESS, message)
