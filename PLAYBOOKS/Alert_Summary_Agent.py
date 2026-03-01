import json
from typing import List, Dict, Any

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

from Lib.baseplaybook import LanggraphPlaybook
from Lib.llmapi import BaseAgentState
from PLUGINS.AlienVaultOTX.alienvaultotx import AlienVaultOTX
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIEM.models import KeywordSearchInput, KeywordSearchOutput
from PLUGINS.SIEM.tools import SIEMToolKit
from PLUGINS.SIRP.sirpapi import Alert
from PLUGINS.SIRP.sirpmodel import AlertModel, PlaybookModel


class SearchKeyword(BaseModel):
    keyword: str = Field(description="Extract specific, high-fidelity strings valuable for full-text SIEM searches. Do not extract generic terms.")
    is_ioc: bool = Field(
        description="Set to true ONLY for public IPs, domains, URLs, and file hashes. Set to false for internal IPs, file paths, command lines, or general strings.")


class AlertExtraction(BaseModel):
    keywords: List[SearchKeyword] = Field(default_factory=list, description="List of extracted keywords and their IOC status.")
    start_time: str = Field(
        description="The start time for the log search, in UTC ISO8601 format. Format: 'YYYY-MM-DDTHH:MM:SSZ'. Example: '2026-02-04T06:00:00Z'")
    end_time: str = Field(description="The end time for the log search, in UTC ISO8601 format. Format: 'YYYY-MM-DDTHH:MM:SSZ'. Example: '2026-02-04T06:00:00Z'")


class AgentState(BaseAgentState):
    keywords: List[SearchKeyword] = []
    start_time: str = ""
    end_time: str = ""
    logs: List[KeywordSearchOutput] = []
    threat_intel_data: Dict[str, Any] = {}
    summary_ai: str = ""


class Playbook(LanggraphPlaybook):
    TYPE = "ALERT"
    NAME = "Alert Summary Agent"

    def __init__(self):
        super().__init__()
        self.init()

    def init(self):
        def preprocess_node(state: AgentState):
            alert = Alert.get(self.param_source_rowid)
            return {"alert": alert}

        def extract_keywords_node(state: AgentState):
            alert: AlertModel = state.alert
            system_prompt_template = self.load_system_prompt_template("extract_agent_system")
            system_message = system_prompt_template.format()

            llm_api = LLMAPI()
            llm = llm_api.get_model(tag="fast").with_structured_output(AlertExtraction)

            messages = [system_message, HumanMessage(content=alert.model_dump_json())]
            alert_extraction: AlertExtraction = llm.invoke(messages)

            return {
                "keywords": alert_extraction.keywords,
                "start_time": alert_extraction.start_time,
                "end_time": alert_extraction.end_time
            }

        def query_threat_intel_node(state: AgentState):
            threat_intel_data = {}
            for keyword in state.keywords:
                if keyword.is_ioc:
                    try:
                        result = AlienVaultOTX.query(keyword.keyword)
                        threat_intel_data[keyword.keyword] = result
                    except Exception as e:
                        self.logger.warning(f"AlienVaultOTX query failed for {keyword.keyword}: {str(e)}")
                        continue
            return {"threat_intel_data": threat_intel_data}

        def search_siem_logs_node(state: AgentState):
            logs: List[KeywordSearchOutput] = []
            for keyword in state.keywords:
                try:
                    results = SIEMToolKit.keyword_search(
                        KeywordSearchInput(
                            keyword=keyword.keyword,
                            time_range_start=state.start_time,
                            time_range_end=state.end_time
                        )
                    )
                    logs.extend(results)
                except Exception as e:
                    self.logger.warning(f"SIEM search failed for {keyword.keyword}: {str(e)}")
                    continue

            return {"logs": logs}

        def generate_summary_node(state: AgentState):
            alert: AlertModel = state.alert
            system_prompt_template = self.load_system_prompt_template("summary_agent_system")
            system_message = system_prompt_template.format()

            ti_summary = json.dumps(state.threat_intel_data, ensure_ascii=False,
                                    indent=2) if state.threat_intel_data else "No threat intelligence data available."
            logs_summary = [log.model_dump_json() for log in state.logs] if state.logs else []

            human_message = self.load_human_prompt_template("summary_agent_human").format(
                alert_data=alert.model_dump_json(),
                threat_intel=ti_summary,
                siem_logs=logs_summary
            )

            llm_api = LLMAPI()
            llm = llm_api.get_model(tag="fast")

            messages = [system_message, human_message]
            response = llm.invoke(messages)

            return {"summary_ai": response.content}

        def output_node(state: AgentState):
            summary_ai = state.summary_ai
            model = AlertModel(rowid=self.param_source_rowid, summary_ai=summary_ai)
            Alert.update(model)
            self.agent_state = state
            return state

        workflow = StateGraph(AgentState)

        workflow.add_node("preprocess_node", preprocess_node)
        workflow.add_node("extract_keywords_node", extract_keywords_node)
        workflow.add_node("query_threat_intel_node", query_threat_intel_node)
        workflow.add_node("search_siem_logs_node", search_siem_logs_node)
        workflow.add_node("generate_summary_node", generate_summary_node)
        workflow.add_node("output_node", output_node)

        workflow.set_entry_point("preprocess_node")
        workflow.add_edge("preprocess_node", "extract_keywords_node")
        workflow.add_edge("extract_keywords_node", "query_threat_intel_node")
        workflow.add_edge("query_threat_intel_node", "search_siem_logs_node")
        workflow.add_edge("search_siem_logs_node", "generate_summary_node")
        workflow.add_edge("generate_summary_node", "output_node")
        workflow.set_finish_point("output_node")

        self.agent_state = AgentState()
        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True

    def run(self):
        self.run_graph()
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    model = PlaybookModel(source_worksheet='alert', source_rowid='03e21470-edd8-4b19-8ffb-628d5203a1c3')
    module = Playbook()
    module._playbook_model = model

    module.run()
