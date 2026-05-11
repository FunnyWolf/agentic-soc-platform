from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field, ConfigDict

from Lib.baseplaybook import LanggraphPlaybook
from Lib.llmapi import BaseAgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpbasemodel import AI_PROFILE_INVESTIGATION
from PLUGINS.SIRP.sirpcoremodel import Severity, AttackStage, Confidence, CaseModel
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus, PlaybookModel


class AnalyzeResult(BaseModel):
    """Structure for extracting user information from text"""
    # config
    model_config = ConfigDict(use_enum_values=True)

    original_severity: Severity = Field(description="Original alert severity")
    new_severity: Severity = Field(description="Recommended new severity level")
    confidence: Confidence = Field(description="Confidence score, only one of 'Low', 'Medium', or 'High'")
    analysis_rationale: str | None = Field(description="Analysis process and reasons", default=None)
    attack_stage: AttackStage = Field(description="e.g. 'Lateral Movement'", default=None)
    recommended_actions: str | dict[str, Any] | None = Field(description="e.g., 'Isolate host 10.1.1.5'", default=None)


class AgentState(BaseAgentState):
    analyze_result: AnalyzeResult = None


class Playbook(LanggraphPlaybook):
    NAME = "L3 SOC Analyst Agent"
    DESC = "L3 SOC Analyst Agent"

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        def preprocess_node(state: AgentState):
            """Preprocess data"""
            case = Case.get(self.param_source_row_id)
            return {"case": case}

        # Define node
        def analyze_node(state: AgentState):
            """AI analyzes Case data"""

            # Load system prompt
            system_prompt_template = self.load_system_prompt_template("L3_SOC_Analyst")

            system_message = system_prompt_template.format()

            # Construct few-shot examples
            few_shot_examples = [
            ]

            # Run
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag="structured_output")

            # Construct message list
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=state.case.model_dump_json_for_ai(profile=AI_PROFILE_INVESTIGATION))
            ]
            llm = llm.with_structured_output(AnalyzeResult)
            response: AnalyzeResult = llm.invoke(messages)
            self.logger.debug(f"Analyze result: {response.model_dump()}")
            return {"analyze_result": response}

        def output_node(state: AgentState):
            """Process analysis results"""

            analyze_result: AnalyzeResult = state.analyze_result

            case_new = CaseModel(row_id=self.param_source_row_id,
                                 severity_ai=analyze_result.new_severity,
                                 confidence_ai=analyze_result.confidence,
                                 )
            Case.update(case_new)

            self.send_notice("Case_L3_SOC_Analyst_Agent Finish", f"row_id:{self.param_source_row_id}")
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Get suggestion by ai agent completed.")
            return state

        # Compile graph
        workflow = StateGraph(AgentState)

        workflow.add_node("preprocess_node", preprocess_node)
        workflow.add_node("analyze_node", analyze_node)
        workflow.add_node("output_node", output_node)

        workflow.set_entry_point("preprocess_node")
        workflow.add_edge("preprocess_node", "analyze_node")
        workflow.add_edge("analyze_node", "output_node")
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
    model = PlaybookModel(source_row_id='141a4bd0-f3cf-4e0c-91b6-f8d9fff6f653')
    module = Playbook()
    module._playbook_model = model

    module.run()
