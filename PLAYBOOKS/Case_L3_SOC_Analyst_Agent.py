import json
from enum import Enum
from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field, ConfigDict

from Lib.baseplaybook import LanggraphPlaybook
from Lib.llmapi import AgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus


class ConfidenceLevel(str, Enum):
    """Confidence Level"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Severity(str, Enum):
    """Severity Level"""
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AnalyzeResult(BaseModel):
    """Structure for extracting user information from text"""
    # config
    model_config = ConfigDict(use_enum_values=True)

    original_severity: Severity = Field(description="Original alert severity")
    new_severity: Severity = Field(description="Recommended new severity level")
    confidence: ConfidenceLevel = Field(description="Confidence score, only one of 'Low', 'Medium', or 'High'")
    analysis_rationale: str | None = Field(description="Analysis process and reasons", default=None)
    current_attack_stage: str | dict[str, Any] | None = Field(description="e.g., 'T1059 - Command and Control', 'Lateral Movement'", default=None)
    recommended_actions: str | dict[str, Any] | None = Field(description="e.g., 'Isolate host 10.1.1.5'", default=None)


class Playbook(LanggraphPlaybook):
    TYPE = "CASE"
    NAME = "L3 SOC Analyst Agent"

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        def preprocess_node(state: AgentState):
            """Preprocess data"""
            case = Case.get_ai_friendly_data(self.param_source_rowid)
            state.case = case
            return state

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
                HumanMessage(content=json.dumps(state.case))
            ]
            llm = llm.with_structured_output(AnalyzeResult)
            response: AnalyzeResult = llm.invoke(messages)
            state.analyze_result = response.model_dump()

            # response = llm.invoke(messages)
            # response = LLMAPI.extract_think(response)  # Temporary solution for langchain chatollama bug
            # state.analyze_result = json.loads(response.content)
            return state

        def output_node(state: AgentState):
            """Process analysis results"""

            analyze_result: AnalyzeResult = AnalyzeResult(**state.analyze_result)

            case_field = [
                {"id": "severity", "value": analyze_result.new_severity},
                {"id": "confidence_ai", "value": analyze_result.confidence},
                {"id": "analysis_rationale_ai", "value": analyze_result.analysis_rationale},
                {"id": "attack_stage_ai", "value": analyze_result.current_attack_stage},
                {"id": "recommended_actions_ai", "value": analyze_result.recommended_actions},
            ]
            Case.update(self.param_source_rowid, case_field)

            self.send_notice("Case_L3_SOC_Analyst_Agent Finish", f"rowid:{self.param_source_rowid}")
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
    params_debug = {'source_rowid': '47da1d00-c9bf-4b5f-8ab8-8877ec292b98', 'source_worksheet': 'case'}
    module = Playbook()
    # module._params = params_debug
    module.run()
