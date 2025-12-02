import json
from enum import Enum
from typing import Optional, Union, Dict, Any

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field, ConfigDict

from Lib.api import get_current_time_string
from Lib.basemodule import LanggraphModule
from Lib.llmapi import AgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.grouprule import GroupRule
from PLUGINS.SIRP.sirpapi import create_alert_with_group_rule, InputAlert, Case


class ConfidenceLevel(str, Enum):
    """置信度等级"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Severity(str, Enum):
    """置信度等级"""
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
    analysis_rationale: str = Field(description="Analysis process and reasons", default=None)
    current_attack_stage: Optional[Union[str, Dict[str, Any]]] = Field(description="e.g., 'T1059 - Command and Control', 'Lateral Movement'", default=None)
    recommended_actions: Optional[Union[str, Dict[str, Any]]] = Field(description="e.g., 'Isolate host 10.1.1.5'", default=None)


class Module(LanggraphModule):
    THREAD_NUM = 2

    def __init__(self):
        super().__init__()
        self.init()

    def init(self):
        def alert_preprocess_node(state: AgentState):
            """Preprocess alert data"""
            # Get raw alert from stream
            alert = self.read_message()
            if alert is None:
                return

            state.alert = alert
            artifact: list = alert.get("artifact")
            alert_date: str = alert.get("alert_date")
            rule_name = "Suspicious command and control (C2) communication"

            hostname = "unknown-hostname"
            for one in artifact:
                if one.get("type") == "hostname":
                    hostname = one.get("value")

            source = alert.get("source", "NDR")
            raw_log = alert.get("raw_log", {})
            tags = alert.get("tags", [])
            severity = alert.get("severity", "Low")
            description = alert.get("description", "")

            input_alert: InputAlert = {
                "source": source,
                "rule_id": self.module_name,
                "rule_name": rule_name,
                "name": f"{rule_name} hostname: {hostname}",
                "alert_date": alert_date,
                "created_date": get_current_time_string(),
                "tags": tags,
                "severity": severity,
                "description": description,
                "reference": "https://your-siem-or-device-url.com/data?source=123456",
                "source_data_identifier": "ndr-alert-00000001",
                "artifact": artifact,
                "raw_log": raw_log
            }

            workbook = self.load_markdown_template("NDR_L2_WORKBOOK").format()
            rule = GroupRule(
                rule_id=self.module_name,
                rule_name=rule_name,
                deduplication_fields=["hostname"],
                source="NDR",
                workbook=workbook
            )

            case_row_id = create_alert_with_group_rule(input_alert, rule)
            state.temp_data = {"case_row_id": case_row_id}

            return state

        # Define nodes
        def alert_analyze_node(state: AgentState):
            """AI analyzes alert data"""

            case_row_id = state.temp_data.get("case_row_id")
            case = Case.get(case_row_id)
            fields_useful_to_llm = ['title', 'alert', 'tags', 'severity', 'type', 'description', 'close_reason', 'alert_date', 'case_id', 'note', 'summary',
                                    'attachment']
            case_for_llm = {}
            for key in case:
                if key in fields_useful_to_llm:
                    case_for_llm[key] = case[key]

            state.temp_data["case"] = case

            # Load system prompt
            system_prompt_template = self.load_system_prompt_template(f"senior_ndr_cyber_security_expert")

            # Demonstrate how to generate dynamic prompts
            system_message = system_prompt_template.format()

            # Build few-shot examples
            few_shot_examples = []

            # Build message list
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=json.dumps(case)),
            ]

            # Execute
            openai_api = LLMAPI()

            llm = openai_api.get_model(tag="structured_output")
            llm = llm.with_structured_output(AnalyzeResult)
            response: AnalyzeResult = llm.invoke(messages)
            state.analyze_result = response.model_dump()
            return state

        def alert_output_node(state: AgentState):
            """Process analysis results"""
            analyze_result: AnalyzeResult = AnalyzeResult(**state.analyze_result)

            case_row_id = state.temp_data.get("case_row_id")

            case_field = [
                {"id": "severity", "value": analyze_result.new_severity},
                {"id": "confidence_ai", "value": analyze_result.confidence},
                {"id": "analysis_rationale_ai", "value": analyze_result.analysis_rationale},
                {"id": "attack_stage_ai", "value": analyze_result.current_attack_stage},
                {"id": "recommended_actions_ai", "value": analyze_result.recommended_actions},
            ]

            case_row_id = Case.update(case_row_id, case_field)

            return state

        # Compile graph
        workflow = StateGraph(AgentState)

        workflow.add_node("alert_preprocess_node", alert_preprocess_node)
        workflow.add_node("alert_analyze_node", alert_analyze_node)
        workflow.add_node("alert_output_node", alert_output_node)

        workflow.set_entry_point("alert_preprocess_node")
        workflow.add_edge("alert_preprocess_node", "alert_analyze_node")
        workflow.add_edge("alert_analyze_node", "alert_output_node")
        workflow.set_finish_point("alert_output_node")

        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True


if __name__ == "__main__":
    module = Module()
    module.debug_message_id = "0-0"
    module.run()
