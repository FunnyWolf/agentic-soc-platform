import json
from enum import Enum
from typing import Optional, Union, Dict, Any

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field, ConfigDict

from Lib.baseplaybook import LanggraphPlaybook
from Lib.llmapi import AgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.nocolyapi import WorksheetRow
from PLUGINS.SIRP.sirpapi import Alert, Artifact
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpapi import Notice
from PLUGINS.SIRP.sirpapi import Playbook as SIRPPlaybook


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


class Playbook(LanggraphPlaybook):
    TYPE = "CASE"
    NAME = "L3 SOC Analyst Agent"

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        def preprocess_node(state: AgentState):
            """预处理数据"""
            # worksheet = self.param("worksheet")
            rowid = self.param("rowid")

            case = WorksheetRow.get(Case.WORKSHEET_ID, rowid, include_system_fields=False)

            alerts = WorksheetRow.relations(Case.WORKSHEET_ID, rowid, "alert", relation_worksheet_id=Alert.WORKSHEET_ID, include_system_fields=False)
            for alert in alerts:
                artifacts = WorksheetRow.relations(Alert.WORKSHEET_ID, alert.get("rowId"), "artifact", relation_worksheet_id=Artifact.WORKSHEET_ID,
                                                   include_system_fields=False)
                alert["artifact"] = artifacts
            case["alert"] = alerts
            state.case = case
            return state

        # 定义node
        def analyze_node(state: AgentState):
            """AI分析Case数据"""

            # 加载system prompt
            system_prompt_template = self.load_system_prompt_template("L3_SOC_Analyst")

            system_message = system_prompt_template.format()

            # 构建few-shot示例
            few_shot_examples = [
                # HumanMessage(
                #     content=json.dumps({
                #         "requirement": ".",
                #     })
                # ),
                # AIMessage(
                #     content=json.dumps({
                #         "function": "the amount of pneumothorax",
                #     })
                # ),
            ]

            # 运行
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag="structured_output")

            # 构建消息列表
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=json.dumps(state.case))
            ]
            llm = llm.with_structured_output(AnalyzeResult)
            response: AnalyzeResult = llm.invoke(messages)
            state.analyze_result = response.model_dump()

            # response = llm.invoke(messages)
            # response = LLMAPI.extract_think(response)  # langchain chatollama bug临时方案
            # state.analyze_result = json.loads(response.content)
            return state

        def output_node(state: AgentState):
            """处理分析结果"""

            analyze_result: AnalyzeResult = AnalyzeResult(**state.analyze_result)

            case_row_id = self.param("rowid")

            case_field = [
                {"id": "severity", "value": analyze_result.new_severity},
                {"id": "confidence_ai", "value": analyze_result.confidence},
                {"id": "analysis_rationale_ai", "value": analyze_result.analysis_rationale},
                {"id": "attack_stage_ai", "value": analyze_result.current_attack_stage},
                {"id": "recommended_actions_ai", "value": analyze_result.recommended_actions},
            ]

            Case.update(case_row_id, case_field)

            Notice.send(self.param("user"), "Case_L3_SOC_Analyst_Agent Finish", f"rowid：{self.param('rowid')}")

            SIRPPlaybook.update_status_and_remark(self.param("playbook_rowid"), "Success", "Get suggestion by ai agent completed.")  # Success/Failed
            return state

        # 编译graph
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
    params_debug = {'rowid': '6635d1e1-406a-4dcb-9b07-797f584db207', 'worksheet': 'case'}
    module = Playbook()
    module._params = params_debug
    module.run()
