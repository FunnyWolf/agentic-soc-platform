import json
from typing import Dict, Any, Annotated, List

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel

from Lib.baseplaybook import LanggraphPlaybook
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.nocolyapi import WorksheetRow
from PLUGINS.SIRP.sirpapi import Alert, Artifact
from PLUGINS.SIRP.sirpapi import Notice
from PLUGINS.SIRP.sirpapi import Playbook as SIRPPlaybook


class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages]

    alert: Dict
    suggestion: str


class Playbook(LanggraphPlaybook):
    TYPE = "ALERT"  # 分类标签
    NAME = "Alert Analysis Agent"  # 剧本名称

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        def preprocess_node(state: AgentState):
            """预处理数据"""
            # worksheet = self.param("worksheet")
            rowid = self.param("rowid")
            worksheet = self.param("worksheet")
            alert = WorksheetRow.get(worksheet, rowid, include_system_fields=False)
            artifacts = WorksheetRow.relations(Alert.WORKSHEET_ID, alert.get("rowId"), "artifact", relation_worksheet_id=Artifact.WORKSHEET_ID,
                                               include_system_fields=False)
            alert["artifact"] = artifacts
            state.alert = alert
            return state

        # 定义node
        def analyze_node(state: AgentState):
            """AI分析告警数据"""

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

            llm = llm_api.get_model(tag="fast")

            # 构建消息列表
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=json.dumps(state.alert))
            ]
            response = llm.invoke(messages)
            response = LLMAPI.extract_think(response)  # langchain chatollama bug临时方案
            state.suggestion = response.content
            return state

        def output_node(state: AgentState):
            """处理分析结果"""

            suggestion = state.suggestion
            fields = [
                {"id": "suggestion_ai", "value": suggestion},
            ]
            rowid = self.param("rowid")
            WorksheetRow.update(Alert.WORKSHEET_ID, rowid, fields)

            self.agent_state = state

            Notice.send(self.param("user"), "Alert_Suggestion_Gen_By_LLM output_node Finish", f"rowid：{self.param('rowid')}")

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
        self.agent_state = AgentState(messages=[], alert={}, suggestion="")
        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True

    def run(self):
        self.run_graph()
        return


if __name__ == "__main__":
    params_debug = {'rowid': '113d3844-792d-47f9-b4f5-29e6f9b3c776', 'worksheet': 'alert'}
    module = Playbook()
    module._params = params_debug
    module.run()
