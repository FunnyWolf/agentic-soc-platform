import json
from typing import Annotated, Any, Dict, List

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, START, END, add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field, ConfigDict

from AGENTS.agent_knowledge import AgentKnowledge
from Lib.baseplaybook import LanggraphPlaybook
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus, CaseModel, PlaybookModel
from PLUGINS.SIRP.sirpmodel import Severity, Confidence


class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = []
    case: CaseModel = None
    loop_count: int = 0


class AnalyzeResult(BaseModel):
    """
    [最终研判报告工具]
    当且仅当你通过分析原始 Case 数据,并结合 KnowledgeAgent.search 搜索到的外部情报得出定论后,调用此工具.
    调用此工具将提交最终分析结果并结束任务.
    """
    model_config = ConfigDict(use_enum_values=True)

    original_severity: Severity = Field(
        description="该案件(Case)在挂载新告警之前的初始严重程度."
    )
    new_severity: Severity = Field(
        description="""
        基于新证据重新评估后的严重程度.
        判定逻辑：
        1. 如果新告警显示攻击链向后期演进(如从初始访问进入到权限维持或数据外泄),应显著提升级别.
        2. 如果新告警仅是已知风险的重复(噪声),应保持或降低级别.
        """
    )
    confidence: Confidence = Field(
        description="""
        研判置信度.
        - High: 存在异构证据交叉验证(例如 NDR 流量告警与 EDR 进程告警指向同一行为).
        - Medium: 证据吻合攻击逻辑,但缺乏多维数据源佐证.
        - Low: 证据模糊,可能是误报.
        """
    )
    analysis_rationale: str | None = Field(
        default=None,
        description="详细推理过程.需包含识别到的新证据、新旧告警关联逻辑以及搜索工具返回的情报如何辅助了判断."
    )
    attack_stage: str | None = Field(
        default=None,
        description="参考 MITRE ATT&CK 战术名称,必须是字符串(如：'T1059 - Command and Control', 'Lateral Movement')."
    )
    recommended_actions: str | None = Field(
        default=None,
        description="具体且可执行的应急响应建议,必须是字符串(如：'Isolate host 10.1.1.5', 'Reset user password')."
    )


NODE_PREPROCESS = "preprocess_node"
NODE_ANALYZE = "analyze_node"
NODE_TOOLS = "tools"
NODE_OUTPUT = "output_node"

FINAL_TOOL_NAME = AnalyzeResult.__name__
MAX_ITERATIONS = 5


class Playbook(LanggraphPlaybook):
    TYPE = "CASE"
    NAME = "L3 SOC Analyst Agent With Tools"

    def __init__(self):
        super().__init__()
        self.init()

    def _get_tool_call_by_name(self, message: Any, tool_name: str) -> Dict[str, Any] | None:
        """获取指定名称的工具调用"""
        if not hasattr(message, 'tool_calls'):
            return None
        for tool_call in message.tool_calls:
            if tool_call.get("name") == tool_name:
                return tool_call
        return None

    def _has_final_tool_call(self, message: Any) -> bool:
        """检查是否调用了最终工具"""
        return self._get_tool_call_by_name(message, FINAL_TOOL_NAME) is not None

    def _has_any_tool_call(self, message: Any) -> bool:
        """检查是否有工具调用"""
        return hasattr(message, 'tool_calls') and len(message.tool_calls) > 0

    def _is_reached_max_iterations(self, loop_count: int) -> bool:
        """检查是否达到最大迭代次数"""
        return loop_count >= MAX_ITERATIONS

    def init(self):
        def preprocess_node(state: AgentState):
            case = Case.get(self.param_source_rowid)
            content = f"Current Case Data (includes latest alert): {json.dumps(case.model_dump_for_ai())}"
            return {"case": case, "messages": [HumanMessage(content=content)]}

        def analyze_node(state: AgentState):
            system_prompt_template = self.load_system_prompt_template("L3_SOC_Analyst")
            system_message = system_prompt_template.format()

            llm_api = LLMAPI()
            llm = llm_api.get_model(tag=["structured_output", "function_calling"])
            llm_with_tools = llm.bind_tools([AgentKnowledge.internal_knowledge_base_search, AnalyzeResult])

            messages = [system_message] + state.messages

            if self._is_reached_max_iterations(state.loop_count):
                messages.append(HumanMessage(
                    content="You have reached the maximum iterations limit. Based on all the information collected above, provide your final analysis using the AnalyzeResult tool immediately."))

            response = llm_with_tools.invoke(messages)
            for message in messages:
                self.add_message_to_playbook(message, node="analyze_node")
            self.add_message_to_playbook(response, node="analyze_node")
            return {"loop_count": state.loop_count + 1, "messages": [response]}

        def should_continue(state: AgentState):
            last_message = state.messages[-1]

            if self._has_final_tool_call(last_message):
                return NODE_OUTPUT

            if self._is_reached_max_iterations(state.loop_count):
                return NODE_ANALYZE

            if self._has_any_tool_call(last_message):
                return NODE_TOOLS

            return NODE_ANALYZE

        def output_node(state: AgentState):
            last_message = state.messages[-1]

            analyze_call = self._get_tool_call_by_name(last_message, FINAL_TOOL_NAME)
            result_data = analyze_call["args"]
            analyze_result = AnalyzeResult(**result_data)

            case_new = CaseModel(rowid=self.param_source_rowid,
                                 severity_ai=analyze_result.new_severity,
                                 confidence_ai=analyze_result.confidence,
                                 analysis_rationale_ai=analyze_result.analysis_rationale,
                                 attack_stage_ai=analyze_result.attack_stage,
                                 recommended_actions_ai=analyze_result.recommended_actions,
                                 )
            Case.update(case_new)

            self.send_notice("Case_L3_SOC_Analyst_Agent Finish", f"rowid:{self.param_source_rowid}")
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, "SOC analysis completed with potential tool-assisted enrichment.")
            return {"analyze_result": result_data}

        workflow = StateGraph(AgentState)

        workflow.add_node(NODE_PREPROCESS, preprocess_node)
        workflow.add_node(NODE_ANALYZE, analyze_node)
        workflow.add_node(NODE_TOOLS, ToolNode([AgentKnowledge.internal_knowledge_base_search]))
        workflow.add_node(NODE_OUTPUT, output_node)

        workflow.add_edge(START, NODE_PREPROCESS)
        workflow.add_edge(NODE_PREPROCESS, NODE_ANALYZE)

        workflow.add_conditional_edges(
            NODE_ANALYZE,
            should_continue,
            [NODE_TOOLS, NODE_OUTPUT, END]
        )

        workflow.add_edge(NODE_TOOLS, NODE_ANALYZE)
        workflow.add_edge(NODE_OUTPUT, END)

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
    model = PlaybookModel(source_worksheet='case', source_rowid='141a4bd0-f3cf-4e0c-91b6-f8d9fff6f653')
    module = Playbook()
    module._playbook_model = model

    module.run()
