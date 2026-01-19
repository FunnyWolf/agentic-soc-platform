import json
from enum import Enum
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
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus


class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = []
    case: Dict[str, Any] = {}
    loop_count: int = 0


class ConfidenceLevel(str, Enum):
    """置信度枚举"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Severity(str, Enum):
    """严重性枚举"""
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


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
    confidence: ConfidenceLevel = Field(
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
    current_attack_stage: str | None = Field(
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

    def init(self):
        def preprocess_node(state: AgentState):
            case = Case.get_ai_friendly_data(self.param_source_rowid)
            content = f"Current Case Data (includes latest alert): {json.dumps(case)}"
            return {"case": case, "messages": [HumanMessage(content=content)]}

        def analyze_node(state: AgentState):
            system_prompt_template = self.load_system_prompt_template("L3_SOC_Analyst")
            system_message = system_prompt_template.format()

            llm_api = LLMAPI()
            llm = llm_api.get_model(tag=["structured_output", "function_calling"])

            llm_with_tools = llm.bind_tools([AgentKnowledge.internal_knowledge_base_search, AnalyzeResult])

            messages = [system_message] + state.messages

            # 熔断处理
            if state.loop_count >= MAX_ITERATIONS:
                messages.append(HumanMessage(
                    content="You have reached the maximum iterations limit. Based on all the information collected above, provide your final analysis using the AnalyzeResult tool immediately."))

            response = llm_with_tools.invoke(messages)
            return {"loop_count": state.loop_count + 1, "messages": [response]}

        def should_continue(state: AgentState):
            last_message = state.messages[-1]

            # 只要模型调用了最终报告工具，就去 output
            for tool_call in last_message.tool_calls:
                if tool_call["name"] == FINAL_TOOL_NAME:
                    return NODE_OUTPUT

            # 只有在还没到上限且模型想搜索时，才去 tools
            if state.loop_count < MAX_ITERATIONS:
                if last_message.tool_calls:
                    return NODE_TOOLS

            # 其他情况（包括达到上限后模型给出的非工具回复），重新回到分析节点由强制指令处理
            return NODE_ANALYZE

        def output_node(state: AgentState):
            last_message = state.messages[-1]

            analyze_call = next(
                tc for tc in last_message.tool_calls if tc["name"] == FINAL_TOOL_NAME
            )
            result_data = analyze_call["args"]
            analyze_result = AnalyzeResult(**result_data)

            case_field = [
                {"id": "severity", "value": analyze_result.new_severity},
                {"id": "confidence_ai", "value": analyze_result.confidence},
                {"id": "analysis_rationale_ai", "value": analyze_result.analysis_rationale},
                {"id": "attack_stage_ai", "value": analyze_result.current_attack_stage},
                {"id": "recommended_actions_ai", "value": analyze_result.recommended_actions},
            ]
            Case.update(self.param_source_rowid, case_field)

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
    params_debug = {'source_rowid': 'f0189cf8-44af-4c46-90c7-988a159bb34c', 'source_worksheet': 'case'}
    module = Playbook()
    # module._params = params_debug
    module.run()
