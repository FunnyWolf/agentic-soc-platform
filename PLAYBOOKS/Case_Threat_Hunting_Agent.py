import json
import operator
from typing import Annotated, Dict, List, Union

from langchain_core.messages import AnyMessage, ToolMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import Send
from pydantic import BaseModel, Field, ConfigDict

from AGENTS.cmdb_agent import CMDBAgent
from AGENTS.siem_agent import SIEMAgent
from AGENTS.ti_agent import TIAgent
from Lib.baseplaybook import LanggraphPlaybook
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.nocolyapi import WorksheetRow
from PLUGINS.SIRP.sirpapi import Alert, Artifact
from PLUGINS.SIRP.sirpapi import Case

MAX_ITERATIONS = 3
PROMPT_LANG = None


class PlanningRecord(BaseModel):
    """用于存储单轮规划的结构化记录"""
    iteration: int = Field(description="当前的轮次")
    rationale: str = Field(description="规划的推理思路")
    plan: List[str] = Field(description="生成的具体任务列表")

    # 可以在这里增加 helper 方法，方便转字符串
    def to_markdown(self) -> str:
        tasks_str = ", ".join(self.plan)
        return (f"### Round {self.iteration}\n"
                f"**Reasoning:** {self.rationale}\n"
                f"**Tasks Executed:** {tasks_str}\n")


class AnalystOutput(BaseModel):
    answer: str = Field(description="对调查问题的最终、简洁的回答")
    reasoning: Union[str, List[str]] = Field(description="支持最终结论的详细推理过程和关键证据。")


# 定义 Planner 的结构化输出
class HuntingPlan(BaseModel):
    # 允许一次生成多个任务，或者为空列表表示结束
    current_plan: List[str] = Field(description="接下来需要并行调查的具体问题列表。如果没有更多问题，返回空列表。")
    rationale: str = Field(description="制定该计划的理由")


class Finding(BaseModel):
    question: str = Field(description="需要调查的问题")
    answer: str = Field(description="调查得到的答案")
    reasoning: Union[str, List[str]] = Field(description="调查的推理过程")
    tool_calls: List = Field(default_factory=list, description="工具调用记录")

    def to_markdown(self) -> str:
        return (f"---\n"
                f"**Question:** {self.question}\n"
                f"**Reasoning:** {self.reasoning}\n"
                f"**Answer:** {self.answer}\n"
                f"---\n"
                )

    def to_markdown_for_planning(self) -> str:
        return (f"---\n"
                f"**Question:** {self.question}\n"
                f"**Answer:** {self.answer}\n"
                f"---\n"
                )


class AnalystState(BaseModel):
    """
    子图状态：负责单次调查任务的执行。
    继承自 Pydantic BaseModel，支持默认值和数据校验。
    """
    model_config = ConfigDict(
        # 允许在实例化时传入 LangChain 或 LangGraph 的内部对象
        # 避免 Pydantic 对复杂对象（如 Runnable, LLM）进行严格的字段检查
        arbitrary_types_allowed=True
    )
    # 消息历史 (LangGraph 核心)
    # 使用 Annotated 保持 LangGraph 的消息追加行为
    messages: Annotated[
        List[AnyMessage],
        add_messages
    ] = Field(
        default_factory=list,  # 确保 messages 字段默认是一个空列表
        description="用于存储所有节点间的消息传递历史。"
    )

    # 输入：要调查的具体问题
    question: str = Field(
        description="要调查的具体问题，通常是用户输入的起点。"
    )

    # 输入：上下文
    case: Dict = Field(
        default_factory=dict,  # 确保 case 默认是一个空字典
        description="提供给本次调查任务的外部上下文或额外数据。"
    )

    # 输出：最终结论
    answer: str = Field(
        default="",  # 默认值设置为空字符串
        description="调查任务的最终结论或摘要。"
    )

    # 输出：推理过程
    reasoning: Union[str, List[str]] = Field(
        default="",  # 默认值设置为空字符串
        description="得出结论的详细推理步骤及证据。"
    )

    tool_calls: Annotated[
        List[Dict],
        operator.add
    ] = Field(
        default_factory=list,
        description="A log of tool calls and their results."
    )


class MainState(BaseModel):
    """
    [主图状态]
    负责全局规划与汇总。
    """
    model_config = ConfigDict(
        # 允许在实例化时传入 LangChain 或 LangGraph 的内部对象
        # 避免 Pydantic 对复杂对象（如 Runnable, LLM）进行严格的字段检查
        arbitrary_types_allowed=True
    )
    # 原始案件/全局上下文
    case: Dict = Field(
        default_factory=dict,
        description="原始案件或全局上下文数据。"
    )

    # 用户意图
    user_intent: str = Field(
        default="",
        description="用户提出的初始请求或核心意图。"
    )

    # 确立的总目标
    hunting_objective: str = Field(
        default="",
        description="根据用户意图确立的，整个图需要达成的总目标。"
    )

    # 核心记忆：子图返回结果的汇总
    # 使用 operator.add 确保并行子图返回的结果能被正确追加合并
    findings: Annotated[
        List[Finding],
        operator.add
    ] = Field(
        default_factory=list,
        description="从子图或子任务中收集到的所有结果或发现的列表。"
    )

    # 当前批次的计划任务列表
    current_plan: List[str] = Field(
        default_factory=list,
        description="当前迭代或批次中需要执行的计划任务列表。"
    )

    # 迭代计数
    iteration_count: int = Field(
        default=0,
        description="主图循环或迭代的次数计数。"
    )

    planning_history: Annotated[
        List[PlanningRecord],  # 这里改为 PlanningRecord
        operator.add
    ] = Field(
        default_factory=list,
        description="结构化的推理历史记录。"
    )

    # 最终输出
    report: str = Field(
        default="",
        description="根据所有 Findings 汇总整理出的最终报告。"
    )


class Playbook(LanggraphPlaybook):
    TYPE = "CASE"
    NAME = "Threat Hunting Agent"

    def __init__(self):
        super().__init__()  # do not delete this code
        self.analyst_graph: CompiledStateGraph
        self.main_graph: CompiledStateGraph
        self.max_iterations = MAX_ITERATIONS
        self.build_analyst_graph()
        self.build_main_graph()

    def build_analyst_graph(self):
        def analyst_node(state: AnalystState):
            self.logger.info("Analyst Node Invoked")

            messages = state.messages

            # 如果是第一次进入（messages为空），构造初始 System/Human Prompt
            if not messages:
                system_prompt_template = self.load_system_prompt_template("Analyst_System", lang=PROMPT_LANG)
                system_message = system_prompt_template.format()
                human_message = self.load_human_prompt_template("Analyst_Human", lang=PROMPT_LANG).format(
                    question=state.question,
                    case=state.case
                )
                few_shot_examples = [
                ]
                messages = [
                    system_message,
                    *few_shot_examples,
                    human_message
                ]

            llm_api = LLMAPI()
            base_llm = llm_api.get_model(tag=["powerful", "function_calling"])
            llm_with_tools = base_llm.bind_tools([SIEMAgent.search, CMDBAgent.query_asset, TIAgent.lookup])
            response = llm_with_tools.invoke(messages)

            # 返回更新的消息列表，LangGraph 会自动追加到 state.messages
            return {"messages": [response]}

        # 工具节点
        tool_node = ToolNode([SIEMAgent.search, CMDBAgent.query_asset, TIAgent.lookup])

        # 结果生成节点：当没有工具调用时，负责把最后的消息转化为结构化输出
        def final_answer_node(state: AnalystState):
            self.logger.info("Final Answer Node Invoked")

            # handle tool_calls
            tool_calls = []
            for message in state.messages:
                if isinstance(message, AIMessage):
                    if message.tool_calls:
                        for tool_call in message.tool_calls:
                            tool_calls.append(tool_call)
                elif isinstance(message, ToolMessage):
                    try:
                        text = json.loads(message.text)
                    except Exception:
                        text = message.text
                    tool_calls.append({"tool_call_id": message.tool_call_id, "name": message.name, "status": message.status, "text": text})
                else:
                    continue

            # get answer reasoning
            last_message = state.messages[-1]
            llm_api = LLMAPI()
            formatter_llm = llm_api.get_model(tag=["cheap", "structured_output"])
            structured_llm = formatter_llm.with_structured_output(AnalystOutput)

            system_prompt_template = self.load_system_prompt_template("Analyst_Final_System", lang=PROMPT_LANG)
            system_message = system_prompt_template.format()
            human_message = self.load_human_prompt_template("Analyst_Final_Human", lang=PROMPT_LANG).format(
                question=state.question,
                content_to_format=last_message.content
            )
            few_shot_examples = [
            ]
            messages = [
                system_message,
                *few_shot_examples,
                human_message
            ]

            response = structured_llm.invoke(messages)
            self.logger.info(f"[final_answer_node] Question: {state.question}")
            self.logger.info(f"[final_answer_node] Answer: {response.answer}")
            return {
                "answer": response.answer,
                "reasoning": response.reasoning,
                "tool_calls": tool_calls
            }

        # 条件判断
        def should_continue(state: AnalystState):
            last_message = state.messages[-1]
            if last_message.tool_calls:
                self.logger.info("Routing to Tool Node")
                return 'tool'
            self.logger.info("Routing to Finalizer Node")
            return 'finalizer'

        # --- 构建图 ---
        builder = StateGraph(AnalystState)

        builder.add_node('analyst_node', analyst_node)
        builder.add_node('tool', tool_node)
        builder.add_node('finalizer', final_answer_node)  # 新增节点

        builder.add_edge(START, 'analyst_node')

        builder.add_conditional_edges(
            'analyst_node',
            should_continue,
        )

        builder.add_edge('tool', 'analyst_node')  # 工具执行完 -> 回到模型看结果
        builder.add_edge('finalizer', END)  # 格式化完 -> 结束

        self.analyst_graph = builder.compile(name='analyst_graph')

    def build_main_graph(self):
        def intent_node(state: MainState):
            """意图识别：确定总目标"""
            self.logger.info("Intent Node Invoked")
            # 获取数据
            rowid = self.param("rowid")

            case = WorksheetRow.get(Case.WORKSHEET_ID, rowid, include_system_fields=False)

            alerts = WorksheetRow.relations(Case.WORKSHEET_ID, rowid, "alert", relation_worksheet_id=Alert.WORKSHEET_ID, include_system_fields=False)
            for alert in alerts:
                artifacts = WorksheetRow.relations(Alert.WORKSHEET_ID, alert.get("rowId"), "artifact", relation_worksheet_id=Artifact.WORKSHEET_ID,
                                                   include_system_fields=False)
                alert["artifact"] = artifacts
            case["alert"] = alerts
            # case = json.dumps(case, indent=2)

            user_intent = self.param("user_input")

            if not user_intent:
                user_intent = "None (Auto-Pilot Mode)"

            # 加载system prompt
            system_prompt_template = self.load_system_prompt_template("Intent_System", lang=PROMPT_LANG)

            system_message = system_prompt_template.format()
            human_message = self.load_human_prompt_template("Intent_Human", lang=PROMPT_LANG).format(case=case, user_intent=user_intent)

            # 构建few-shot示例
            few_shot_examples = [
            ]

            # 运行
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag="fast")

            # 构建消息列表
            messages = [
                system_message,
                *few_shot_examples,
                human_message
            ]

            resp = llm.invoke(messages)

            node_out = {
                "case": case,
                "user_intent": user_intent,
                "hunting_objective": resp.content,
                "iteration_count": 0,
                "findings": []
            }
            return node_out

        def planner_node(state: MainState):
            """
            [核心逻辑]
            查看已有的 findings，决定还需要查什么。
            一次性生成一批任务。
            """
            self.logger.info("Planner Node Invoked")

            findings = state.findings
            iteration_count = state.iteration_count
            hunting_objective = state.hunting_objective

            iteration_count = iteration_count + 1

            # 强制退出机制
            if iteration_count > self.max_iterations:
                self.logger.info("Max iterations reached, terminating planning.")
                node_out = {"current_plan": []}
                return node_out

            # 加载system prompt
            system_prompt_template = self.load_system_prompt_template("Planner_System", lang=PROMPT_LANG)

            system_message = system_prompt_template.format()

            history_md_list = []
            for record in findings:
                record: Finding
                # 调用对象自己的方法，或者在这里自定义格式
                history_md_list.append(record.to_markdown_for_planning())

            findings_str = "\n".join(history_md_list)

            human_message = self.load_human_prompt_template("Planner_Human", lang=PROMPT_LANG).format(hunting_objective=hunting_objective,
                                                                                                      findings=findings_str,
                                                                                                      iteration_count=iteration_count,
                                                                                                      )
            # 构建few-shot示例
            few_shot_examples = [
            ]

            # 运行
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag=["powerful", "structured_output"])

            # 构建消息列表
            messages = [
                system_message,
                *few_shot_examples,
                human_message
            ]
            llm = llm.with_structured_output(HuntingPlan)

            plan_result: HuntingPlan = llm.invoke(messages)

            current_record = PlanningRecord(
                iteration=iteration_count,
                rationale=plan_result.rationale,
                plan=plan_result.current_plan
            )
            current_plan = plan_result.current_plan

            self.logger.info(f"Generated Plan for Round {iteration_count}")
            for plan in current_plan:
                self.logger.info(f" - {plan}")

            node_out = {
                "current_plan": current_plan,
                "iteration_count": iteration_count,
                "planning_history": [current_record]

            }
            return node_out

        def continue_to_analysts(state: MainState):
            """
            条件边逻辑：
            1. 如果 planner 返回了任务列表 -> 使用 Send API 并行分发给 Subgraph
            2. 如果 planner 返回空列表 -> 结束，去写报告
            """
            current_plan = state.current_plan
            case = state.case
            iteration_count = state.iteration_count
            if not current_plan:
                # 没有任务了，结束
                self.logger.info(f"Round {iteration_count},No more tasks in plan, proceeding to report.")
                return "report"

            # 有任务，并行分发 (Map)
            # Send(目标节点名, 传递给该节点的State)
            self.logger.info(f"Round {iteration_count},Dispatching {len(current_plan)} tasks to analyst subgraph.")
            return [
                Send("analyst_subgraph", AnalystState(question=question, case=case))
                for question in current_plan
            ]

        # --- 封装 Subgraph 调用 ---
        # 这是一个 Wrapper 函数，用于接收 Subgraph 的输出并格式化给 MainState
        def run_analyst_subgraph(state: AnalystState):
            self.logger.info("Running Analyst Subgraph Wrapper")
            # graph的输出是dict
            result: dict = self.analyst_graph.invoke(state)
            analyst_state = AnalystState(**result)
            finding = Finding(
                question=analyst_state.question,
                answer=analyst_state.answer,
                reasoning=analyst_state.reasoning,
                tool_calls=analyst_state.tool_calls)

            node_out = {"findings": [finding]}
            return node_out

        def reporter_node(state: MainState):
            """生成最终报告"""
            self.logger.info("Reporter Node Invoked")
            findings = state.findings
            hunting_objective = state.hunting_objective

            # planning_history
            history_md_list = []
            for record in state.planning_history:
                record: PlanningRecord
                history_md_list.append(record.to_markdown())

            planning_history_str = "\n".join(history_md_list)

            # findings
            total_tool_calls = []
            history_md_list = []
            for record in findings:
                record: Finding
                history_md_list.append(record.to_markdown())
                total_tool_calls.extend(record.tool_calls)

            findings_str = "\n".join(history_md_list)

            # 加载system prompt
            system_prompt_template = self.load_system_prompt_template("Report_System", lang=PROMPT_LANG)

            system_message = system_prompt_template.format()
            human_message = self.load_human_prompt_template("Report_Human", lang=PROMPT_LANG).format(hunting_objective=hunting_objective,
                                                                                                     findings=findings_str,
                                                                                                     planning_history=planning_history_str)
            # 构建few-shot示例
            few_shot_examples = [
            ]

            # 运行
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag=["powerful"])

            # 构建消息列表
            messages = [
                system_message,
                *few_shot_examples,
                human_message
            ]

            resp = llm.invoke(messages)

            case_row_id = self.param("rowid")

            case_field = [
                {"id": "threat_hunting_report", "value": resp.content},
                {"id": "threat_hunting_tool_calls", "value": json.dumps(total_tool_calls)},
            ]

            Case.update(case_row_id, case_field)

            node_out = {"report": resp.content}
            return node_out

        # --- 构建主图 ---
        main_builder = StateGraph(MainState)

        main_builder.add_node("intent", intent_node)
        main_builder.add_node("planner", planner_node)
        # 注意：这里注册的是 subgraph wrapper 函数
        main_builder.add_node("analyst_subgraph", run_analyst_subgraph)
        main_builder.add_node("report", reporter_node)

        # 流程：Start -> Intent -> Planner
        main_builder.add_edge(START, "intent")
        main_builder.add_edge("intent", "planner")

        # 流程：Planner -> (Map: 并行执行多个子图) OR (Report)
        main_builder.add_conditional_edges(
            "planner",
            continue_to_analysts,
            ["analyst_subgraph", "report"]
        )

        # 流程：所有子图执行完后 -> (Reduce/Gather) -> 自动回到 Planner
        # LangGraph 的机制是：并行分支全部执行完后，才会进入下一个公共节点。
        # 既然我们要回 Planner 反思，就把边连回 Planner。
        main_builder.add_edge("analyst_subgraph", "planner")

        main_builder.add_edge("report", END)

        self.graph = main_builder.compile(checkpointer=self.get_checkpointer())

    def run(self):
        self.run_graph()
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASF.settings")
    django.setup()

    params_debug = {'rowid': 'e07f7b79-caac-43aa-b7d3-d99d2354c5c9', 'worksheet': 'case', "user_input": "Has the host in the case been infected"}
    module = Playbook()
    module._params = params_debug
    module.run()
