import json
import operator
from typing import Annotated, Dict, List

from langchain_core.messages import AnyMessage, ToolMessage, AIMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import Send
from pydantic import BaseModel, Field, ConfigDict

from AGENTS.agent_cmdb import AgentCMDB
from AGENTS.agent_siem import AgentSIEM
from AGENTS.agent_ti import AgentTI
from Lib.api import get_current_time_str
from Lib.baseplaybook import LanggraphPlaybook
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus

MAX_ITERATIONS = 3
PROMPT_LANG = None


class PlanningRecord(BaseModel):
    """Structured record for storing single-round planning"""
    iteration: int = Field(description="The current round")
    rationale: str = Field(description="The reasoning for the plan")
    plan: List[str] = Field(description="The specific list of tasks generated")

    # Helper methods can be added here to facilitate string conversion
    def to_markdown(self) -> str:
        tasks_str = ", ".join(self.plan)
        return (f"#### Round {self.iteration}\n"
                f"**Reasoning:** {self.rationale}\n"
                f"**Tasks Executed:** {tasks_str}\n")


class AnalystOutput(BaseModel):
    answer: str = Field(description="The final, concise answer to the investigation question")
    reasoning: str | List[str] = Field(description="The detailed reasoning process and key evidence supporting the final conclusion.")


# Define the structured output of the Planner
class HuntingPlan(BaseModel):
    # Allows generating multiple tasks at once, or an empty list to indicate the end
    current_plan: List[str] = Field(
        description="A list of specific questions to be investigated in parallel next. Returns an empty list if there are no more questions.")
    rationale: str = Field(description="The reason for making this plan")


class Finding(BaseModel):
    question: str = Field(description="The question to be investigated")
    answer: str = Field(description="The answer obtained from the investigation")
    reasoning: str | List[str] = Field(description="The reasoning process of the investigation")
    tool_calls: List = Field(default_factory=list, description="Tool call records")

    def to_markdown(self) -> str:
        return (f"\n"
                f"**Question:** {self.question}\n"
                f"**Reasoning:** {self.reasoning}\n"
                f"**Answer:** {self.answer}\n"
                f"\n\n\n"
                )


MAX_ITERATIONS_OF_FUNCTIONS_CALL = 10


class AnalystState(BaseModel):
    """
    Subgraph state: responsible for the execution of a single investigation task.
    Inherits from Pydantic BaseModel, supports default values and data validation.
    """
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )
    # Message history
    messages: Annotated[
        List[AnyMessage],
        add_messages
    ] = Field(
        default_factory=list,
        description="Used to store the message passing history between all nodes."
    )

    # Input: The specific question to be investigated
    question: str = Field(
        description="The specific question to be investigated, usually the starting point of user input."
    )

    # Input: Context
    case: Dict = Field(
        default_factory=dict,
        description="External context or additional data provided for this investigation task."
    )

    # Output: Final conclusion
    answer: str = Field(
        default="",
        description="The final conclusion or summary of the investigation task."
    )

    # Output: Reasoning process
    reasoning: str | List[str] = Field(
        default="",
        description="Detailed reasoning steps and evidence for the conclusion."
    )

    tool_calls: Annotated[
        List[Dict],
        operator.add
    ] = Field(
        default_factory=list,
        description="A log of tool calls and their results."
    )
    loop_count: int = Field(
        default=0,
        description="Count of function call iterations."
    )


class MainState(BaseModel):
    """
    [Main graph state]
    Responsible for global planning and summarization.
    """
    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )
    # Original case/global context
    case: Dict = Field(
        default_factory=dict,
        description="Original case or global context data."
    )

    # User intent
    user_intent: str = Field(
        default="",
        description="The initial request or core intent proposed by the user."
    )

    # Established overall goal
    hunting_objective: str = Field(
        default="",
        description="The overall goal that the entire graph needs to achieve, established based on the user's intent."
    )

    # Core memory: summary of subgraph return results
    # Use operator.add to ensure that the results returned by parallel subgraphs can be correctly appended and merged
    findings: Annotated[
        List[Finding],
        operator.add
    ] = Field(
        default_factory=list,
        description="A list of all results or findings collected from subgraphs or subtasks."
    )

    # List of planned tasks for the current batch
    current_plan: List[str] = Field(
        default_factory=list,
        description="A list of planned tasks to be executed in the current iteration or batch."
    )

    # Iteration count
    iteration_count: int = Field(
        default=0,
        description="A count of the number of main graph loops or iterations."
    )

    planning_history: Annotated[
        List[PlanningRecord],
        operator.add
    ] = Field(
        default_factory=list,
        description="Structured reasoning history record."
    )

    # Final output
    report: str = Field(
        default="",
        description="The final report summarized and organized based on all Findings."
    )


class Playbook(LanggraphPlaybook):
    TYPE = "CASE"
    NAME = "Threat Hunting Agent"

    def __init__(self):
        super().__init__()
        self.analyst_graph: CompiledStateGraph
        self.max_iterations = MAX_ITERATIONS
        self.build_analyst_graph()
        self.build_main_graph()

    def build_analyst_graph(self):
        def analyst_node(state: AnalystState):
            self.logger.debug(f"Analyst Node Invoked (Loop: {state.loop_count})")

            messages = state.messages

            # 1. 构造初始消息（如果是第一轮）
            if not messages:
                system_prompt_template = self.load_system_prompt_template("Analyst_System", lang=PROMPT_LANG)
                system_message = system_prompt_template.format()
                human_message = self.load_human_prompt_template("Analyst_Human", lang=PROMPT_LANG).format(
                    question=state.question,
                    case=state.case
                )
                messages = [system_message, human_message]

            llm_api = LLMAPI()

            # 2. 判断是否触发“强制总结”模式
            # 如果达到最大次数，就不再绑定工具，并修改 Prompt 要求其收尾
            if state.loop_count >= MAX_ITERATIONS_OF_FUNCTIONS_CALL - 1:
                self.logger.warning("Approaching max iterations, forcing analyst to summarize.")

                # 注入一条强制性指令，告诉 LLM 不要再查了
                stop_instruction = (
                    "\n\n[SYSTEM NOTICE]: You have reached the search limit. "
                    "Do not call any more tools. Please provide your final conclusion "
                    "based ONLY on the information gathered above."
                )
                # 将指令追加到最后一条消息中，或者作为新的 HumanMessage
                messages.append(HumanMessage(content=stop_instruction))

                # 使用不带工具绑定的模型，确保它只能输出文本
                base_llm = llm_api.get_model(tag=["powerful"])
                response: AIMessage = base_llm.invoke(messages)
            else:
                # 正常调查模式：绑定工具
                base_llm = llm_api.get_model(tag=["powerful", "function_calling"])
                llm_with_tools = base_llm.bind_tools([
                    AgentSIEM.siem_search_by_natural_language,
                    AgentCMDB.cmdb_query_asset,
                    AgentTI.threat_intelligence_lookup
                ])
                response: AIMessage = llm_with_tools.invoke(messages)

            # 3. 兜底逻辑：如果模型在最后关头依然执意返回 tool_calls（即便没绑定，有时也会幻觉）
            # 我们可以手动清除 tool_calls 以确保 should_continue 路由到 finalizer
            if state.loop_count >= MAX_ITERATIONS_OF_FUNCTIONS_CALL - 1:
                if response.tool_calls:
                    self.logger.info("Stripping hallucinated tool calls in final round.")
                    response.tool_calls = []

            # update record
            for message in messages:
                self.add_message_to_playbook(message, node="analyst_node")

            self.add_message_to_playbook(response, node="analyst_node")

            return {"loop_count": state.loop_count + 1, "messages": [response]}

        # Tool node
        tool_node = ToolNode([AgentSIEM.siem_search_by_natural_language, AgentCMDB.cmdb_query_asset, AgentTI.threat_intelligence_lookup])

        # Result generation node: when there is no tool call, it is responsible for converting the last message into a structured output
        def final_answer_node(state: AnalystState):
            self.logger.debug("Final Answer Node Invoked")

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

            llm_api = LLMAPI()
            formatter_llm = llm_api.get_model(tag=["cheap", "structured_output"])
            structured_llm = formatter_llm.with_structured_output(AnalystOutput)
            response: AnalystOutput = structured_llm.invoke(messages)

            # update record
            for message in messages:
                self.add_message_to_playbook(message, node="final_answer_node")

            self.add_message_to_playbook(response, node="final_answer_node")

            return {
                "answer": response.answer,
                "reasoning": response.reasoning,
                "tool_calls": tool_calls
            }

        # Conditional judgment
        def should_continue(state: AnalystState):
            last_message = state.messages[-1]
            if last_message.tool_calls:
                self.logger.debug("Routing to Tool Node")
                return 'tool'
            self.logger.debug("Routing to Finalizer Node")
            return 'finalizer'

        # --- Build graph ---
        builder = StateGraph(AnalystState)

        builder.add_node('analyst_node', analyst_node)
        builder.add_node('tool', tool_node)
        builder.add_node('finalizer', final_answer_node)  # Add new node

        builder.add_edge(START, 'analyst_node')

        builder.add_conditional_edges(
            'analyst_node',
            should_continue,
        )

        builder.add_edge('tool', 'analyst_node')  # After the tool is executed -> return to the model to see the result
        builder.add_edge('finalizer', END)  # After formatting -> end

        self.analyst_graph = builder.compile(name='analyst_graph')

    def build_main_graph(self):
        def intent_node(state: MainState):
            """Intent recognition: determine the overall goal"""
            self.logger.debug("Intent Node Invoked")

            # Get Case data
            case = Case.get_ai_friendly_data(rowid=self.param_source_rowid)

            # User intent
            user_intent = self.param_user_input

            if not user_intent:
                user_intent = "None (Auto-Pilot Mode)"

            # Load system prompt
            system_prompt_template = self.load_system_prompt_template("Intent_System", lang=PROMPT_LANG)
            system_message = system_prompt_template.format()

            human_message = self.load_human_prompt_template("Intent_Human", lang=PROMPT_LANG).format(case=case, user_intent=user_intent)

            # Construct few-shot examples
            few_shot_examples = [
            ]

            # Construct message list
            messages = [
                system_message,
                *few_shot_examples,
                human_message
            ]

            # Run
            llm_api = LLMAPI()
            llm = llm_api.get_model(tag="fast")
            response: AIMessage = llm.invoke(messages)

            # update record
            for message in messages:
                self.add_message_to_playbook(message, node="intent_node")

            self.add_message_to_playbook(response, node="intent_node")

            node_out = {
                "case": case,
                "user_intent": user_intent,
                "hunting_objective": response.content,
                "iteration_count": 0,
                "findings": []
            }
            return node_out

        def planner_node(state: MainState):
            """
            [Core logic]
            Check existing findings to decide what else to look for.
            Generate a batch of tasks at once.
            """
            self.logger.debug("Planner Node Invoked")

            findings = state.findings
            iteration_count = state.iteration_count
            hunting_objective = state.hunting_objective

            iteration_count = iteration_count + 1

            # Forced exit mechanism
            if iteration_count > self.max_iterations:
                self.logger.debug("Max iterations reached, terminating planning.")
                node_out = {"current_plan": []}
                return node_out

            # Load system prompt
            system_prompt_template = self.load_system_prompt_template("Planner_System", lang=PROMPT_LANG)

            system_message = system_prompt_template.format()

            history_md_list = []
            for record in findings:
                record: Finding
                # Call the object's own method, or customize the format here
                history_md_list.append(record.to_markdown())

            findings_str = "\n".join(history_md_list)
            additional_info = f"Report Time: {get_current_time_str()} \n Reporter: ASF CSIRT Team"
            human_message = self.load_human_prompt_template("Planner_Human", lang=PROMPT_LANG).format(case=state.case, hunting_objective=hunting_objective,
                                                                                                      findings=findings_str, iteration_count=iteration_count,
                                                                                                      additional_info=additional_info)
            # Construct few-shot examples
            few_shot_examples = [
            ]

            # Run
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag=["powerful", "structured_output"])

            # Construct message list
            messages = [
                system_message,
                *few_shot_examples,
                human_message
            ]
            llm = llm.with_structured_output(HuntingPlan)

            response: HuntingPlan = llm.invoke(messages)

            current_record = PlanningRecord(
                iteration=iteration_count,
                rationale=response.rationale,
                plan=response.current_plan
            )
            current_plan = response.current_plan

            self.logger.debug(f"Generated Plan for Round {iteration_count}")

            # update record
            for message in messages:
                self.add_message_to_playbook(message, node="planner_node")
            self.add_message_to_playbook(response, node="planner_node")

            node_out = {
                "current_plan": current_plan,
                "iteration_count": iteration_count,
                "planning_history": [current_record]

            }
            return node_out

        def continue_to_analysts(state: MainState):
            """
            Conditional edge logic:
            1. If the planner returns a list of tasks -> use the Send API to distribute them to the Subgraph in parallel
            2. If the planner returns an empty list -> end and go to write the report
            """
            current_plan = state.current_plan
            case = state.case
            iteration_count = state.iteration_count
            if not current_plan:
                # No more tasks, end
                self.logger.debug(f"Round {iteration_count},No more tasks in plan, proceeding to report.")
                return "report"

            # There are tasks, parallel distribution (Map)
            # Send(target node name, State passed to this node)
            self.logger.debug(f"Round {iteration_count},Dispatching {len(current_plan)} tasks to analyst subgraph.")
            return [
                Send("analyst_subgraph", AnalystState(question=question, case=case))
                for question in current_plan
            ]

        # --- Encapsulate Subgraph call ---
        def run_analyst_subgraph(state: AnalystState):
            self.logger.debug("Running Analyst Subgraph Wrapper")
            # The output of the graph is dict
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
            """Generate final report"""
            self.logger.debug("Reporter Node Invoked")
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

            # Load system prompt
            system_prompt_template = self.load_system_prompt_template("Report_System", lang=PROMPT_LANG)

            system_message = system_prompt_template.format()
            human_message = self.load_human_prompt_template("Report_Human", lang=PROMPT_LANG).format(hunting_objective=hunting_objective,
                                                                                                     findings=findings_str,
                                                                                                     planning_history=planning_history_str)
            # Construct few-shot examples
            few_shot_examples = [
            ]

            # Construct message list
            messages = [
                system_message,
                *few_shot_examples,
                human_message
            ]

            # Run
            llm_api = LLMAPI()
            llm = llm_api.get_model(tag=["powerful"])
            response = llm.invoke(messages)

            case_field = [
                {"id": "threat_hunting_report", "value": response.content},
                {"id": "threat_hunting_tool_calls", "value": json.dumps(total_tool_calls)},
            ]

            Case.update(self.param_source_rowid, case_field)

            # update record
            for message in messages:
                self.add_message_to_playbook(message, node="planner_node")
            self.add_message_to_playbook(response, node="planner_node")

            node_out = {"report": response.content}

            # update playbook status
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Threat Hunting Agent Finish.")
            return node_out

        # --- Build the main graph ---
        main_builder = StateGraph(MainState)

        main_builder.add_node("intent", intent_node)
        main_builder.add_node("planner", planner_node)
        # Note: The subgraph wrapper function is registered here
        main_builder.add_node("analyst_subgraph", run_analyst_subgraph)
        main_builder.add_node("report", reporter_node)

        # Process: Start -> Intent -> Planner
        main_builder.add_edge(START, "intent")
        main_builder.add_edge("intent", "planner")

        # Process: Planner -> (Map: execute multiple subgraphs in parallel) OR (Report)
        main_builder.add_conditional_edges(
            "planner",
            continue_to_analysts,
            ["analyst_subgraph", "report"]
        )

        # Process: After all subgraphs are executed -> (Reduce/Gather) -> automatically return to Planner
        # The mechanism of LangGraph is: after all parallel branches are executed, the next common node will be entered.
        # Since we want to go back to the Planner to reflect, we connect the edge back to the Planner.
        main_builder.add_edge("analyst_subgraph", "planner")

        main_builder.add_edge("report", END)

        self.graph = main_builder.compile(checkpointer=self.get_checkpointer())

    def run(self):
        self.run_graph()
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()

    params_debug = {
        'source_rowid': '47da1d00-c9bf-4b5f-8ab8-8877ec292b98',
        'source_worksheet': 'case',
        "user_input": "Has the host in the case been infected",
        "playbook_rowid": "9fb4a3e1-6ae7-47b2-9b15-95264272dff5"
    }
    module = Playbook()
    # module._params = params_debug
    module.run()
