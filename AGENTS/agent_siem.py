from typing import Annotated, List, Literal, Any, Optional

from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

from Lib.api import get_current_time_str
from Lib.baseplaybook import LanggraphPlaybook
from Lib.log import logger
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIEM.tools import SIEMToolKit

# Define constants for graph nodes
AGENT_NODE = "AGENT"
TOOL_NODE = "TOOL_NODE"
MAX_ITERATIONS = 10

_graph_agent_instance = None


def _get_graph_agent() -> "GraphAgent":
    global _graph_agent_instance
    if _graph_agent_instance is None:
        _graph_agent_instance = GraphAgent()
    return _graph_agent_instance


# Define the state for the graph
class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = Field(default_factory=list)
    loop_count: int = Field(default=0, description="Count of agent iterations")
    max_iterations: int = Field(default=MAX_ITERATIONS)


# Main class for the SIEM Agent, serving as the public interface
class AgentSIEM:
    @staticmethod
    def siem_search_by_natural_language(
            natural_query: Annotated[str, "A natural language query for SIEM. (e.g., 'Find connections from 10.10.10.10 to any malicious IP')"],
            time_range_start: Annotated[Optional[str], "UTC start time in ISO8601 format: YYYY-MM-DDTHH:MM:SSZ. Provide together with time_range_end."] = None,
            time_range_end: Annotated[Optional[str], "UTC end time in ISO8601 format: YYYY-MM-DDTHH:MM:SSZ. Provide together with time_range_start."] = None,
    ) -> Annotated[str, "A summary of the findings from the SIEM search."]:
        """
        Searches SIEM logs by a natural language query.
        """
        if (time_range_start and not time_range_end) or (time_range_end and not time_range_start):
            raise ValueError("time_range_start and time_range_end must be provided together.")

        adjusted_query = natural_query
        if time_range_start and time_range_end:
            adjusted_query = f"{natural_query}\nTime range (UTC): start={time_range_start}, end={time_range_end}."

        agent = _get_graph_agent()
        result = agent.siem_query(adjusted_query)
        return result


tools = [SIEMToolKit.explore_schema, SIEMToolKit.execute_adaptive_query, SIEMToolKit.keyword_search]


# LangGraph-based agent for complex, stateful queries
class GraphAgent(LanggraphPlaybook):

    def __init__(self):
        super().__init__()
        self._system_prompt_template = self.load_system_prompt_template("system_prompt")
        self._schema_info = self._get_schema_info()
        self._llm_api = LLMAPI()
        self._llm_base = self._llm_api.get_model(tag=["fast"])
        self._llm_with_tools = self._llm_api.get_model(tag=["fast", "function_calling"]).bind_tools(tools)
        self.graph = self._build_graph()

    @classmethod
    def _get_schema_info(cls) -> str:
        """Get available SIEM indices information from schema explorer."""
        try:
            schema_list = SIEMToolKit.explore_schema()
            schema_text = "Available SIEM Indices:\n"
            for item in schema_list:
                schema_text += f"- {item['name']}: {item['description']}\n"
            return schema_text
        except Exception as e:
            logger.warning(f"Failed to retrieve schema info: {e}")
            return "Available SIEM Indices: (Failed to retrieve)"

    def _build_graph(self) -> CompiledStateGraph:
        """Constructs the LangGraph agent graph."""
        tool_node = ToolNode(tools)

        def route_after_agent(state: AgentState) -> Literal["TOOL_NODE", "__end__"]:
            last_message = state.messages[-1]
            if state.loop_count >= state.max_iterations:
                self.logger.debug(f"Max iterations ({state.max_iterations}) reached, ending agent.")
                return END
            if last_message.tool_calls:
                tool_info = "\n".join([f"  [{idx}] Name: {tc.get('name', 'N/A')}, ID: {tc.get('id', 'N/A')}, Args: {tc.get('args', {})}" for idx, tc in
                                       enumerate(last_message.tool_calls, 1)])
                self.logger.debug(f"Tool calls detected: {len(last_message.tool_calls)} tool(s) {tool_info}")
                return TOOL_NODE
            self.logger.debug(f"No tool calls detected, ending agent execution")
            return END

        def agent_node(state: AgentState):
            self.logger.debug(f"Agent Node Invoked (Loop: {state.loop_count})")
            self.logger.debug(f"Current messages count: {len(state.messages)}")

            system_message = self._system_prompt_template.format(
                CURRENT_UTC_TIME=get_current_time_str(),
                AVAILABLE_INDICES=self._schema_info
            )

            messages = [system_message, *state.messages]
            self.logger.debug(f"Total messages to send to LLM: {len(messages)}")

            if state.loop_count >= state.max_iterations - 1:
                self.logger.warning("Approaching max iterations, forcing agent to provide final answer.")

                stop_instruction = (
                    "\n\n[SYSTEM NOTICE]: You have reached the search limit. "
                    "Do not call any more tools. Please provide your final conclusion "
                    "based ONLY on the information gathered above."
                )
                messages.append(HumanMessage(content=stop_instruction))
                self.logger.debug("Stop instruction appended to messages")

                self.logger.debug("Using base LLM model (no tool binding) for final response")
                response: AIMessage = self._llm_base.invoke(messages)
                self.logger.debug(f"Final response generated, tool_calls count: {len(response.tool_calls) if response.tool_calls else 0}")
            else:
                self.logger.debug(f"Using LLM with tools binding, available tools: {len(tools)}")
                response: AIMessage = self._llm_with_tools.invoke(messages)
                self.logger.debug(f"Response generated, tool_calls count: {len(response.tool_calls) if response.tool_calls else 0}")

            if state.loop_count >= state.max_iterations - 1:
                if response.tool_calls:
                    self.logger.info("Stripping hallucinated tool calls in final round.")
                    response.tool_calls = []

            return {"messages": [response], "loop_count": state.loop_count + 1}

        workflow = StateGraph(AgentState)
        workflow.add_node(AGENT_NODE, agent_node)
        workflow.add_node(TOOL_NODE, tool_node)

        workflow.set_entry_point(AGENT_NODE)
        workflow.add_conditional_edges(AGENT_NODE, route_after_agent)
        workflow.add_edge(TOOL_NODE, AGENT_NODE)

        compiled_graph = workflow.compile(checkpointer=self.get_checkpointer())
        self.logger.debug(f"LangGraph workflow compiled successfully")
        return compiled_graph

    def siem_query(self, query: str, clear_thread: bool = True, max_iterations: int = MAX_ITERATIONS) -> str:
        """Executes a query against the graph."""
        self.logger.info(f"SIEM Query started: {query[:100]}...")
        if clear_thread:
            self.graph.checkpointer.delete_thread(self.module_name)
            self.logger.debug(f"Deleted previous thread state for module: {self.module_name}")

        config = RunnableConfig(configurable={"thread_id": self.module_name})
        self.logger.debug(f"RunnableConfig created with thread_id: {self.module_name}")

        initial_state = AgentState(messages=[HumanMessage(content=query)], loop_count=0, max_iterations=max_iterations)
        self.logger.debug(f"Initial state created")

        self.logger.info(f"Starting graph invocation...")
        final_state = self.graph.invoke(initial_state, config)
        self.logger.info(f"Graph invocation completed")

        result = final_state['messages'][-1].content
        self.logger.info(f"Query result extracted, result length: {len(result)} characters")
        return result
