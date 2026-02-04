from typing import Annotated, List, Literal, Any

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

from Lib.api import get_current_time_str
from Lib.baseplaybook import LanggraphPlaybook
from Lib.configs import DATA_DIR
from Lib.llmapi import load_system_prompt_template
from Lib.log import logger
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIEM.tools import SIEMToolKit

# Define constants for graph nodes
AGENT_NODE = "AGENT"
TOOL_NODE = "TOOL_NODE"
MAX_ITERATIONS = 10


# Define the state for the graph
class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = Field(default_factory=list)
    loop_count: int = Field(default=0, description="Count of agent iterations")


# Main class for the SIEM Agent, serving as the public interface
class AgentSIEM:
    @staticmethod
    def siem_search_by_natural_language(
            natural_query: Annotated[str, "A natural language query for SIEM. (e.g., 'Find connections from 10.10.10.10 to any malicious IP')"]
    ) -> Annotated[str, "A summary of the findings from the SIEM search."]:
        """
        Searches SIEM logs by translating a natural language query into an SPL query,
        executing it, and returning a summarized result.
        """
        agent = GraphAgent()
        result = agent.siem_query(natural_query)
        return result


tools = [SIEMToolKit.explore_schema, SIEMToolKit.execute_adaptive_query]


# LangGraph-based agent for complex, stateful queries
class GraphAgent(LanggraphPlaybook):

    def __init__(self):
        super().__init__()
        self.graph = self._build_graph()

    def _build_graph(self) -> CompiledStateGraph:
        """Constructs the LangGraph agent graph."""
        tool_node = ToolNode(tools)

        def route_after_agent(state: AgentState) -> Literal["TOOL_NODE", "__end__"]:
            last_message = state.messages[-1]
            if state.loop_count >= MAX_ITERATIONS:
                self.logger.debug(f"Max iterations ({MAX_ITERATIONS}) reached, ending agent.")
                return END
            if last_message.tool_calls:
                tool_info = "\n".join([f"  [{idx}] Name: {tc.get('name', 'N/A')}, ID: {tc.get('id', 'N/A')}, Args: {tc.get('args', {})}" for idx, tc in
                                       enumerate(last_message.tool_calls, 1)])
                self.logger.debug(f"Tool calls detected: {len(last_message.tool_calls)} tool(s)\n{tool_info}\nRouting to TOOL_NODE for execution")
                return TOOL_NODE
            self.logger.debug(f"No tool calls detected, ending agent execution")
            return END

        def agent_node(state: AgentState):
            self.logger.debug(f"Agent Node Invoked (Loop: {state.loop_count})")
            self.logger.debug(f"Current messages count: {len(state.messages)}")

            system_message = self.load_system_prompt_template(f"system_prompt").format(CURRENT_UTC_TIME=get_current_time_str())

            messages = [system_message, *state.messages]
            self.logger.debug(f"Total messages to send to LLM: {len(messages)}")

            if state.loop_count >= MAX_ITERATIONS - 1:
                self.logger.warning("Approaching max iterations, forcing agent to provide final answer.")

                stop_instruction = (
                    "\n\n[SYSTEM NOTICE]: You have reached the search limit. "
                    "Do not call any more tools. Please provide your final conclusion "
                    "based ONLY on the information gathered above."
                )
                messages.append(HumanMessage(content=stop_instruction))
                self.logger.debug("Stop instruction appended to messages")

                llm_api = LLMAPI()
                base_llm = llm_api.get_model(tag=["fast"])
                self.logger.debug(f"Using base LLM model (no tool binding) for final response")
                response: AIMessage = base_llm.invoke(messages)
                self.logger.debug(f"Final response generated, tool_calls count: {len(response.tool_calls) if response.tool_calls else 0}")
            else:
                llm_api = LLMAPI()
                llm = llm_api.get_model(tag=["fast", "function_calling"])
                llm_with_tools = llm.bind_tools(tools)
                self.logger.debug(f"Using LLM with tools binding, available tools: {len(tools)}")
                response: AIMessage = llm_with_tools.invoke(messages)
                self.logger.debug(f"Response generated, tool_calls count: {len(response.tool_calls) if response.tool_calls else 0}")

            if state.loop_count >= MAX_ITERATIONS - 1:
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

    def siem_query(self, query: str) -> str:
        """Executes a query against the graph."""
        self.logger.info(f"SIEM Query started: {query[:100]}...")
        self.graph.checkpointer.delete_thread(self.module_name)
        self.logger.debug(f"Deleted previous thread state for module: {self.module_name}")

        config = RunnableConfig(configurable={"thread_id": self.module_name})
        self.logger.debug(f"RunnableConfig created with thread_id: {self.module_name}")

        initial_state = AgentState(messages=[HumanMessage(content=query)], loop_count=0)
        self.logger.debug(f"Initial state created")

        self.logger.info(f"Starting graph invocation...")
        final_state = self.graph.invoke(initial_state, config)
        self.logger.info(f"Graph invocation completed")

        result = final_state['messages'][-1].content
        self.logger.info(f"Query result extracted, result length: {len(result)} characters")
        return result


# Alternative, simpler agent implementation using create_agent
def create_siem_agent(
        query: Annotated[str, "A natural language query for SIEM."]
) -> Annotated[str, "A summary of the findings from the SIEM search."]:
    """
a simpler, stateless agent created using the create_agent factory function from langchain.agents.
    """

    logger.info(f"Creating SIEM agent with query: {query[:100]}...")
    prompt_path = os.path.join(DATA_DIR, "Agent_SIEM", "system_prompt.md")
    logger.debug(f"Loading system prompt from: {prompt_path}")
    system_prompt = load_system_prompt_template(prompt_path).format(CURRENT_UTC_TIME=get_current_time_str())
    logger.debug(f"System prompt loaded successfully")

    llm_api = LLMAPI()
    llm = llm_api.get_model(tag=["fast", "function_calling"])
    logger.debug(f"LLM model obtained with tags: ['fast', 'function_calling']")

    logger.debug(f"Creating agent with {len(tools)} tools")
    agent = create_agent(llm, tools, system_prompt=system_prompt)
    logger.debug(f"Agent created successfully")

    logger.info(f"Invoking agent...")
    response = agent.invoke({"messages": [HumanMessage(content=query)]})
    logger.info(f"Agent invocation completed")

    result = response['messages'][-1].content
    logger.info(f"Agent result extracted, result length: {len(result)} characters")
    return result


# Test code
if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()

    # print("\n--- Using create_agent for Query ---")
    # test_query = "Have there been any suspicious logins for the user 'admin' on Windows machines?"
    # result_simple = create_siem_agent(test_query)
    # print(result_simple)

    print("\n--- Using create_agent for Query ---")
    test_query = "最近5分钟192.168.1.150使用ssh访问了哪些内网主机?"
    result_simple = AgentSIEM.siem_search_by_natural_language(test_query)
    print(result_simple)
