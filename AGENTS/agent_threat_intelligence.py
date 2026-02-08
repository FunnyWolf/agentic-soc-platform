from typing import Annotated, Literal, Any, List

from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

from Lib.baseplaybook import LanggraphPlaybook
from Lib.log import logger
from PLUGINS.AlienVaultOTX.alienvaultotx import AlienVaultOTX
from PLUGINS.LLM.llmapi import LLMAPI

AGENT_NODE = "AGENT"
TOOL_NODE = "TOOL_NODE"
MAX_ITERATIONS = 5

_graph_agent_instance = None


def _get_graph_agent() -> "GraphAgent":
    global _graph_agent_instance
    if _graph_agent_instance is None:
        _graph_agent_instance = GraphAgent()
    return _graph_agent_instance


class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = Field(default_factory=list)
    loop_count: int = Field(default=0, description="Count of agent iterations")
    max_iterations: int = Field(default=MAX_ITERATIONS)


class AgentThreatIntelligence(object):

    @staticmethod
    def threat_intelligence_lookup(
            ioc_type: Annotated[Literal["ip", "domain", "hash", "url"], "The type of IOC. Supported: 'ip', 'domain', 'hash', 'url'"],
            ioc_value: Annotated[str, "The value of the IOC (e.g., '1.1.1.1' or 'a1b2...')"],
    ) -> Annotated[str, "Threat intelligence report including risk score and categories"]:
        """
        Check Threat Intelligence reputation for an artifact.
        """
        agent = _get_graph_agent()
        query = f"IOC Type: {ioc_type}\nIOC Value: {ioc_value}"
        result = agent.threat_intelligence_query(query)
        return result


tools = [AlienVaultOTX.query_url, AlienVaultOTX.query_ip, AlienVaultOTX.query_file]


class GraphAgent(LanggraphPlaybook):

    def __init__(self):
        super().__init__()
        self._system_prompt_template = self.load_system_prompt_template("system_prompt")
        self._llm_api = LLMAPI()
        self._llm_base = self._llm_api.get_model(tag=["fast"])
        self._llm_with_tools = self._llm_api.get_model(tag=["fast", "function_calling"]).bind_tools(tools)
        self.graph = self._build_graph()

    def _build_graph(self) -> CompiledStateGraph:
        tool_node = ToolNode(tools)

        def route_after_agent(state: AgentState) -> Literal["TOOL_NODE", "__end__"]:
            last_message = state.messages[-1]
            if state.loop_count >= state.max_iterations:
                logger.debug(f"Max iterations ({state.max_iterations}) reached, ending agent.")
                return END
            if last_message.tool_calls:
                return TOOL_NODE
            logger.debug(f"No tool calls detected, ending agent execution")
            return END

        def agent_node(state: AgentState):
            logger.debug(f"Agent Node Invoked (Loop: {state.loop_count})")

            system_message = self._system_prompt_template

            messages = [system_message.format(), *state.messages]

            if state.loop_count >= state.max_iterations - 1:
                stop_instruction = (
                    "\n\n[SYSTEM NOTICE]: You have reached the search limit. "
                    "Do not call any more tools. Please provide your final conclusion "
                    "based ONLY on the information gathered above."
                )
                messages.append(HumanMessage(content=stop_instruction))
                response: AIMessage = self._llm_base.invoke(messages)
            else:
                response: AIMessage = self._llm_with_tools.invoke(messages)

            if state.loop_count >= state.max_iterations - 1:
                if response.tool_calls:
                    response.tool_calls = []

            return {"messages": [response], "loop_count": state.loop_count + 1}

        workflow = StateGraph(AgentState)
        workflow.add_node(AGENT_NODE, agent_node)
        workflow.add_node(TOOL_NODE, tool_node)

        workflow.set_entry_point(AGENT_NODE)
        workflow.add_conditional_edges(AGENT_NODE, route_after_agent)
        workflow.add_edge(TOOL_NODE, AGENT_NODE)

        compiled_graph = workflow.compile(checkpointer=self.get_checkpointer())
        logger.debug(f"LangGraph workflow compiled successfully")
        return compiled_graph

    def threat_intelligence_query(self, query: str, clear_thread: bool = True, max_iterations: int = MAX_ITERATIONS) -> str:
        logger.info(f"Threat Intelligence Query started: {query[:100]}...")
        if clear_thread:
            self.graph.checkpointer.delete_thread(self.module_name)
            logger.debug(f"Deleted previous thread state for module: {self.module_name}")

        config = RunnableConfig(configurable={"thread_id": self.module_name})

        initial_state = AgentState(messages=[HumanMessage(content=query)], loop_count=0, max_iterations=max_iterations)

        logger.info(f"Starting graph invocation...")
        final_state = self.graph.invoke(initial_state, config)
        logger.info(f"Graph invocation completed")

        result = final_state['messages'][-1].content
        logger.info(f"Query result extracted, result length: {len(result)} characters")
        return result


# Test code
if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()

    print("\n--- Using create_agent for Query ---")
    test_query = "最近5分钟192.168.1.150使用ssh访问了哪些内网主机?"
    result_simple = AgentThreatIntelligence.threat_intelligence_lookup("ip", "66.240.205.34")
    print(result_simple)
