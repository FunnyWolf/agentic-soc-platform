import json
from typing import Annotated, List, Literal, Any

import yaml
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

from Lib.baseplaybook import LanggraphPlaybook
from Lib.configs import DATA_DIR
from Lib.llmapi import load_system_prompt_template
from PLUGINS.LLM.llmapi import LLMAPI
# change this to your actual Splunk api
from PLUGINS.Mock.SIEM_Splunk import splunk_search_tool

# Define constants for graph nodes
AGENT_NODE = "AGENT"
TOOL_NODE = "TOOL_NODE"
MAX_ITERATIONS = 2


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


# LangGraph-based agent for complex, stateful queries
class GraphAgent(LanggraphPlaybook):

    def __init__(self):
        super().__init__()
        self.graph = self._build_graph()

    def splunk_schemas(self) -> dict:
        """Loads Splunk data models from the YAML config file."""
        with open(self._get_file_path("splunk_datamodels.yml"), 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _build_graph(self) -> CompiledStateGraph:
        """Constructs the LangGraph agent graph."""
        tools = [splunk_search_tool]
        tool_node = ToolNode(tools)

        def route_after_agent(state: AgentState) -> Literal["TOOL_NODE", "__end__"]:
            last_message = state.messages[-1]
            if state.loop_count >= MAX_ITERATIONS:
                self.logger.debug(f"Max iterations ({MAX_ITERATIONS}) reached, ending agent.")
                return END
            if last_message.tool_calls:
                return TOOL_NODE
            return END

        def agent_node(state: AgentState):
            self.logger.debug(f"Agent Node Invoked (Loop: {state.loop_count})")

            schema_json = json.dumps(self.splunk_schemas(), indent=2)

            system_prompt_template = self.load_system_prompt_template(f"system_prompt")
            system_message = system_prompt_template.format(splunk_schema_json=schema_json)

            messages = [system_message, *state.messages]

            if state.loop_count >= MAX_ITERATIONS - 1:
                self.logger.warning("Approaching max iterations, forcing agent to provide final answer.")

                stop_instruction = (
                    "\n\n[SYSTEM NOTICE]: You have reached the search limit. "
                    "Do not call any more tools. Please provide your final conclusion "
                    "based ONLY on the information gathered above."
                )
                messages.append(HumanMessage(content=stop_instruction))

                llm_api = LLMAPI()
                base_llm = llm_api.get_model(tag=["fast"])
                response: AIMessage = base_llm.invoke(messages)
            else:
                llm_api = LLMAPI()
                llm = llm_api.get_model(tag=["fast", "function_calling"])
                llm_with_tools = llm.bind_tools(tools)
                response: AIMessage = llm_with_tools.invoke(messages)

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

        return workflow.compile(checkpointer=self.get_checkpointer())

    def siem_query(self, query: str) -> str:
        """Executes a query against the graph."""
        self.graph.checkpointer.delete_thread(self.module_name)
        config = RunnableConfig(configurable={"thread_id": self.module_name})

        initial_state = AgentState(messages=[HumanMessage(content=query)], loop_count=0)

        final_state = self.graph.invoke(initial_state, config)

        return final_state['messages'][-1].content


# Alternative, simpler agent implementation using create_agent
def create_siem_agent(
        query: Annotated[str, "A natural language query for SIEM."]
) -> Annotated[str, "A summary of the findings from the SIEM search."]:
    """
a simpler, stateless agent created using the create_agent factory function from langchain.agents.
    """
    # Load schemas and prompt template
    schema_path = os.path.join(DATA_DIR, "Agent_SIEM", "splunk_datamodels.yml")
    with open(schema_path, 'r', encoding='utf-8') as f:
        splunk_schemas = yaml.safe_load(f)
    schema_json = json.dumps(splunk_schemas, indent=2)

    prompt_path = os.path.join(DATA_DIR, "Agent_SIEM", "system_prompt.md")
    system_prompt_template = load_system_prompt_template(prompt_path)

    llm_api = LLMAPI()
    llm = llm_api.get_model(tag=["fast", "function_calling"])

    tools = [splunk_search_tool]

    agent = create_agent(llm, tools, system_prompt=system_prompt_template.format(splunk_schema_json=schema_json))

    response = agent.invoke({"messages": [HumanMessage(content=query)]})

    return response['messages'][-1].content


# Test code
if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    # Agent_SIEM = SIEMAgent()
    #
    # # Example query that requires the agent to formulate an SPL query
    # test_query = "Have there been any suspicious logins for the user 'admin' on Windows machines?"
    #
    # print(f"--- Using GraphAgent for Query: '{test_query}' ---")
    # result = Agent_SIEM.search(test_query)
    # print("\n--- Final Answer ---")
    # print(result)
    #
    # print("\n" + "=" * 50 + "\n")
    #
    # # A more complex query
    # test_query_2 = "check for connections from the victim host 10.67.3.130 to any known malicious IPs, like 45.33.22.11"
    # print(f"--- Using GraphAgent for Query: '{test_query_2}' ---")
    # result_2 = Agent_SIEM.search(test_query_2)
    # print("\n--- Final Answer ---")
    # print(result_2)

    # # You can also test the simpler agent directly
    print("\n--- Using create_agent for Query ---")
    test_query = "Have there been any suspicious logins for the user 'admin' on Windows machines?"
    result_simple = create_siem_agent(test_query)
    print(result_simple)
