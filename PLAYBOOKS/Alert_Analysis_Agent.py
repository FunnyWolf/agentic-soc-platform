import json
from typing import Any, Annotated, List

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel

from Lib.baseplaybook import LanggraphPlaybook
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Alert
from PLUGINS.SIRP.sirpmodel import PlaybookJobStatus, AlertModel


class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages]

    alert: AlertModel
    suggestion: str


class Playbook(LanggraphPlaybook):
    TYPE = "ALERT"  # Classification tag
    NAME = "Alert Analysis Agent"  # PlaybookLoader name

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        def preprocess_node(state: AgentState):
            """Preprocess data"""
            alert = Alert.get(self.param_source_rowid)
            return {"alert": alert}

        # Define node
        def analyze_node(state: AgentState):
            """AI analyzes alert data"""

            # Load system prompt
            system_prompt_template = self.load_system_prompt_template("L3_SOC_Analyst")

            system_message = system_prompt_template.format()

            # Construct few-shot examples
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

            # Run
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag="fast")

            # Construct message list
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=json.dumps(state.alert))
            ]
            response = llm.invoke(messages)
            response = LLMAPI.extract_think(response)  # Temporary solution for langchain chatollama bug
            state.suggestion = response.content
            return state

        def output_node(state: AgentState):
            """Process analysis results"""
            suggestion = state.suggestion
            fields = [
                {"id": "suggestion_ai", "value": suggestion},
            ]
            Alert.update(self.param_source_rowid, fields)

            self.send_notice("Alert_Suggestion_Gen_By_LLM output_node Finish", f"rowid:{self.param_source_rowid}")
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, "Get suggestion by ai agent completed.")

            self.agent_state = state
            return state

        # Compile graph
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
    params_debug = {'source_rowid': '13782e0a-2423-4fc3-9b16-7f2eb15ae83f', 'source_worksheet': 'alert'}
    module = Playbook()
    # module._params = params_debug
    module.run()
