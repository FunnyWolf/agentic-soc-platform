from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph

from Lib.baseplaybook import LanggraphPlaybook
from Lib.llmapi import BaseAgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Alert
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus, PlaybookModel
from PLUGINS.SIRP.sirpcoremodel import AlertModel


class AgentState(BaseAgentState):
    suggestion: str = None


class Playbook(LanggraphPlaybook):
    NAME = "Alert Analysis Agent"  # PlaybookLoader name
    DESC = "Alert Analysis Agent"

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        def preprocess_node(state: AgentState):
            """Preprocess data"""
            alert = Alert.get(self.param_source_row_id)
            return {"alert": alert}

        # Define node
        def analyze_node(state: AgentState):
            """AI analyzes alert data"""
            alert: AlertModel = state.alert
            # Load system prompt
            system_prompt_template = self.load_system_prompt_template("L3_SOC_Analyst")

            system_message = system_prompt_template.format()

            # Construct few-shot examples
            few_shot_examples = [
            ]

            # Run
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag="fast")

            # Construct message list
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=alert.model_dump_json())
            ]
            response = llm.invoke(messages)
            # response = LLMAPI.extract_think(response)  # Temporary solution for langchain chatollama bug
            return {"suggestion": response.content}

        def output_node(state: AgentState):
            """Process analysis results"""
            suggestion = state.suggestion
            model = AlertModel(row_id=self.param_source_row_id, summary_ai=suggestion)
            Alert.update(model)

            self.send_notice("Alert_Suggestion_Gen_By_LLM output_node Finish", f"row_id:{self.param_source_row_id}")
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
        model = AlertModel()
        self.agent_state = AgentState(messages=[], alert=model, suggestion="")
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
    model = PlaybookModel(source_row_id='89f83414-a0fc-43bf-a15d-afab4309153a')
    module = Playbook()
    module._playbook_model = model

    module.run()
