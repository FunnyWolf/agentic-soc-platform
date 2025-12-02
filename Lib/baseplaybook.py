from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph

from Lib.baseapi import BaseAPI
from Lib.llmapi import AgentState
from Lib.log import logger


class BasePlaybook(BaseAPI):
    RUN_AS_JOB = True  # 是否作为后台任务运行
    TYPE = None
    NAME = None

    def __init__(self):
        super().__init__()
        self._params = {}
        self.logger = logger

    def param(self, key, default=None):
        return self._params.get(key, default)


class LanggraphPlaybook(BasePlaybook):
    def __init__(self):
        super().__init__()
        self.graph: CompiledStateGraph = None
        self.agent_state = None

    @staticmethod
    def get_checkpointer():
        checkpointer = MemorySaver()
        return checkpointer

    def run_graph(self):
        self.graph.checkpointer.delete_thread(self.module_name)
        config = RunnableConfig()
        config["configurable"] = {"thread_id": self.module_name}
        if self.agent_state is None:
            self.agent_state = AgentState()
        for event in self.graph.stream(self.agent_state, config, stream_mode="values"):
            self.logger.debug(event)

    def run(self):
        self.run_graph()
        return self.agent_state
