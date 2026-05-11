from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph

from Lib.baseapi import BaseAPI
from Lib.llmapi import BaseAgentState
from Lib.log import logger
from PLUGINS.SIRP.sirpapi import Playbook, Notice
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus, PlaybookModel


class BasePlaybook(BaseAPI):
    RUN_AS_JOB = True  # 是否作为后台任务运行
    NAME = None

    def __init__(self):
        super().__init__()
        self.logger = logger
        # noinspection PyTypeChecker
        self._playbook_model: PlaybookModel = None

    @property
    def param_source_row_id(self):
        return self._playbook_model.source_row_id

    @property
    def param_user_input(self):
        return self._playbook_model.user_input

    def update_playbook_status(self, job_status: PlaybookJobStatus, remark: str):
        model_tmp = PlaybookModel()
        model_tmp.row_id = self._playbook_model.row_id
        model_tmp.job_status = job_status
        model_tmp.remark = remark
        row_id = Playbook.update(model_tmp)
        return row_id

    def send_notice(self, title: str, body: str) -> bool:
        result = Notice.send(self._playbook_model.user, title, body)
        return result

    def execute(self):
        try:
            self.run()
        except Exception as e:
            self.logger.exception(e)
            self.update_playbook_status(PlaybookJobStatus.FAILED, str(e))


class LanggraphPlaybook(BasePlaybook):
    def __init__(self):
        super().__init__()
        self.graph: CompiledStateGraph = None
        self.agent_state = None

    @staticmethod
    def get_checkpointer():
        checkpointer = MemorySaver()
        return checkpointer

    # langgraph interface
    def run_graph(self):
        self.graph.checkpointer.delete_thread(self.module_name)
        config = RunnableConfig()
        config["configurable"] = {"thread_id": self.module_name}
        if self.agent_state is None:
            self.agent_state = BaseAgentState()
        for event in self.graph.stream(self.agent_state, config, stream_mode="values"):
            self.logger.debug(event)

    def run(self):
        self.run_graph()
        return self.agent_state
