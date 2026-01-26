import json

from langchain_core.messages import (
    BaseMessage,
    SystemMessage,
    HumanMessage,
    AIMessage,
    ToolMessage
)
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel

from Lib.baseapi import BaseAPI
from Lib.llmapi import AgentState
from Lib.log import logger
from PLUGINS.SIRP.sirpapi import Message
from PLUGINS.SIRP.sirpapi import Playbook, Notice
from PLUGINS.SIRP.sirpmodel import PlaybookModel, PlaybookJobStatus, MessageModel, MessageType


class BasePlaybook(BaseAPI):
    RUN_AS_JOB = True  # 是否作为后台任务运行
    TYPE = None
    NAME = None

    def __init__(self):
        super().__init__()
        self.logger = logger
        # noinspection PyTypeChecker
        self._playbook_model: PlaybookModel = None

    @property
    def param_source_rowid(self):
        return self._playbook_model.source_rowid

    @property
    def param_source_worksheet(self):
        return self._playbook_model.source_worksheet

    @property
    def param_user_input(self):
        return self._playbook_model.user_input

    def update_playbook_status(self, job_status: PlaybookJobStatus, remark: str):
        model_tmp = PlaybookModel()
        model_tmp.rowid = self._playbook_model.rowid
        model_tmp.job_status = job_status
        model_tmp.remark = remark
        rowid = Playbook.update(model_tmp)
        return rowid

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

    def add_message_to_playbook(self, message: BaseMessage | BaseModel, node=None):

        message_model = MessageModel()
        message_model.playbook = [self._playbook_model.rowid]
        message_model.node = node

        # handle content
        if isinstance(message, BaseMessage):
            message_model.content = message.content

        if isinstance(message, SystemMessage):
            message_model.type = MessageType.SYSTEM
        elif isinstance(message, HumanMessage):
            message_model.type = MessageType.HUMAN
        elif isinstance(message, AIMessage):
            if hasattr(message, 'tool_calls') and message.tool_calls:
                message_model.type = MessageType.AI
                message_model.data = json.dumps(message.tool_calls)
            else:
                message_model.type = MessageType.AI
        elif isinstance(message, ToolMessage):
            try:
                json_data = {"name": message.name, "tool_call_id": message.tool_call_id, "result": json.loads(message.content)}
            except json.decoder.JSONDecodeError:
                json_data = {"name": message.name, "tool_call_id": message.tool_call_id, "result": message.content}
            message_model.type = MessageType.TOOL
            message_model.data = json.dumps(json_data)
        elif isinstance(message, BaseModel):
            message_model.type = MessageType.AI
            message_model.data = message.model_dump_json(exclude_none=True, exclude_defaults=True, exclude_unset=True)
        else:
            logger.warning(f"Unknown message type: {message.type}.")

        row_id = Message.create(message_model)
        return row_id

    # langgraph interface
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
