from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph

from Lib.baseapi import BaseAPI
from Lib.configs import REDIS_CONSUMER_GROUP
from Lib.llmapi import BaseAgentState
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI


class BaseModule(BaseAPI):
    THREAD_NUM = 1

    def __init__(self):
        super().__init__()
        self._thread_name = None
        self.agent_state = None
        self.debug_message_id = None  # 设置为非None以启用Debug模式

    def read_stream_message(self) -> dict:
        """读取消息"""
        redis_stream_api = RedisStreamAPI()
        if self.debug_message_id is not None:
            message = redis_stream_api.read_stream_message_by_id(self.module_name, message_id=self.debug_message_id)
        else:
            message = redis_stream_api.read_stream_message(stream_name=self.module_name, consumer_group=REDIS_CONSUMER_GROUP, consumer_name=self._thread_name)
        return message


class LanggraphModule(BaseModule):
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
            self.agent_state = BaseAgentState()
        for event in self.graph.stream(self.agent_state, config, stream_mode="values"):
            self.logger.debug(event)
        self.logger.debug(f"{self.module_name} finished processing.")

    def run(self):
        self.run_graph()
        return self.agent_state
