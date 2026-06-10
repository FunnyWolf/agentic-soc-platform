import hashlib
from datetime import datetime, timezone
from typing import Literal, List, Union

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph

from Lib.baseapi import BaseAPI, BaseAgentState
from Lib.configs import REDIS_CONSUMER_GROUP
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI

ValidTimeWindows = Literal['5m', '10m', '30m', '1h', '2h', '4h', '8h', '12h', '24h', '7d', '30d']


class Correlation(object):

    @classmethod
    def _get_time_bucket(cls, dt: datetime, window: str) -> str:
        if window.endswith('m'):
            minutes = int(window[:-1])
            bucket_minute = (dt.minute // minutes) * minutes
            return dt.replace(minute=bucket_minute, second=0, microsecond=0).strftime('%Y%m%d%H%M')
        elif window.endswith('h'):
            hours = int(window[:-1])
            if hours >= 24:
                return dt.replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y%m%d')
            bucket_hour = (dt.hour // hours) * hours
            return dt.replace(hour=bucket_hour, minute=0, second=0, microsecond=0).strftime('%Y%m%d%H%M')
        elif window.endswith('d'):
            return dt.replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y%m%d')
        return dt.strftime('%Y%m%d%H%M')

    @classmethod
    def generate_correlation_uid(cls,
                                 rule_id: str,
                                 time_window: ValidTimeWindows = "24h",
                                 timestamp: datetime = None,
                                 keys: List[Union[str, None]] = None) -> str:
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        keys = keys or []
        time_bucket = cls._get_time_bucket(timestamp, time_window)

        key_parts = [rule_id, time_bucket]

        for key in sorted(keys):
            if key:
                key_parts.append(str(key))

        raw_key = "|".join(key_parts)
        short_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:16]

        return f"corr-{short_hash}"


class BaseModule(BaseAPI):
    THREAD_NUM = 1

    def __init__(self):
        super().__init__()
        self._thread_name = None
        self.agent_state = None
        self.debug_message_id = None  # 设置为非None以启用Debug模式

    def read_stream_head_ids(self, n):  # 调试时使用，读取最近的n条消息
        redis_stream_api = RedisStreamAPI()
        messages = redis_stream_api.read_stream_head_ids(self.module_name, n=n)
        return messages

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
