import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, List

import redis

from Lib.configs import REDIS_CONSUMER_GROUP, REDIS_CONSUMER_NAME
from Lib.log import logger
from PLUGINS.Redis.CONFIG import REDIS_STREAM_MAX_LENGTH
from PLUGINS.Redis.redis_client import RedisClient


class RedisStreamAPI(object):
    """
    Redis Stream API封装类,提供消息发送和读取功能
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        """实现单例模式"""
        if not cls._instance:
            cls._instance = super(RedisStreamAPI, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """初始化RedisStreamAPI类"""
        if self._initialized:
            return

        self.redis_client = RedisClient.get_stream_connection()

        self._checked_groups = set()
        self._initialized = True
        logger.info("RedisStreamAPI init finished.")

    def send_message(self, stream_name: str, message: Dict[str, Any], maxlen: int = REDIS_STREAM_MAX_LENGTH) -> Optional[str]:
        """
        发送消息到指定stream
        
        Args:
            stream_name (str): Redis stream的key名称
            message (Dict[str, Any]): 要发送的消息内容
            maxlen (int): stream最大长度,超过则删除最旧的消息,默认10000
        Returns:
            Optional[str]: 发送成功返回消息ID,失败返回None
        """
        try:
            data = json.dumps(message, ensure_ascii=False)
            # 发送消息到stream
            message_id = self.redis_client.xadd(
                stream_name,
                {"data": data},
                maxlen=maxlen,
                approximate=True
            )
            return message_id

        except Exception as e:
            logger.exception(e)
            return None

    def read_stream_message(self, stream_name: str, consumer_group: str = None,
                            consumer_name: str = None, timeout: int = 5000) -> dict:
        """
        从指定stream读取一条消息

        Args:
            stream_name (str): Redis stream的key名称
            consumer_group (str): 消费者组名称,如果为None则使用默认配置
            consumer_name (str): 消费者名称,如果为None则使用默认配置
            timeout (int): 阻塞等待时间,单位毫秒,默认5000ms
        """
        if consumer_group is None:
            consumer_group = REDIS_CONSUMER_GROUP
        if consumer_name is None:
            consumer_name = REDIS_CONSUMER_NAME

        # 确保消费者组存在（只在第一次调用时执行）
        if stream_name not in self._checked_groups:
            if self._ensure_consumer_group(stream_name, consumer_group):
                self._checked_groups.add(stream_name)

        while True:
            try:
                messages = self.redis_client.xreadgroup(
                    consumer_group,
                    consumer_name,
                    {stream_name: '>'},
                    count=1,
                    block=timeout,
                    noack=True,
                )

                if not messages or not messages[0][1]:
                    continue

                _, stream_messages = messages[0]
                message_id, fields = stream_messages[0]
                data: dict = json.loads(fields["data"])

                logger.info(f"Received: {stream_name} -> {message_id}")
                return data

            except Exception as e:
                logger.error(f"Error reading from stream {stream_name}: {e}")
                time.sleep(1)  # 发生异常(如网络闪断)时稍作停顿，防止死循环刷屏

    def read_stream_head(self, stream_name: str, n: int, timeout: Optional[float] = None) -> List[dict]:
        """
        读取指定 stream 的前 n 条消息（非阻塞）.
        :param stream_name: Stream 的名称.
        :param n: 要读取的消息数量.
        :param timeout: 超时时间（秒），None 表示不限制.
        """

        def _fetch():
            messages = self.redis_client.xrange(stream_name, min='-', max='+', count=n)
            return [json.loads(fields["data"]) for _, fields in messages]

        if timeout is None:
            return _fetch()
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(_fetch).result(timeout=timeout)

    def read_stream_message_by_id(self, stream_name: str, message_id: str, timeout: Optional[float] = None) -> dict:
        """
        读取指定 ID 的消息（精确匹配，非阻塞）.
        :param stream_name: Stream 的名称.
        :param message_id: 要读取的消息 ID.
        :param timeout: 超时时间（秒），None 表示不限制.
        """

        def _fetch():
            messages = self.redis_client.xrange(stream_name, min=message_id, max=message_id, count=1)
            if not messages:
                return {}
            _, fields = messages[0]
            result: dict = json.loads(fields["data"])
            return result

        if timeout is None:
            return _fetch()
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(_fetch).result(timeout=timeout)

    def acknowledge_message(self, stream_name: str, message_id: str,
                            consumer_group: str = None) -> bool:
        """
        确认消息已被处理
        
        Args:
            stream_name (str): Redis stream的key名称
            message_id (str): 消息ID
            consumer_group (str): 消费者组名称,如果为None则使用默认配置
        
        Returns:
            bool: 确认成功返回True,失败返回False
        """
        try:
            if consumer_group is None:
                consumer_group = REDIS_CONSUMER_GROUP

            # 确认消息
            result = self.redis_client.xack(stream_name, consumer_group, message_id)

            if result:
                return True
            else:
                return False

        except Exception as e:
            logger.exception(e)
            return False

    def get_pending_messages(self, stream_name: str, consumer_group: str = None,
                             consumer_name: str = None) -> List[Dict[str, Any]]:
        """
        获取待处理的消息
        
        Args:
            stream_name (str): Redis stream的key名称
            consumer_group (str): 消费者组名称,如果为None则使用默认配置
            consumer_name (str): 消费者名称,如果为None则使用默认配置
        
        Returns:
            List[Dict[str, Any]]: 待处理的消息列表
        """
        try:
            if consumer_group is None:
                consumer_group = REDIS_CONSUMER_GROUP
            if consumer_name is None:
                consumer_name = REDIS_CONSUMER_NAME

            # 获取待处理消息
            pending_messages = self.redis_client.xpending(
                stream_name, consumer_group, '-', '+', 100, consumer_name
            )

            messages = []
            for message_id, consumer, idle_time, delivery_count in pending_messages:
                messages.append({
                    'message_id': message_id,
                    'consumer': consumer,
                    'idle_time': idle_time,
                    'delivery_count': delivery_count
                })
            return messages

        except Exception as e:
            logger.exception(e)
            return []

    def _ensure_consumer_group(self, stream_name: str, consumer_group: str) -> bool:
        """
        静默确保消费者组存在
        """
        try:
            # 直接创建，利用 mkstream=True。如果流不存在会自动创建流，如果组已存在会报错
            self.redis_client.xgroup_create(stream_name, consumer_group, id='$', mkstream=True)
            return True
        except redis.ResponseError as e:
            # 如果报错信息包含 BUSYGROUP，说明组已经存在，属于正常情况
            if "BUSYGROUP" in str(e):
                return True
            # logger.error(f"创建消费者组失败: {e}")
            return False

    def get_stream_info(self, stream_name: str) -> Optional[Dict[str, Any]]:
        """
        获取stream信息
        
        Args:
            stream_name (str): Redis stream的key名称
        
        Returns:
            Optional[Dict[str, Any]]: stream信息,失败返回None
        """
        try:
            info = self.redis_client.xinfo_stream(stream_name)
            return info
        except Exception as e:
            logger.exception(e)
            return None

    def delete_stream(self, stream_name: str) -> bool:
        """
        删除stream
        
        Args:
            stream_name (str): Redis stream的key名称
        
        Returns:
            bool: 删除成功返回True,失败返回False
        """
        try:
            result = self.redis_client.delete(stream_name)
            if result:
                return True
            else:
                return False
        except Exception as e:
            logger.exception(e)
            return False

    def close(self):
        """关闭Redis连接"""
        try:
            self.redis_client.close()
        except Exception as e:
            logger.exception(e)
