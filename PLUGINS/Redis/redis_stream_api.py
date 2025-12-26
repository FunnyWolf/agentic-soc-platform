import json
import time
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

    def send_message(self, stream_key: str, message: Dict[str, Any], maxlen: int = REDIS_STREAM_MAX_LENGTH) -> Optional[str]:
        """
        发送消息到指定stream
        
        Args:
            stream_key (str): Redis stream的key名称
            message (Dict[str, Any]): 要发送的消息内容
            maxlen (int): stream最大长度,超过则删除最旧的消息,默认10000
        Returns:
            Optional[str]: 发送成功返回消息ID,失败返回None
        """
        try:
            data = json.dumps(message, ensure_ascii=False)
            # 发送消息到stream
            message_id = self.redis_client.xadd(
                stream_key,
                {"data": data},
                maxlen=maxlen,
                approximate=True
            )
            return message_id

        except Exception as e:
            logger.exception(e)
            return None

    def read_message(self, stream_key: str, consumer_group: str = None,
                     consumer_name: str = None, timeout: int = 5000) -> Optional[Dict[str, Any]]:
        """
        从指定stream读取一条消息

        Args:
            stream_key (str): Redis stream的key名称
            consumer_group (str): 消费者组名称,如果为None则使用默认配置
            consumer_name (str): 消费者名称,如果为None则使用默认配置
            timeout (int): 阻塞等待时间,单位毫秒,默认5000ms
        """
        if consumer_group is None:
            consumer_group = REDIS_CONSUMER_GROUP
        if consumer_name is None:
            consumer_name = REDIS_CONSUMER_NAME

        # 确保消费者组存在（只在第一次调用时执行）
        if stream_key not in self._checked_groups:
            if self._ensure_consumer_group(stream_key, consumer_group):
                self._checked_groups.add(stream_key)

        while True:
            try:
                messages = self.redis_client.xreadgroup(
                    consumer_group,
                    consumer_name,
                    {stream_key: '>'},
                    count=1,
                    block=timeout,
                    noack=True,
                )

                if not messages or not messages[0][1]:
                    continue

                _, stream_messages = messages[0]
                message_id, fields = stream_messages[0]
                data = json.loads(fields["data"])

                logger.info(f"Received: {stream_key} -> {message_id}")
                return data

            except Exception as e:
                logger.error(f"Error reading from stream {stream_key}: {e}")
                time.sleep(1)  # 发生异常(如网络闪断)时稍作停顿，防止死循环刷屏

    def read_stream_from_start(self, stream_key, start_id='0-0'):
        """
        从指定 Stream 的开头重复读取消息.
        :param topic: Stream 的名称.
        :param count: 要读取的消息数量.
        """

        try:
            messages = self.redis_client.xread(
                count=1,
                block=0,
                streams={stream_key: start_id}
            )

            if not messages or not messages[0][1]:
                return None

            # 解析消息
            stream_name, stream_messages = messages[0]
            if not stream_messages:
                return None

            message_id, fields = stream_messages[0]

            value = fields["data"]
            data = json.loads(value)
            return data

        except Exception as e:
            logger.exception(e)
            return None

    def acknowledge_message(self, stream_key: str, message_id: str,
                            consumer_group: str = None) -> bool:
        """
        确认消息已被处理
        
        Args:
            stream_key (str): Redis stream的key名称
            message_id (str): 消息ID
            consumer_group (str): 消费者组名称,如果为None则使用默认配置
        
        Returns:
            bool: 确认成功返回True,失败返回False
        """
        try:
            if consumer_group is None:
                consumer_group = REDIS_CONSUMER_GROUP

            # 确认消息
            result = self.redis_client.xack(stream_key, consumer_group, message_id)

            if result:
                return True
            else:
                return False

        except Exception as e:
            logger.exception(e)
            return False

    def get_pending_messages(self, stream_key: str, consumer_group: str = None,
                             consumer_name: str = None) -> List[Dict[str, Any]]:
        """
        获取待处理的消息
        
        Args:
            stream_key (str): Redis stream的key名称
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
                stream_key, consumer_group, '-', '+', 100, consumer_name
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

    def _ensure_consumer_group(self, stream_key: str, consumer_group: str) -> bool:
        """
        静默确保消费者组存在
        """
        try:
            # 直接创建，利用 mkstream=True。如果流不存在会自动创建流，如果组已存在会报错
            self.redis_client.xgroup_create(stream_key, consumer_group, id='$', mkstream=True)
            return True
        except redis.ResponseError as e:
            # 如果报错信息包含 BUSYGROUP，说明组已经存在，属于正常情况
            if "BUSYGROUP" in str(e):
                return True
            # logger.error(f"创建消费者组失败: {e}")
            return False

    def get_stream_info(self, stream_key: str) -> Optional[Dict[str, Any]]:
        """
        获取stream信息
        
        Args:
            stream_key (str): Redis stream的key名称
        
        Returns:
            Optional[Dict[str, Any]]: stream信息,失败返回None
        """
        try:
            info = self.redis_client.xinfo_stream(stream_key)
            return info
        except Exception as e:
            logger.exception(e)
            return None

    def delete_stream(self, stream_key: str) -> bool:
        """
        删除stream
        
        Args:
            stream_key (str): Redis stream的key名称
        
        Returns:
            bool: 删除成功返回True,失败返回False
        """
        try:
            result = self.redis_client.delete(stream_key)
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
