import datetime
import json
from typing import Dict, Any, Optional, List

import redis

from Lib.configs import REDIS_CONSUMER_GROUP, REDIS_CONSUMER_NAME
from Lib.log import logger
from PLUGINS.Redis.redis_client import RedisClient


class RedisStreamAPI:
    """
    Redis Stream API封装类，提供消息发送和读取功能
    """

    def __init__(self):
        """初始化RedisStreamAPI类"""
        self.redis_client = RedisClient.get_stream_connection()

    def send_message(self, stream_key: str, message: Dict[str, Any]) -> Optional[str]:
        """
        发送消息到指定stream
        
        Args:
            stream_key (str): Redis stream的key名称
            message (Dict[str, Any]): 要发送的消息内容
        
        Returns:
            Optional[str]: 发送成功返回消息ID，失败返回None
        """
        try:
            data = json.dumps(message, ensure_ascii=False)
            # 发送消息到stream
            message_id = self.redis_client.xadd(
                stream_key,
                {"data": data}
            )
            return message_id

        except Exception as e:
            logger.exception(e)
            return None

    def read_message(self, stream_key: str, consumer_group: str = None,
                     consumer_name: str = None, timeout: int = 0, noack: bool = False) -> Optional[Dict[str, Any]]:
        """
        从指定stream读取一条消息
        
        Args:
            noack:
            stream_key (str): Redis stream的key名称
            consumer_group (str): 消费者组名称，如果为None则使用默认配置
            consumer_name (str): 消费者名称，如果为None则使用默认配置
            timeout (int): 读取超时时间（毫秒），默认5000毫秒
        
        Returns:
            Optional[Dict[str, Any]]: 读取到的消息，如果没有消息或出错则返回None
        """
        try:
            if consumer_group is None:
                consumer_group = REDIS_CONSUMER_GROUP
            if consumer_name is None:
                consumer_name = REDIS_CONSUMER_NAME

            # 确保消费者组存在
            flag = self._ensure_consumer_group(stream_key, consumer_group)
            if not flag:
                logger.error(f"无法确保消费者组 {consumer_group} 存在。")
                return None
            # 从消费者组读取消息
            messages = self.redis_client.xreadgroup(
                consumer_group,
                consumer_name,
                {stream_key: '>'},  # '>' 表示只读取新消息
                count=1,
                block=timeout,
                noack=noack,
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

            # 确认消息
            flag = self.redis_client.xack(stream_key, consumer_group, message_id)

            logger.info(f"{consumer_group} : {consumer_name} : {message_id}")
            return data
        except Exception as e:
            logger.exception(e)
            return None

    def read_stream_from_start(self, stream_key, start_id='0-0'):
        """
        从指定 Stream 的开头重复读取消息。
        :param topic: Stream 的名称。
        :param count: 要读取的消息数量。
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
            consumer_group (str): 消费者组名称，如果为None则使用默认配置
        
        Returns:
            bool: 确认成功返回True，失败返回False
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
            consumer_group (str): 消费者组名称，如果为None则使用默认配置
            consumer_name (str): 消费者名称，如果为None则使用默认配置
        
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

    def _ensure_consumer_group(self, stream_key: str, consumer_group: str):
        """
        确保消费者组存在，如果不存在则创建
        
        Args:
            stream_key (str): Redis stream的key名称
            consumer_group (str): 消费者组名称
        """
        try:
            # 检查消费者组是否存在
            groups = self.redis_client.xinfo_groups(stream_key)
            group_names = [group['name'] for group in groups]

            if consumer_group not in group_names:
                # 创建消费者组
                self.redis_client.xgroup_create(stream_key, consumer_group, '$', mkstream=True)
            return True
        except redis.ResponseError as e:
            # 如果流不存在，xinfo_groups会报错。捕获此错误并创建流和组。
            if "no such key" in str(e).lower():
                try:
                    self.redis_client.xgroup_create(stream_key, consumer_group, '$', mkstream=True)
                    return True
                except Exception as create_e:
                    if "BUSYGROUP Consumer Group name already exists" in str(e):
                        return True
                    else:
                        logger.exception(f"创建流 {stream_key} 和组 {consumer_group} 失败: {create_e}")
                        return False
            elif "BUSYGROUP" in str(e):
                # 消费者组已存在，这是正常情况
                return True
            else:
                logger.exception(f"检查或创建消费者组时发生未知Redis响应错误: {e}")
                return False
        except Exception as e:
            logger.exception(e)
            return False

    def get_stream_info(self, stream_key: str) -> Optional[Dict[str, Any]]:
        """
        获取stream信息
        
        Args:
            stream_key (str): Redis stream的key名称
        
        Returns:
            Optional[Dict[str, Any]]: stream信息，失败返回None
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
            bool: 删除成功返回True，失败返回False
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

    def clean_redis_stream(self, max_age_days=30):
        """
        清理Redis Stream中超过指定天数的键值对。
        """
        # 计算最老允许的时间戳，单位为毫秒
        # Unix时间戳（秒）* 1000
        logger.info(f"Clean Redis Stream older than {max_age_days} days.")
        cutoff_timestamp_ms = int((datetime.datetime.now() - datetime.timedelta(days=max_age_days)).timestamp() * 1000)

        try:
            for key in self.redis_client.scan_iter(match='*'):
                # 检查键的类型是否为 stream
                if self.redis_client.type(key) == 'stream':
                    # 使用 XTRIM 命令删除早于给定ID的条目
                    # ID的格式是 `unix_time_ms-sequence_number`
                    # 我们可以使用 `unix_time_ms-0` 作为删除的上限ID
                    trim_id = f'{cutoff_timestamp_ms}-0'

                    # `XTRIM` 带有 `MINID` 选项，用于删除ID小于指定ID的所有条目
                    trimmed_count = self.redis_client.xtrim(key, minid=trim_id)
                    logger.info(f"Delete {trimmed_count} items from '{key}'")
        except Exception as e:
            logger.exception(e)
        finally:
            logger.info("clean task finished.")
