import redis

from Lib.log import logger
from PLUGINS.Redis.CONFIG import REDIS_URL, REDIS_MAX_CONNECTIONS


class RedisClient(object):
    # 类变量，用于存储全局唯一的连接池
    _stream_pool = None

    @classmethod
    def get_stream_connection(cls):
        """获取单例连接池中的连接"""
        if cls._stream_pool is None:
            logger.info("Initializing Global Redis Stream Connection Pool...")
            cls._stream_pool = redis.ConnectionPool.from_url(
                f"{REDIS_URL}0",
                decode_responses=True,
                max_connections=REDIS_MAX_CONNECTIONS,  # 限制最大连接数
                health_check_interval=30  # 每30秒自动检测连接状态
            )

        # 使用同一个池创建 client 实例
        redis_client = redis.Redis(connection_pool=cls._stream_pool)
        return redis_client
