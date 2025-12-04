import redis

from PLUGINS.Redis.CONFIG import REDIS_URL
from Lib.log import logger


class RedisClient(object):

    def __init__(self):
        pass

    @staticmethod
    def get_stream_connection():
        """用于订阅类操作,无需使用连接池"""
        redis_client = redis.Redis.from_url(f"{REDIS_URL}0", decode_responses=True)
        # 测试连接
        try:
            redis_client.ping()
            return redis_client
        except redis.ConnectionError as e:
            logger.exception(e)
            raise
