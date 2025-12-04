# Redis Stack Config
# You can change the Redis URL according to your environment
# Login in Redis Insight by http://192.168.241.128:8001 and default/redis-stack-password-for-agentic-soc-platform
# 根据你的环境修改Redis的连接地址
# 你通过 http://192.168.241.128:8001 和 default/redis-stack-password-for-agentic-soc-platform 登录 Redis Insight
REDIS_URL = "redis://:redis-stack-password-for-agentic-soc-platform@192.168.241.128:6379/"
REDIS_STREAM_STORE_DAYS = 7  # 消息在Redis Stream中保存的天数
