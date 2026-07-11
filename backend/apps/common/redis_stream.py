import json

import redis
from django.conf import settings
from django.core.cache import caches

from apps.settings.runtime_config import get_stream_maxlen

DEFAULT_STREAM_BLOCK_MS = 1000


class RedisStreamMessageDecodeError(ValueError):
    def __init__(self, *, stream, message_id, raw_data):
        super().__init__(f"invalid JSON payload for Redis stream {stream} message {message_id}")
        self.stream = stream
        self.message_id = message_id
        self.raw_data = raw_data


def _decode_stream_message(message_id, fields, *, stream=""):
    if isinstance(message_id, bytes):
        message_id = message_id.decode()
    raw_data = fields.get("data", fields.get(b"data"))
    if isinstance(raw_data, bytes):
        raw_data = raw_data.decode()
    try:
        data = json.loads(raw_data)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RedisStreamMessageDecodeError(stream=stream, message_id=message_id, raw_data=raw_data) from exc
    return {"message_id": message_id, "data": data}


class RedisStreamClient:
    def __init__(self, *, redis_client=None):
        self.redis = redis_client or self._default_client()

    def _default_client(self):
        cache = caches["default"]
        if hasattr(cache, "client"):
            return cache.client.get_client(write=True)
        return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

    def ensure_group(self, stream, group):
        try:
            self.redis.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        return True

    def send_message(self, stream, data, *, maxlen=None):
        maxlen = get_stream_maxlen() if maxlen is None else maxlen
        message_id = self.redis.xadd(
            stream,
            {"data": json.dumps(data, ensure_ascii=False)},
            maxlen=maxlen,
            approximate=True,
        )
        return message_id.decode() if isinstance(message_id, bytes) else message_id

    def read_message(self, stream, *, group, consumer, block_ms=None, count=1):
        block_ms = DEFAULT_STREAM_BLOCK_MS if block_ms is None else block_ms
        self.ensure_group(stream, group)
        messages = self.redis.xreadgroup(
            group,
            consumer,
            {stream: ">"},
            count=count,
            block=block_ms,
            noack=True,
        )
        if not messages or not messages[0][1]:
            return None

        _stream_name, stream_messages = messages[0]
        message_id, fields = stream_messages[0]
        return _decode_stream_message(message_id, fields, stream=stream)

    def read_stream_head(self, stream, count):
        messages = self.redis.xrange(stream, min="-", max="+", count=count)
        return [_decode_stream_message(message_id, fields, stream=stream) for message_id, fields in messages]

    def read_stream_recent(self, stream, count):
        messages = self.redis.xrevrange(stream, max="+", min="-", count=count)
        return [_decode_stream_message(message_id, fields, stream=stream) for message_id, fields in messages]

    def read_stream_message_by_id(self, stream, message_id):
        messages = self.redis.xrange(stream, min=message_id, max=message_id, count=1)
        if not messages:
            return {}
        found_id, fields = messages[0]
        return _decode_stream_message(found_id, fields, stream=stream)

    def stream_info(self, stream):
        return self.redis.xinfo_stream(stream)

    def stream_groups(self, stream):
        return self.redis.xinfo_groups(stream)

    def delete_stream(self, stream):
        return bool(self.redis.delete(stream))
