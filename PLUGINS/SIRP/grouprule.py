import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Union


class CorrelationConfig:

    def __init__(self,
                 rule_id: str,
                 time_window: str = "24h",
                 keys: List[str] = None):
        self.rule_id = rule_id
        self.time_window = time_window
        self.keys = keys or []

        valid_windows = ['10m', '30m', '1h', '2h', '4h', '8h', '12h', '24h', '7d', '30d']
        if time_window not in valid_windows:
            raise ValueError(f"无效的时间窗口: {time_window}. 有效选项: {valid_windows}")


class GroupRule:

    def __init__(self, config: CorrelationConfig):
        self.config = config

    @staticmethod
    def _get_time_bucket(dt: datetime, window: str) -> str:
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

    @staticmethod
    def _parse_timestamp(timestamp: Optional[Union[int, float, str, datetime]]) -> datetime:
        if timestamp is None:
            return datetime.now(timezone.utc)
        elif isinstance(timestamp, datetime):
            return timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
        elif isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                return datetime.now(timezone.utc)
        else:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    def generate_correlation_uid(self,
                                 keys: List[str] = None,
                                 timestamp: Optional[Union[int, float, str, datetime]] = None) -> str:
        processing_dt = self._parse_timestamp(timestamp)
        time_bucket = self._get_time_bucket(processing_dt, self.config.time_window)

        key_parts = [self.config.rule_id, time_bucket]

        final_keys = keys or self.config.keys
        for key in sorted(final_keys):
            if key:
                key_parts.append(str(key))

        raw_key = "|".join(key_parts)
        short_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:16]

        return f"corr-{short_hash}"
