import hashlib
from datetime import datetime, timezone
from typing import List, Union

from typing import Literal

ValidTimeWindows = Literal['5m','10m', '30m', '1h', '2h', '4h', '8h', '12h', '24h', '7d', '30d']


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
