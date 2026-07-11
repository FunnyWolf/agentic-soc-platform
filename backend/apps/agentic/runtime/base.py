import hashlib
from datetime import datetime, timezone
from pathlib import Path

from dateutil import parser
from django.conf import settings
from django.utils import timezone as django_timezone

from apps.settings.runtime_config import get_prompt_language


class BasePlaybook:
    NAME = ""
    DESC = ""
    TAGS = []
    PROMPT_SLUG = ""
    SCRIPT_PATH = None

    def __init__(self, *, playbook_run=None):
        self.playbook_run = playbook_run
        self.case = playbook_run.case if playbook_run else None
        self.user_input = playbook_run.user_input if playbook_run else ""

    def run(self):
        raise NotImplementedError

    @classmethod
    def prompt_slug(cls):
        if cls.PROMPT_SLUG:
            return cls.PROMPT_SLUG
        if cls.SCRIPT_PATH:
            return Path(cls.SCRIPT_PATH).stem
        raise ValueError(f"{cls.__name__} must set PROMPT_SLUG or be loaded from a script file.")

    @classmethod
    def prompt_path(cls, prompt_name, language=None):
        filename = f"{prompt_name}_{language or get_prompt_language()}.md"
        return Path(settings.CUSTOM_DIR) / "data" / "playbooks" / cls.prompt_slug() / filename

    def read_prompt(self, prompt_name, language=None):
        path = self.prompt_path(prompt_name, language=language)
        if not path.exists():
            raise FileNotFoundError(f"Custom playbook prompt not found: {path}")
        return path.read_text(encoding="utf-8")


class BaseModule:
    NAME = ""
    DESC = ""
    STREAM_NAME = ""
    THREAD_NUM = 1

    def run(self, message):
        raise NotImplementedError


def parse_event_time(value, default=None):
    if not value:
        return default or django_timezone.now(), {}
    try:
        parsed = parser.parse(str(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=django_timezone.get_current_timezone())
        return parsed, {}
    except Exception as exc:
        return default or django_timezone.now(), {
            "time_parse_error": {
                "value": value,
                "error": f"{type(exc).__name__}: {exc}",
            }
        }


def _time_bucket(dt, window):
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if window.endswith("m"):
        minutes = int(window[:-1])
        bucket_minute = (dt.minute // minutes) * minutes
        return dt.replace(minute=bucket_minute, second=0, microsecond=0).strftime("%Y%m%d%H%M")
    if window.endswith("h"):
        hours = int(window[:-1])
        if hours >= 24:
            return dt.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y%m%d")
        bucket_hour = (dt.hour // hours) * hours
        return dt.replace(hour=bucket_hour, minute=0, second=0, microsecond=0).strftime("%Y%m%d%H%M")
    if window.endswith("d"):
        return dt.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y%m%d")
    return dt.strftime("%Y%m%d%H%M")


def generate_correlation_uid(rule_id, time_window="24h", timestamp=None, keys=None):
    key_parts = [str(rule_id), _time_bucket(timestamp or datetime.now(timezone.utc), time_window)]
    for key in sorted(str(item) for item in (keys or []) if item):
        key_parts.append(key)
    raw_key = "|".join(key_parts)
    return f"corr-{hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:16]}"
