from pathlib import Path

import redis
from django.conf import settings

from apps.agentic.runtime.module import AGENTIC_MODULE_CONSUMER_GROUP, scan_module_definitions
from apps.agentic.services.playbooks import scan_playbook_definitions
from apps.common.redis_stream import RedisStreamClient
from integrations.siem.registry import reload_registry, scan_registry_configs

MAX_STREAM_MESSAGES = 20


def _source_for_path(path):
    custom_dir = Path(settings.CUSTOM_DIR).resolve()
    resolved_path = Path(path).resolve()
    try:
        resolved_path.relative_to(custom_dir)
    except ValueError:
        return "official"
    return "custom"


def _module_record(definition):
    return {
        "name": definition.name,
        "description": getattr(definition.module_class, "DESC", ""),
        "stream_name": definition.stream_name,
        "thread_num": definition.thread_num,
        "path": str(definition.path),
    }


def _playbook_record(definition):
    raw_tags = getattr(definition.script_class, "TAGS", []) or []
    tags = [raw_tags] if isinstance(raw_tags, str) else list(raw_tags)
    return {
        "name": definition.name,
        "description": getattr(definition.script_class, "DESC", ""),
        "tags": tags,
        "path": str(definition.path),
        "source": _source_for_path(definition.path),
    }


def _siem_record(item):
    return item


def _decode(value):
    return value.decode() if isinstance(value, bytes) else value


def _info_get(info, key, default=None):
    return info.get(key, info.get(key.encode(), default))


def _stream_group_record(group):
    return {
        "name": _decode(_info_get(group, "name", "")),
        "consumers": _info_get(group, "consumers", 0),
        "pending": _info_get(group, "pending", 0),
        "last_delivered_id": _decode(_info_get(group, "last-delivered-id", "")),
    }


def _entry_id(entry):
    if isinstance(entry, (list, tuple)) and entry:
        return _decode(entry[0])
    return ""


def _stream_health(stream_name, *, redis_client=None):
    try:
        client = redis_client or RedisStreamClient()
        info = client.stream_info(stream_name)
        groups = client.stream_groups(stream_name)
    except redis.ResponseError as exc:
        if "no such key" in str(exc).lower():
            return {
                "available": False,
                "length": 0,
                "first_id": "",
                "last_id": "",
                "groups": [],
                "warning": "Stream does not exist yet.",
            }
        raise

    return {
        "available": True,
        "length": _info_get(info, "length", 0),
        "first_id": _entry_id(_info_get(info, "first-entry")),
        "last_id": _entry_id(_info_get(info, "last-entry")),
        "groups": [_stream_group_record(group) for group in groups],
        "warning": "",
    }


def _module_record_with_stream_health(definition, *, redis_client=None):
    record = _module_record(definition)
    try:
        record["stream_health"] = _stream_health(definition.stream_name, redis_client=redis_client)
    except redis.RedisError as exc:
        record["stream_health"] = {
            "available": False,
            "length": 0,
            "first_id": "",
            "last_id": "",
            "groups": [],
            "warning": f"{type(exc).__name__}: {exc}",
        }
    return record


def _section_result(section, items, errors):
    return {
        "section": section,
        "success": not errors,
        "counts": {
            "items": len(items),
            "errors": len(errors),
        },
        "items": items,
        "errors": errors,
    }


def list_module_definitions_with_health():
    modules, errors = scan_module_definitions()
    items = [
        _module_record_with_stream_health(definition)
        for definition in modules
    ]
    return _section_result("modules", items, errors)


def list_playbook_definition_records():
    playbooks, errors = scan_playbook_definitions()
    items = [_playbook_record(item) for item in playbooks]
    return _section_result("playbooks", items, errors)


def list_siem_definition_records(*, reload=False):
    if reload:
        reload_registry()
    siem_indices, errors = scan_registry_configs()
    items = [_siem_record(item) for item in siem_indices]
    return _section_result("siem", items, errors)


def known_module_streams():
    modules, _errors = scan_module_definitions()
    return {definition.stream_name for definition in modules}


def read_module_stream_recent(stream_name, limit):
    limit = max(1, min(int(limit or 5), MAX_STREAM_MESSAGES))
    messages = RedisStreamClient().read_stream_recent(stream_name, limit)
    return {
        "stream_name": stream_name,
        "consumer_group": AGENTIC_MODULE_CONSUMER_GROUP,
        "limit": limit,
        "messages": messages,
    }


def read_module_stream_message(stream_name, message_id):
    message = RedisStreamClient().read_stream_message_by_id(stream_name, message_id)
    return {
        "stream_name": stream_name,
        "message_id": message_id,
        "message": message,
    }
