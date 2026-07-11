from functools import lru_cache

import splunklib.client
from elasticsearch import Elasticsearch

from apps.settings.runtime_config import get_elk_config, get_splunk_config


def _require_setting(name, value):
    if value in {None, ""}:
        raise RuntimeError(f"{name} is required for SIEM live backend tests.")
    return value


@lru_cache(maxsize=1)
def get_splunk_service():
    config = get_splunk_config()
    return splunklib.client.connect(
        host=_require_setting("Splunk host", config["host"]),
        port=config["port"],
        username=_require_setting("Splunk username", config["username"]),
        password=_require_setting("Splunk password", config["password"]),
        scheme=config["scheme"],
        verify=config["verify"],
    )


@lru_cache(maxsize=1)
def get_elk_client():
    config = get_elk_config()
    return Elasticsearch(
        _require_setting("ELK host", config["host"]),
        api_key=_require_setting("ELK API key", config["api_key"]),
        verify_certs=config["verify_certs"],
    )


def reset_clients():
    get_splunk_service.cache_clear()
    get_elk_client.cache_clear()
