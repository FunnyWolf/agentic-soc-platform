import json
import logging
from dataclasses import dataclass
from datetime import UTC, timedelta

from django.utils import timezone

from apps.settings.runtime_config import get_elk_config, invalidate
from apps.webhook.service import handle_kibana_webhook
from integrations.siem.clients import get_elk_client

logger = logging.getLogger(__name__)

ELK_CLIENT_CONFIG_FIELDS = ("host", "api_key", "verify_certs", "request_timeout_seconds")


@dataclass
class ProcessResult:
    actions: int = 0
    sent: int = 0
    skipped: int = 0


def format_es_time(value):
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ELKActionProcessor:
    def __init__(self, *, elk_client=None, index_name=None, interval_seconds=None, size=None):
        config = self.load_config()
        self.elk_client = elk_client
        self.index_name_override = index_name
        self.interval_seconds_override = interval_seconds
        self.size_override = size
        self.index_name = index_name if index_name is not None else config["action_index"]
        self.interval_seconds = interval_seconds if interval_seconds is not None else config["action_poll_interval_seconds"]
        self.size = size if size is not None else config["action_size"]
        self.elk_client_config = self.client_config(config)
        self.last_check_time = None

    @staticmethod
    def load_config():
        invalidate("elk")
        return get_elk_config()

    @staticmethod
    def client_config(config):
        return tuple(config[field] for field in ELK_CLIENT_CONFIG_FIELDS)

    @staticmethod
    def parse_hits(hits):
        if isinstance(hits, str):
            hits = json.loads(hits)
        if isinstance(hits, dict):
            return [hits]
        return hits if isinstance(hits, list) else []

    def refresh_config(self):
        config = self.load_config()
        elk_client_config = self.client_config(config)
        if self.elk_client is None and elk_client_config != self.elk_client_config:
            get_elk_client.cache_clear()
        self.elk_client_config = elk_client_config
        if self.index_name_override is None:
            self.index_name = config["action_index"]
        if self.interval_seconds_override is None:
            self.interval_seconds = config["action_poll_interval_seconds"]
        if self.size_override is None:
            self.size = config["action_size"]
        return config

    def process_once(self, *, start_time=None, end_time=None):
        config = self.refresh_config()
        current_time = end_time or timezone.now()
        if not config["process_alert_from_index_enabled"]:
            self.last_check_time = current_time
            logger.info("ELK Process Alert From Index is disabled; skipping poll")
            return ProcessResult()

        if self.last_check_time is None:
            self.last_check_time = start_time or current_time - timedelta(seconds=self.interval_seconds)

        query_body = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": format_es_time(self.last_check_time),
                                "lt": format_es_time(current_time),
                            }
                        }
                    }
                ]
            }
        }

        elk_client = self.elk_client or get_elk_client()
        response = elk_client.search(
            index=self.index_name,
            query=query_body,
            size=self.size,
            sort=[{"@timestamp": {"order": "asc"}}],
        )
        result = ProcessResult()
        for action_hit in response.get("hits", {}).get("hits", []):
            result.actions += 1
            action_source = action_hit.get("_source") if isinstance(action_hit, dict) else None
            sent, skipped = self.process_action(action_source if isinstance(action_source, dict) else {})
            result.sent += sent
            result.skipped += skipped

        self.last_check_time = current_time
        return result

    def process_action(self, action_data):
        rule_name = action_data.get("rule", {}).get("name") if isinstance(action_data.get("rule"), dict) else ""
        if not rule_name:
            logger.warning("ELK action missing rule.name; skipping")
            return 0, 1
        try:
            hits = self.parse_hits(
                action_data.get("context", {}).get("hits", []) if isinstance(action_data.get("context"), dict) else []
            )
        except json.JSONDecodeError:
            logger.warning("ELK action %s has invalid JSON context.hits; skipping", rule_name)
            return 0, 1
        if not hits:
            logger.warning("ELK action %s has no context.hits; skipping", rule_name)
            return 0, 1

        webhook_result = handle_kibana_webhook({"rule": {"name": rule_name}, "context": {"hits": hits}})
        return webhook_result.sent, webhook_result.skipped
