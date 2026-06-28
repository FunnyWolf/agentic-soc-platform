from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from django.urls import Resolver404, resolve
from django.utils import timezone
from rest_framework.test import APIClient

from apps.settings.models import RuntimeConfig, SiemElkConfig
from apps.settings.runtime_config import get_elk_config, invalidate
from apps.webhook.elk_actions import ELKActionProcessor
from apps.webhook.schemas import WebhookResult
from apps.webhook.service import (
    WebhookRedisError,
    handle_kibana_webhook,
    handle_splunk_webhook,
)


class FakeRedisClient:
    def __init__(self):
        self.messages = []

    def send_message(self, stream, data, *, maxlen=None):
        self.messages.append({"stream": stream, "data": data, "maxlen": maxlen})
        return f"{len(self.messages)}-0"


class FailingRedisClient:
    def send_message(self, stream, data, *, maxlen=None):
        raise RuntimeError("redis unavailable")


class FakeElkClient:
    def __init__(self):
        self.searches = []

    def search(self, **kwargs):
        self.searches.append(kwargs)
        return {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "rule": {"name": "rule-without-hits"},
                            "context": {"hits": []},
                        }
                    }
                ]
            }
        }


class WebhookServiceTests(TestCase):
    def set_stream_maxlen(self, value):
        config = RuntimeConfig.get_current()
        config.stream_maxlen = value
        config.save(update_fields=["stream_maxlen", "updated_at"])
        invalidate("runtime")

    def test_handle_splunk_webhook_writes_result_to_search_stream(self):
        self.set_stream_maxlen(123)
        redis_client = FakeRedisClient()

        result = handle_splunk_webhook(
            {"search_name": " test-search ", "result": {"host": "server-1"}},
            redis_client=redis_client,
        )

        self.assertEqual(result.stream, "test-search")
        self.assertEqual(result.sent, 1)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(result.message_ids, ["1-0"])
        self.assertEqual(
            redis_client.messages,
            [{"stream": "test-search", "data": {"host": "server-1"}, "maxlen": 123}],
        )

    def test_handle_splunk_webhook_rejects_empty_search_name(self):
        with self.assertRaisesMessage(ValueError, "search_name is required."):
            handle_splunk_webhook({"search_name": " ", "result": {}}, redis_client=FakeRedisClient())

    def test_handle_kibana_webhook_writes_normalized_sources(self):
        self.set_stream_maxlen(456)
        redis_client = FakeRedisClient()

        result = handle_kibana_webhook(
            {
                "rule": {"name": " kibana-rule "},
                "context": {
                    "hits": [
                        {
                            "_source": {
                                "user": {"keyword": "alice"},
                                "host.keyword": "ignored",
                                "tags": [{"keyword": "prod"}],
                            }
                        }
                    ]
                },
            },
            redis_client=redis_client,
        )

        self.assertEqual(result.stream, "kibana-rule")
        self.assertEqual(result.sent, 1)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(result.message_ids, ["1-0"])
        self.assertEqual(
            redis_client.messages,
            [{"stream": "kibana-rule", "data": {"user": "alice", "tags": ["prod"]}, "maxlen": 456}],
        )

    def test_handle_kibana_webhook_skips_empty_sources(self):
        redis_client = FakeRedisClient()

        result = handle_kibana_webhook(
            {"rule": {"name": "rule"}, "context": {"hits": [{"_source": {}}, None]}},
            redis_client=redis_client,
        )

        self.assertEqual(result.sent, 0)
        self.assertEqual(result.skipped, 2)
        self.assertEqual(redis_client.messages, [])

    def test_handle_kibana_webhook_raises_webhook_error_on_redis_failure(self):
        with self.assertRaisesMessage(WebhookRedisError, "Failed to write Redis stream rule: RuntimeError"):
            handle_kibana_webhook(
                {"rule": {"name": "rule"}, "context": {"hits": [{"_source": {"event": "login"}}]}},
                redis_client=FailingRedisClient(),
            )


class ELKActionProcessorTests(TestCase):
    def test_process_once_refreshes_config_cached_before_settings_change(self):
        config = SiemElkConfig.get_current()
        config.host = "https://elk.example.com:9200"
        config.api_key = "test-api-key"
        config.process_alert_from_index_enabled = False
        config.save()
        invalidate("elk")

        elk_client = FakeElkClient()
        processor = ELKActionProcessor(elk_client=elk_client, interval_seconds=60)
        self.assertFalse(get_elk_config()["process_alert_from_index_enabled"])

        config.process_alert_from_index_enabled = True
        config.save(update_fields=["process_alert_from_index_enabled", "updated_at"])

        end_time = timezone.now()
        result = processor.process_once(start_time=end_time - timedelta(seconds=60), end_time=end_time)

        self.assertEqual(result.actions, 1)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(len(elk_client.searches), 1)


class WebhookAPITests(SimpleTestCase):
    def setUp(self):
        self.client = APIClient()

    @patch("apps.webhook.views.handle_splunk_webhook")
    def test_splunk_webhook_route_uses_new_api_path(self, handle_splunk_webhook_mock):
        handle_splunk_webhook_mock.return_value = WebhookResult(stream="search", sent=1, message_ids=["1-0"])

        response = self.client.post(
            "/api/webhook/splunk/",
            {"search_name": "search", "result": {"host": "server-1"}},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["stream"], "search")
        handle_splunk_webhook_mock.assert_called_once()

    @patch("apps.webhook.views.handle_kibana_webhook")
    def test_kibana_webhook_route_uses_new_api_path(self, handle_kibana_webhook_mock):
        handle_kibana_webhook_mock.return_value = WebhookResult(stream="rule", sent=1, message_ids=["1-0"])

        response = self.client.post(
            "/api/webhook/kibana/",
            {"rule": {"name": "rule"}, "context": {"hits": [{"_source": {"host": "server-1"}}]}},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["stream"], "rule")
        handle_kibana_webhook_mock.assert_called_once()

    @patch("apps.webhook.views.handle_splunk_webhook")
    def test_webhook_redis_error_returns_service_unavailable(self, handle_splunk_webhook_mock):
        handle_splunk_webhook_mock.side_effect = WebhookRedisError("Failed to write Redis stream search: RuntimeError")

        response = self.client.post(
            "/api/webhook/splunk/",
            {"search_name": "search", "result": {"host": "server-1"}},
            format="json",
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "Failed to write Redis stream search: RuntimeError")

    def test_old_agentic_forwarder_route_is_removed(self):
        with self.assertRaises(Resolver404):
            resolve("/api/agentic/forwarder/splunk/")
