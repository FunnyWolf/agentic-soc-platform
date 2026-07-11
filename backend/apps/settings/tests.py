from unittest.mock import patch

from django.test import SimpleTestCase

from apps.settings.models import ThreatIntelOpenCTIConfig
from apps.settings.serializers import ThreatIntelOpenCTIConfigSerializer
from apps.settings.services import test_alienvault_otx_config, test_opencti_config

import httpx


class FakeHelper:
    def __init__(self, items):
        self.items = items

    def list(self, **kwargs):
        return self.items


class FakeOpenCTIClient:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.indicator = FakeHelper([{"id": "indicator-1", "name": "Indicator sample", "entity_type": "Indicator"}])
        self.stix_cyber_observable = FakeHelper(
            [{"id": "observable-1", "observable_value": "203.0.113.10", "entity_type": "IPv4-Addr"}]
        )


class FakeOTXClientWithPublicIndicatorEndpoint:
    requested_urls = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url, headers):
        self.requested_urls.append(url)
        if url.endswith("/user/me"):
            return httpx.Response(403, json={"detail": "Authentication required"})
        return httpx.Response(200, json={"indicator": "8.8.8.8", "pulse_info": {"count": 0}})


class ThreatIntelAlienVaultOTXServiceTests(SimpleTestCase):
    @patch("apps.settings.services.httpx.Client", FakeOTXClientWithPublicIndicatorEndpoint)
    def test_otx_test_uses_authenticated_endpoint(self):
        FakeOTXClientWithPublicIndicatorEndpoint.requested_urls = []

        result = test_alienvault_otx_config(
            {
                "api_key": "wrong-key",
                "base_url": "https://otx.alienvault.com/api/v1",
                "proxy": "",
            }
        )

        self.assertFalse(result["success"])
        self.assertEqual(FakeOTXClientWithPublicIndicatorEndpoint.requested_urls, ["https://otx.alienvault.com/api/v1/user/me"])


class ThreatIntelOpenCTIConfigSerializerTests(SimpleTestCase):
    def test_token_is_hidden_without_reveal_context(self):
        instance = ThreatIntelOpenCTIConfig(url="http://opencti.example", token="secret-token")

        data = ThreatIntelOpenCTIConfigSerializer(instance).data

        self.assertEqual(data["token"], "")
        self.assertTrue(data["token_configured"])

    def test_token_can_be_revealed_with_context(self):
        instance = ThreatIntelOpenCTIConfig(url="http://opencti.example", token="secret-token")

        data = ThreatIntelOpenCTIConfigSerializer(instance, context={"reveal_secrets": True}).data

        self.assertEqual(data["token"], "secret-token")


class ThreatIntelOpenCTIServiceTests(SimpleTestCase):
    @patch("apps.settings.services.OpenCTIApiClient", FakeOpenCTIClient)
    def test_opencti_test_checks_health_and_read_permission(self):
        result = test_opencti_config(
            {
                "url": "http://opencti.example",
                "token": "secret-token",
                "ssl_verify": False,
                "proxy": "",
            }
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["detail"], "OpenCTI responded successfully.")
        self.assertIn("indicator_sample_count", result["response_preview"])
        self.assertIn("observable_sample_count", result["response_preview"])

    def test_opencti_test_requires_token(self):
        result = test_opencti_config(
            {
                "url": "http://opencti.example",
                "token": "",
                "ssl_verify": False,
                "proxy": "",
            }
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["detail"], "OpenCTI API token is not configured.")
