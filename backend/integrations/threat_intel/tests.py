from django.test import SimpleTestCase, TestCase

from apps.settings.models import ThreatIntelAlienVaultOTXConfig, ThreatIntelOpenCTIConfig
from apps.settings.runtime_config import invalidate
from integrations.threat_intel.providers import OPENCTI_PROVIDER_NAME, OpenCTIProvider, get_providers
from integrations.threat_intel.service import query_indicator


class FakeHelper:
    def __init__(self, items=None):
        self.items = items or []
        self.calls = []

    def list(self, **kwargs):
        self.calls.append(kwargs)
        return self.items


class FakeOpenCTIClient:
    def __init__(self):
        self.indicator = FakeHelper(
            [
                {
                    "id": "indicator-1",
                    "standard_id": "indicator--1",
                    "entity_type": "Indicator",
                    "name": "Bad IP",
                    "pattern": "[ipv4-addr:value = '203.0.113.10']",
                    "x_opencti_score": 82,
                    "x_opencti_observable_values": [{"type": "IPv4-Addr", "value": "203.0.113.10"}],
                    "objectLabel": [{"value": "c2"}, {"value": "mock-opencti"}],
                },
                {
                    "id": "indicator-prefix-false-positive",
                    "standard_id": "indicator--prefix",
                    "entity_type": "Indicator",
                    "name": "Similar IP",
                    "pattern": "[ipv4-addr:value = '203.0.113.107']",
                    "x_opencti_score": 90,
                    "x_opencti_observable_values": [{"type": "IPv4-Addr", "value": "203.0.113.107"}],
                }
            ]
        )
        self.stix_cyber_observable = FakeHelper(
            [
                {
                    "id": "observable-1",
                    "standard_id": "ipv4-addr--1",
                    "entity_type": "IPv4-Addr",
                    "observable_value": "203.0.113.10",
                    "x_opencti_score": 65,
                    "objectLabel": [{"value": "observable"}],
                },
                {
                    "id": "observable-prefix-false-positive",
                    "standard_id": "ipv4-addr--prefix",
                    "entity_type": "IPv4-Addr",
                    "observable_value": "203.0.113.107",
                }
            ]
        )
        self.stix_core_relationship = FakeHelper(
            [
                {
                    "id": "relationship-1",
                    "standard_id": "relationship--1",
                    "entity_type": "uses",
                    "relationship_type": "uses",
                    "from": {"id": "indicator-1", "entity_type": "Indicator", "name": "Bad IP"},
                    "to": {"id": "malware-1", "entity_type": "Malware", "name": "LedgerLocker"},
                },
                {
                    "id": "relationship-2",
                    "standard_id": "relationship--2",
                    "entity_type": "uses",
                    "relationship_type": "uses",
                    "from": {"id": "indicator-1", "entity_type": "Indicator", "name": "Bad IP"},
                    "to": {"id": "attack-1", "entity_type": "Attack-Pattern", "name": "T1566.002 - Spearphishing Link"},
                },
            ]
        )


class OpenCTIProviderTests(SimpleTestCase):
    def test_query_maps_opencti_result_to_common_ti_result(self):
        provider = OpenCTIProvider(
            url="http://opencti.example",
            token="token",
            ssl_verify=False,
            proxy="",
            client=FakeOpenCTIClient(),
        )

        result = provider.query("203.0.113.10", artifact_type="IP Address")

        self.assertEqual(result.provider, OPENCTI_PROVIDER_NAME)
        self.assertEqual(result.indicator_type, "ip")
        self.assertEqual(result.risk_level, "high")
        self.assertEqual(result.reputation_score, 82)
        self.assertTrue(result.is_malicious)
        self.assertIn("LedgerLocker", result.malware_families)
        self.assertIn("T1566.002 - Spearphishing Link", result.attack_techniques)
        self.assertEqual(result.raw["opencti"]["stix_type"], "IPv4-Addr")
        self.assertEqual(result.raw["opencti"]["matched_by"], "strict_type_mapping")
        self.assertEqual(len(result.raw["opencti"]["matches"]), 2)

    def test_query_returns_provider_error_for_unsupported_type(self):
        provider = OpenCTIProvider(
            url="http://opencti.example",
            token="token",
            ssl_verify=False,
            proxy="",
            client=FakeOpenCTIClient(),
        )

        result = provider.query("443", artifact_type="Port")

        self.assertEqual(result.provider, OPENCTI_PROVIDER_NAME)
        self.assertIn("Unsupported artifact type", result.error)


class ThreatIntelProviderRegistryTests(TestCase):
    def tearDown(self):
        invalidate("threat_intel")
        return super().tearDown()

    def test_no_enabled_real_providers_does_not_fallback_to_mock(self):
        ThreatIntelAlienVaultOTXConfig.get_current()
        ThreatIntelOpenCTIConfig.get_current()
        invalidate("threat_intel")

        self.assertEqual(get_providers(), {})
        result = query_indicator("203.0.113.10", artifact_type="IP Address")
        self.assertEqual(result.results, [])
        self.assertEqual(result.errors, ["No enabled threat intelligence providers are configured."])

    def test_get_providers_includes_enabled_opencti(self):
        opencti = ThreatIntelOpenCTIConfig.get_current()
        opencti.enabled = True
        opencti.url = "http://opencti.example"
        opencti.token = "token"
        opencti.save()
        invalidate("threat_intel")

        self.assertEqual(list(get_providers().keys()), [OPENCTI_PROVIDER_NAME])
