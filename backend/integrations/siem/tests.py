from django.test import SimpleTestCase

from integrations.siem.query_builders import format_splunk_index


class SplunkIndexFormattingTests(SimpleTestCase):
    def test_allows_valid_index_names_and_wildcard_sentinel(self):
        for index_name in ("main", "wineventlog", "linux_secure", "os:linux", "prod-web.1", "*"):
            with self.subTest(index_name=index_name):
                self.assertEqual(format_splunk_index(index_name), index_name)

    def test_rejects_values_that_can_escape_splunk_index_clause(self):
        malicious_values = (
            'main" | delete index=* | search index="x',
            "main | stats count",
            "main; delete",
            "main search",
            "",
            "a" * 81,
            123,
        )

        for index_name in malicious_values:
            with self.subTest(index_name=index_name):
                with self.assertRaisesMessage(ValueError, "Invalid Splunk index name"):
                    format_splunk_index(index_name)
