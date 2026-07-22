from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient


class AgentSIEMValidationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="agent", password="password")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_keyword_search_backend_value_error_returns_bad_request(self):
        payload = {
            "keyword": "powershell",
            "index_name": 'main" | delete index=* | search index="x',
            "time_range_start": "2026-06-23T12:00:00Z",
            "time_range_end": "2026-06-23T13:00:00Z",
        }

        with patch("apps.agent_api.views.siem_service.keyword_search", side_effect=ValueError("Invalid Splunk index name")):
            response = self.client.post("/api/agent/v1/siem/search/keyword/", payload, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["detail"], "Invalid Splunk index name")
