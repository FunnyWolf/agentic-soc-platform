from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.worker_runner import _run_once_or_raise


class WorkerRunnerTests(SimpleTestCase):
    def test_run_once_refreshes_runtime_config_before_work(self):
        calls = []

        def run_once():
            calls.append("run_once")
            return True

        with patch("apps.common.worker_runner._refresh_runtime_config_cache") as refresh:
            result = _run_once_or_raise("test worker", run_once)

        self.assertTrue(result.processed)
        refresh.assert_called_once()
        self.assertEqual(calls, ["run_once"])
