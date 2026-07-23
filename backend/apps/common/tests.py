from unittest.mock import patch
from types import SimpleNamespace
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase
from django.utils import timezone

from apps.common.cursor_pagination import decode_cursor, encode_cursor
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


class CursorPaginationTests(SimpleTestCase):
    def test_cursor_round_trips_uuid_primary_key(self):
        record_id = uuid4()
        created_at = timezone.now()
        cursor = encode_cursor(SimpleNamespace(id=record_id, created_at=created_at))

        decoded_created_at, decoded_id = decode_cursor(cursor)

        self.assertEqual(decoded_created_at, created_at)
        self.assertEqual(decoded_id, str(record_id))


class BackendImageDependencyTests(SimpleTestCase):
    def test_backend_image_installs_libmagic_for_python_magic(self):
        dockerfile = settings.BASE_DIR / "Dockerfile"

        self.assertIn("libmagic1", dockerfile.read_text(encoding="utf-8"))
