from asgiref.sync import async_to_sync
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from starlette.routing import Mount

from apps.accounts.models import User, UserApiKey
from apps.mcp.asgi import mcp_asgi_app
from apps.mcp.auth import ApiKeyMCPMiddleware
from apps.mcp.server import create_mcp_server
from apps.mcp.tools import REGISTERED_MCP_TOOLS


class FakeMCPServer:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.tools = []

    def add_tool(self, tool):
        self.tools.append(tool)


class MCPServerTests(SimpleTestCase):
    def test_create_mcp_server_registers_all_tools(self):
        server = create_mcp_server(server_factory=FakeMCPServer)

        self.assertEqual(server.args[0], "ASP-MCP")
        self.assertTrue(server.kwargs["stateless_http"])
        self.assertTrue(server.kwargs["json_response"])
        self.assertEqual(server.kwargs["streamable_http_path"], "/")
        self.assertEqual(server.tools, REGISTERED_MCP_TOOLS)

    def test_mcp_asgi_app_uses_api_key_middleware(self):
        self.assertIsInstance(mcp_asgi_app, ApiKeyMCPMiddleware)


class MCPASGIMountTests(SimpleTestCase):
    def test_asp_asgi_mounts_new_mcp_path_only(self):
        from asp.asgi import application

        http_application = application.application_mapping["http"]
        paths = [route.path for route in http_application.routes if isinstance(route, Mount)]

        self.assertIn("/api/mcp", paths)
        self.assertNotIn("/api/agentic/mcp", paths)


class MCPAuthMiddlewareTests(TestCase):
    def _call_middleware(self, middleware, *, headers=None):
        messages = []
        scope = {"type": "http", "headers": headers or []}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        async_to_sync(middleware)(scope, receive, send)
        return scope, messages

    def test_missing_api_key_returns_unauthorized(self):
        async def app(scope, receive, send):
            raise AssertionError("inner app should not be called")

        _scope, messages = self._call_middleware(ApiKeyMCPMiddleware(app))

        self.assertEqual(messages[0]["status"], 401)
        self.assertIn(b"API key required", messages[1]["body"])

    def test_invalid_api_key_returns_unauthorized(self):
        async def app(scope, receive, send):
            raise AssertionError("inner app should not be called")

        _scope, messages = self._call_middleware(
            ApiKeyMCPMiddleware(app),
            headers=[(b"authorization", b"Api-Key invalid")],
        )

        self.assertEqual(messages[0]["status"], 401)
        self.assertIn(b"Invalid API key", messages[1]["body"])

    def test_valid_api_key_sets_scope_and_updates_last_used_at(self):
        user = User.objects.create_user(username="mcp-user", password="unused")
        api_key = UserApiKey.objects.create(user=user, name="mcp", key="asp_test")
        captured_scope = {}

        async def app(scope, receive, send):
            captured_scope.update(scope)
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        scope, messages = self._call_middleware(
            ApiKeyMCPMiddleware(app),
            headers=[(b"authorization", b"Api-Key asp_test")],
        )

        api_key.refresh_from_db()
        self.assertEqual(messages[0]["status"], 204)
        self.assertEqual(scope["user"], user)
        self.assertEqual(scope["api_key"], api_key)
        self.assertEqual(captured_scope["user"], user)
        self.assertIsNotNone(api_key.last_used_at)
        self.assertLessEqual(api_key.last_used_at, timezone.now())
