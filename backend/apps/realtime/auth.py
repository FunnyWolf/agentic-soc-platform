from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.authentication import JWTAuthentication


class JWTAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope["user"] = await self._authenticate(scope)
        return await self.app(scope, receive, send)

    @database_sync_to_async
    def _authenticate(self, scope):
        token = self._token_from_scope(scope)
        if not token:
            return AnonymousUser()

        authenticator = JWTAuthentication()
        try:
            validated_token = authenticator.get_validated_token(token)
            return authenticator.get_user(validated_token)
        except Exception:
            return AnonymousUser()

    def _token_from_scope(self, scope):
        query_string = scope.get("query_string", b"").decode("utf-8")
        token = parse_qs(query_string).get("token", [""])[0]
        if token:
            return token

        for name, value in scope.get("headers", []):
            if name != b"sec-websocket-protocol":
                continue
            protocols = [
                part.strip()
                for part in value.decode("utf-8").split(",")
                if part.strip()
            ]
            for protocol in protocols:
                if protocol.startswith("bearer."):
                    return protocol.removeprefix("bearer.")
        return ""

