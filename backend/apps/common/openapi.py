from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.openapi import AutoSchema
from drf_spectacular.plumbing import build_serializer_context
from drf_spectacular.types import OpenApiTypes
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView


class AspAutoSchema(AutoSchema):
    def _get_serializer(self):
        view = self.view
        context = build_serializer_context(view)
        try:
            if isinstance(view, GenericAPIView):
                if view.__class__.get_serializer == GenericAPIView.get_serializer:
                    return view.get_serializer_class()(context=context)
                return view.get_serializer(context=context)
            if isinstance(view, APIView):
                if callable(getattr(view, "get_serializer", None)):
                    return view.get_serializer(context=context)
                if callable(getattr(view, "get_serializer_class", None)):
                    return view.get_serializer_class()(context=context)
                if hasattr(view, "serializer_class"):
                    return view.serializer_class
        except Exception:
            return None
        return None

    def get_request_serializer(self):
        serializer = self._get_serializer()
        if serializer is None and self.method in ("POST", "PUT", "PATCH"):
            return OpenApiTypes.OBJECT
        return serializer

    def get_response_serializers(self):
        return self._get_serializer() or OpenApiTypes.OBJECT


class BearerAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "rest_framework_simplejwt.authentication.JWTAuthentication"
    name = "bearerAuth"
    priority = 1

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Use the format: Bearer <access_token>",
        }


class ApiKeyAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "apps.accounts.authentication.ApiKeyAuthentication"
    name = "apiKeyAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Use the format: Api-Key <key>",
        }


BUSINESS_TAG_PREFIXES = (
    ("/api/agent/v1/", "Agent API"),
    ("/api/auth/api-keys", "API Keys"),
    ("/api/auth/users", "Users"),
    ("/api/auth/", "Auth"),
    ("/api/alerts", "Alerts"),
    ("/api/artifacts", "Artifacts"),
    ("/api/attachments", "Attachments"),
    ("/api/audit-logs", "Audit"),
    ("/api/cases", "Cases"),
    ("/api/comments", "Comments"),
    ("/api/custom/", "Custom"),
    ("/api/dashboard", "Dashboard"),
    ("/api/enrichments", "Enrichments"),
    ("/api/health", "System"),
    ("/api/inbox", "Inbox"),
    ("/api/knowledge", "Knowledge"),
    ("/api/metadata", "Metadata"),
    ("/api/playbooks", "Playbooks"),
    ("/api/saved-table-filters", "Preferences"),
    ("/api/settings", "Settings"),
    ("/api/user-table-preferences", "Preferences"),
    ("/api/webhook", "Webhooks"),
)


def postprocess_business_tags(result, generator, request, public):
    for path, methods in result.get("paths", {}).items():
        tag = next((candidate for prefix, candidate in BUSINESS_TAG_PREFIXES if path.startswith(prefix)), None)
        if tag is None:
            continue
        for operation in methods.values():
            if isinstance(operation, dict):
                operation["tags"] = [tag]
    return result
