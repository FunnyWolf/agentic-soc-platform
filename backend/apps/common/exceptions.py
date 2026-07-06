import json
import logging
from uuid import uuid4

from rest_framework.views import exception_handler

logger = logging.getLogger(__name__)

SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "password",
    "secret",
    "token",
}


def _redact(value):
    if isinstance(value, dict):
        return {
            key: "***" if any(sensitive in str(key).lower() for sensitive in SENSITIVE_KEYS) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    return value


def _serializable(value):
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(key): _serializable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [_serializable(item) for item in value]
        return str(value)


def _client_ip(request):
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _query_params(request):
    return _redact({key: values if len(values) != 1 else values[0] for key, values in request.GET.lists()})


def _request_id(request):
    return request.headers.get("X-Request-ID") or f"req_{uuid4().hex}"


def _user_context(request):
    user = getattr(request, "user", None)
    if not user or not getattr(user, "is_authenticated", False):
        return {"id": None, "username": ""}
    return {"id": getattr(user, "id", None), "username": getattr(user, "username", "")}


def _view_context(context):
    view = context.get("view")
    if not view:
        return {"name": "", "action": ""}
    return {
        "name": f"{view.__class__.__module__}.{view.__class__.__name__}",
        "action": getattr(view, "action", ""),
    }


def _event(exc, context, response=None):
    request = context.get("request")
    response_data = _serializable(getattr(response, "data", None)) if response is not None else None
    return {
        "request_id": _request_id(request) if request is not None else "",
        "method": getattr(request, "method", ""),
        "path": getattr(request, "path", ""),
        "query_params": _query_params(request) if request is not None else {},
        "status_code": getattr(response, "status_code", 500),
        "client_ip": _client_ip(request) if request is not None else "",
        "user": _user_context(request) if request is not None else {"id": None, "username": ""},
        "view": _view_context(context),
        "exception": exc.__class__.__name__,
        "response_data": _redact(response_data),
    }


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    event = _event(exc, context, response)
    event_json = json.dumps(event, ensure_ascii=False, default=str)

    if response is None:
        logger.exception("Unhandled API exception: %s", event_json, extra={"api_error": event})
        return None

    if response.status_code >= 500:
        logger.exception("API server error: %s", event_json, extra={"api_error": event})
    elif response.status_code >= 400:
        logger.warning("API request failed: %s", event_json, extra={"api_error": event})

    return response
