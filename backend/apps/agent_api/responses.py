from uuid import uuid4

from rest_framework.response import Response


def request_id(request):
    return request.headers.get("X-Request-ID") or f"req_{uuid4().hex}"


def agent_response(request, *, operation, data, status=200, pagination=None):
    meta = {
        "operation": operation,
        "request_id": request_id(request),
    }
    if pagination is not None:
        meta["pagination"] = pagination
    return Response({"data": data, "meta": meta}, status=status)


def pagination_meta(page):
    return {
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
    }
