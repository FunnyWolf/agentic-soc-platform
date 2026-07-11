"""
ASGI config for asp project.
"""

import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter

from apps.common.logging import configure_process_file_logging

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "asp.settings")

django_application = get_asgi_application()
configure_process_file_logging("asgi")

from apps.realtime.auth import JWTAuthMiddleware  # noqa: E402
from apps.realtime.routing import websocket_urlpatterns  # noqa: E402


application = ProtocolTypeRouter({
    "http": django_application,
    "websocket": JWTAuthMiddleware(URLRouter(websocket_urlpatterns)),
})
