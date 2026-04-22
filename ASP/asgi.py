# -*- coding: utf-8 -*-
# @File  : asgi.py
# @Date  : 2019/10/3
# @Desc  :

"""
ASGI entrypoint. Configures Django and then runs the application
defined in the ASGI_APPLICATION setting.
"""
import os

import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ASP.settings')
os.environ.setdefault('ASP_START_BACKGROUND_SERVICES', '1')
os.environ.setdefault('ASP_BACKGROUND_SERVICES_SOURCE', 'asgi')
django.setup()
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

websocket_urlpatterns = [

]

application = ProtocolTypeRouter({
    "http": get_asgi_application(),  # Django's WSGI application handles HTTP requests
    "websocket": AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns  # WebSocket handling
        )
    ),
})
