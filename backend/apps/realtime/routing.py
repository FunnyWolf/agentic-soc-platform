from django.urls import path

from .consumers import EventsConsumer

websocket_urlpatterns = [
    path("ws/events/", EventsConsumer.as_asgi()),
]
