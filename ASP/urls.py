from django.urls import re_path, include
from rest_framework import routers

# from Core.views import BaseAuthView, CurrentUserView
from Forwarder.views import WebhookSplunkView, WebhookKibanaView, WebhookNocolyMailView

router = routers.DefaultRouter(trailing_slash=False)
# router.register(r'api/login/account', BaseAuthView, basename="BaseAuth")
# router.register(r'api/currentUser', CurrentUserView, basename="CurrentUser")

router.register(r'api/v1/webhook/splunk', WebhookSplunkView, basename="WebhookSplunkView")
router.register(r'api/v1/webhook/kibana', WebhookKibanaView, basename="WebhookKibanaView")
router.register(r'api/v1/webhook/nocolymail', WebhookNocolyMailView, basename="WebhookNocolyMailView")

urlpatterns = [
    re_path(r'^', include(router.urls)),
]
from Lib.montior import MainMonitor

MainMonitor().start()
