from django.urls import re_path, include
from rest_framework import routers

# from Core.views import BaseAuthView, CurrentUserView


router = routers.DefaultRouter(trailing_slash=False)
# router.register(r'api/login/account', BaseAuthView, basename="BaseAuth")
# router.register(r'api/currentUser', CurrentUserView, basename="CurrentUser")


urlpatterns = [
    re_path(r'^', include(router.urls)),
]
from Lib.montior import MainMonitor

MainMonitor().start()
