import datetime

from django.utils import timezone

from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.generics import UpdateAPIView, DestroyAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from Core.Handle.currentuser import CurrentUser
from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import BASEAUTH_MSG_ZH, BASEAUTH_MSG_EN, EXPIRE_MINUTES
from Lib.log import logger


class BaseAuthView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = []
    serializer_class = AuthTokenSerializer
    authentication_classes = []
    permission_classes = [AllowAny]

    def create(self, request, pk=None, **kwargs):

        null_response = {"status": "error", "type": "account", "currentAuthority": "guest",
                         "token": "forguest"}

        # Get encrypted password and decrypt it
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            serializer = AuthTokenSerializer(data={"username": username, "password": password})
            if serializer.is_valid():
                token, created = Token.objects.get_or_create(user=serializer.validated_data['user'])
                time_now = timezone.now()
                if created or token.created < time_now - datetime.timedelta(minutes=EXPIRE_MINUTES):  # type: ignore[operator]
                    # Update creation time to keep token valid
                    token.delete()
                    token = Token.objects.create(user=serializer.validated_data['user'])
                    token.created = time_now
                    token.save()
                null_response['status'] = 'ok'
                null_response['currentAuthority'] = 'admin'  # Currently in single-user mode, default is admin
                null_response['token'] = token.key
                context = data_return(201, null_response, BASEAUTH_MSG_ZH.get(201), BASEAUTH_MSG_EN.get(201))
                return Response(context)
            else:
                context = data_return(301, null_response, BASEAUTH_MSG_ZH.get(301), BASEAUTH_MSG_EN.get(301))
                return Response(context)
        except Exception as E:
            logger.exception(E)
            context = data_return(301, null_response, BASEAUTH_MSG_ZH.get(301), BASEAUTH_MSG_EN.get(301))
            return Response(context)


class CurrentUserView(BaseView):
    def list(self, request, **kwargs):
        """Query host information in the database"""
        user = request.user
        user_info = CurrentUser.list(user)
        context = data_return(301, user_info, BASEAUTH_MSG_ZH.get(301), BASEAUTH_MSG_EN.get(301))
        return Response(context)
