import logging

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from django.db import models
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import parsers, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from apps.attachments.models import Attachment
from apps.common.advanced_filters import AdvancedFilterBackend
from .ldap import ldap_authenticates
from .models import UserApiKey
from .permissions import IsAdmin
from .serializers import (
    ChangePasswordSerializer,
    LoginSerializer,
    UserAdminUpdateSerializer,
    UserApiKeySerializer,
    UserCreateSerializer,
    UserProfileSerializer,
    UserSerializer,
    generate_password,
)

User = get_user_model()
logger = logging.getLogger(__name__)


def _credentials_for(user, password=None):
    credentials = {
        "username": user.username,
        "auth_type": user.auth_type,
    }
    if password:
        credentials["password"] = password
    return credentials


def _set_avatar_attachment(user, attachment_id):
    try:
        attachment = Attachment.objects.get(id=attachment_id)
    except Attachment.DoesNotExist:
        return Response({"detail": "Attachment not found."}, status=404)
    user.avatar_attachment = attachment
    user.save(update_fields=["avatar_attachment"])
    return None


def _serialized_user(user, request):
    return UserSerializer(user, context={"request": request}).data


class AuthViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]
    parser_classes = [parsers.JSONParser, parsers.MultiPartParser, parsers.FormParser]

    @action(detail=False, methods=["post"])
    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]
        auth_type = serializer.validated_data["auth_type"]

        try:
            expected_user = User.objects.get(username=username)
        except User.DoesNotExist:
            if auth_type == User.AuthType.LDAP:
                logger.warning("LDAP login rejected for %s: ASP user does not exist", username)
            return Response({"detail": "Invalid credentials"}, status=400)

        if expected_user.auth_type != auth_type:
            logger.warning(
                "Login rejected for %s: requested auth_type=%s but user auth_type=%s",
                username,
                auth_type,
                expected_user.auth_type,
            )
            return Response({"detail": "Invalid credentials"}, status=400)

        if not expected_user.is_active:
            logger.warning("Login rejected for %s: user is disabled", username)
            return Response({"detail": "Account disabled"}, status=400)

        if auth_type == User.AuthType.LOCAL:
            user = authenticate(username=username, password=password)
            if user is None or user.id != expected_user.id:
                logger.warning("Local login rejected for %s: invalid password", username)
                return Response({"detail": "Invalid credentials"}, status=400)
        else:
            logger.info("LDAP login requested for %s", username)
            if not ldap_authenticates(username, password):
                logger.warning("LDAP login rejected for %s: LDAP authentication failed", username)
                return Response({"detail": "Invalid credentials"}, status=400)
            user = expected_user

        update_last_login(None, user)
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": _serialized_user(user, request),
        })

    @action(detail=False, methods=["get"], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        return Response(_serialized_user(request.user, request))

    @action(detail=False, methods=["patch"], permission_classes=[permissions.IsAuthenticated])
    def profile(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(_serialized_user(request.user, request))

    @action(detail=False, methods=["put"], permission_classes=[permissions.IsAuthenticated])
    def avatar(self, request):
        attachment_id = request.data.get("attachment_id")
        if not attachment_id:
            return Response({"detail": "attachment_id is required."}, status=400)
        error = _set_avatar_attachment(request.user, attachment_id)
        if error:
            return error
        return Response(_serialized_user(request.user, request))

    @action(detail=False, methods=["post"], permission_classes=[permissions.IsAuthenticated])
    def change_password(self, request):
        if request.user.auth_type != User.AuthType.LOCAL:
            return Response({"detail": "Only local users can change password"}, status=400)

        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user

        if not user.check_password(serializer.validated_data["old_password"]):
            return Response({"detail": "Old password is incorrect"}, status=400)

        user.set_password(serializer.validated_data["new_password"])
        user.save()
        return Response({"detail": "Password changed"})

    @action(detail=False, methods=["get"], url_path="user-options", permission_classes=[permissions.IsAuthenticated])
    def user_options(self, request):
        search = request.query_params.get("search", "").strip()
        queryset = User.objects.filter(is_active=True).order_by("username")
        if search:
            queryset = queryset.filter(
                models.Q(username__icontains=search) |
                models.Q(email__icontains=search) |
                models.Q(first_name__icontains=search) |
                models.Q(last_name__icontains=search) |
                models.Q(mobile_phone__icontains=search)
            )
        return Response([
            {
                "value": str(user.id),
                "label": user.get_full_name() or user.username,
                "id": user.id,
                "username": user.username,
                "name": user.get_full_name(),
            }
            for user in queryset[:50]
        ])


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by("id")
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    parser_classes = [parsers.JSONParser, parsers.MultiPartParser, parsers.FormParser]
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    search_fields = ("username", "email", "first_name", "last_name", "mobile_phone")
    ordering_fields = ("date_joined", "last_login", "is_active", "auth_type")
    filterset_fields = ("is_active", "auth_type")
    advanced_filter_fields = {
        "username": "text",
        "email": "text",
        "first_name": "text",
        "last_name": "text",
        "mobile_phone": "text",
        "auth_type": "select",
        "is_active": "select",
        "date_joined": "date",
        "last_login": "date",
    }

    def get_queryset(self):
        queryset = super().get_queryset()
        role = self.request.query_params.get("role")
        if role == "admin":
            return queryset.filter(is_superuser=True)
        if role == "viewer":
            return queryset.filter(is_superuser=False, groups__name="viewer")
        if role == "user":
            return queryset.filter(is_superuser=False).exclude(groups__name="viewer")
        return queryset

    def get_serializer_class(self):
        if self.action == "create":
            return UserCreateSerializer
        if self.action in {"update", "partial_update"}:
            return UserAdminUpdateSerializer
        return UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "user": _serialized_user(user, request),
            "credentials": _credentials_for(user, serializer.generated_password),
        }, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(_serialized_user(user, request))

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.pk == request.user.pk:
            raise PermissionDenied("You cannot delete your own account.")
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"])
    def reset_password(self, request, pk=None):
        user = self.get_object()
        if user.auth_type != User.AuthType.LOCAL:
            return Response({"detail": "Only local users can reset password"}, status=400)

        new_password = generate_password()
        user.set_password(new_password)
        user.save()
        return Response({
            "detail": "Password reset",
            "user": _serialized_user(user, request),
            "credentials": _credentials_for(user, new_password),
        })

    @action(detail=True, methods=["put"])
    def avatar(self, request, pk=None):
        user = self.get_object()
        attachment_id = request.data.get("attachment_id")
        if not attachment_id:
            return Response({"detail": "attachment_id is required."}, status=400)
        error = _set_avatar_attachment(user, attachment_id)
        if error:
            return error
        return Response(_serialized_user(user, request))


class UserApiKeyViewSet(viewsets.ModelViewSet):
    serializer_class = UserApiKeySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserApiKey.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=["post"])
    def refresh(self, request, pk=None):
        api_key = self.get_object()
        api_key.refresh_key()
        api_key.save()
        return Response(self.get_serializer(api_key).data)
