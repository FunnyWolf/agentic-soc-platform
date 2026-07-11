from rest_framework.permissions import SAFE_METHODS, BasePermission

from apps.accounts.permissions import is_admin_user
from .models import SavedTableFilter


class CanUseSavedTableFilter(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return obj.visibility == SavedTableFilter.Visibility.SHARED or obj.owner_id == request.user.id
        return obj.owner_id == request.user.id or is_admin_user(request.user)
