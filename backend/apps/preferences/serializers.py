from rest_framework import serializers

from apps.accounts.permissions import is_admin_user
from .models import SavedTableFilter, UserTablePreference


PAGE_SIZE_OPTIONS = {20, 50, 100}


def _validate_string_array(value, field_name):
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise serializers.ValidationError(f"{field_name} must be an array of strings.")


def validate_column_settings(value):
    if value is None:
        return value
    if not isinstance(value, dict):
        raise serializers.ValidationError("column_settings must be an object.")
    allowed_keys = {"visible", "order", "fixedLeft"}
    unknown_keys = set(value.keys()) - allowed_keys
    if unknown_keys:
        raise serializers.ValidationError("column_settings contains unsupported keys.")
    _validate_string_array(value.get("visible", []), "column_settings.visible")
    _validate_string_array(value.get("order", []), "column_settings.order")
    _validate_string_array(value.get("fixedLeft", []), "column_settings.fixedLeft")
    return {
        "visible": value.get("visible", []),
        "order": value.get("order", []),
        "fixedLeft": value.get("fixedLeft", []),
    }


def validate_filter_state(value):
    if not isinstance(value, dict):
        raise serializers.ValidationError("state must be an object.")
    quick = value.get("quick", {})
    advanced = value.get("advanced", [])
    if not isinstance(quick, dict):
        raise serializers.ValidationError("state.quick must be an object.")
    if not isinstance(advanced, list):
        raise serializers.ValidationError("state.advanced must be an array.")
    return {
        "quick": quick,
        "advanced": advanced,
    }


class UserTablePreferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTablePreference
        fields = ("table_key", "page_size", "column_settings", "created_at", "updated_at")
        read_only_fields = ("table_key", "created_at", "updated_at")

    def validate_page_size(self, value):
        if value is not None and value not in PAGE_SIZE_OPTIONS:
            raise serializers.ValidationError("page_size must be one of 20, 50, or 100.")
        return value

    def validate_column_settings(self, value):
        return validate_column_settings(value)


class SavedTableFilterSerializer(serializers.ModelSerializer):
    owner_id = serializers.IntegerField(source="owner.id", read_only=True)
    owner_username = serializers.CharField(source="owner.username", read_only=True)
    can_edit = serializers.SerializerMethodField()

    class Meta:
        model = SavedTableFilter
        fields = (
            "id",
            "table_key",
            "name",
            "state",
            "visibility",
            "owner_id",
            "owner_username",
            "can_edit",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "owner_id", "owner_username", "can_edit", "created_at", "updated_at")

    def get_can_edit(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        return bool(user and user.is_authenticated and (obj.owner_id == user.id or is_admin_user(user)))

    def validate_state(self, value):
        return validate_filter_state(value)

    def validate_table_key(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("table_key is required.")
        return value

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("name is required.")
        return value
