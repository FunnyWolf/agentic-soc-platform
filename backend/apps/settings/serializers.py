from rest_framework import serializers

from .models import (
    LdapConfig,
    LLMProviderConfig,
    RuntimeConfig,
    SiemElkConfig,
    SiemSplunkConfig,
    ThreatIntelAlienVaultOTXConfig,
    ThreatIntelOpenCTIConfig,
)


class LLMProviderConfigSerializer(serializers.ModelSerializer):
    api_key_configured = serializers.SerializerMethodField()

    class Meta:
        model = LLMProviderConfig
        fields = (
            "id",
            "name",
            "base_url",
            "model",
            "api_key",
            "api_key_configured",
            "proxy",
            "tags",
            "enabled",
            "priority",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "api_key_configured", "created_at", "updated_at")
        extra_kwargs = {
            "api_key": {"required": False, "allow_blank": True, "trim_whitespace": False},
            "proxy": {"required": False, "allow_blank": True},
            "tags": {"required": False},
        }

    def get_api_key_configured(self, obj):
        return bool(obj.api_key)

    def validate_tags(self, value):
        if value in (None, ""):
            return []
        if not isinstance(value, list):
            raise serializers.ValidationError("Tags must be a list.")

        tags = []
        for item in value:
            tag = str(item).strip()
            if tag and tag not in tags:
                tags.append(tag)
        return tags

    def validate(self, attrs):
        attrs = super().validate(attrs)
        tags = attrs.get("tags")
        if tags is None and self.instance is not None:
            tags = self.instance.tags
        if not tags:
            raise serializers.ValidationError({"tags": "Select at least one tag."})
        return attrs

    def validate_proxy(self, value):
        proxy = (value or "").strip()
        if proxy and not proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
            raise serializers.ValidationError("Proxy must start with http://, https://, socks4://, or socks5://.")
        return proxy

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not self.context.get("reveal_secrets"):
            data["api_key"] = ""
        return data


class ThreatIntelAlienVaultOTXConfigSerializer(serializers.ModelSerializer):
    api_key_configured = serializers.SerializerMethodField()

    class Meta:
        model = ThreatIntelAlienVaultOTXConfig
        fields = (
            "enabled",
            "api_key",
            "api_key_configured",
            "base_url",
            "proxy",
            "updated_at",
        )
        read_only_fields = ("api_key_configured", "updated_at")
        extra_kwargs = {
            "api_key": {"required": True, "allow_blank": False, "trim_whitespace": False},
            "proxy": {"required": False, "allow_blank": True},
        }

    def get_api_key_configured(self, obj):
        return bool(obj.api_key)

    def validate_proxy(self, value):
        proxy = (value or "").strip()
        if proxy and not proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
            raise serializers.ValidationError("Proxy must start with http://, https://, socks4://, or socks5://.")
        return proxy

    def validate(self, attrs):
        attrs = super().validate(attrs)
        api_key = attrs.get("api_key")
        if api_key is None and self.instance is not None:
            api_key = self.instance.api_key
        if not str(api_key or "").strip():
            raise serializers.ValidationError({"api_key": "API key is required."})
        return attrs

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not self.context.get("reveal_secrets"):
            data["api_key"] = ""
        return data


class ThreatIntelOpenCTIConfigSerializer(serializers.ModelSerializer):
    token_configured = serializers.SerializerMethodField()

    class Meta:
        model = ThreatIntelOpenCTIConfig
        fields = (
            "enabled",
            "url",
            "token",
            "token_configured",
            "ssl_verify",
            "proxy",
            "updated_at",
        )
        read_only_fields = ("token_configured", "updated_at")
        extra_kwargs = {
            "url": {"required": True, "allow_blank": False},
            "token": {"required": True, "allow_blank": False, "trim_whitespace": False},
            "proxy": {"required": False, "allow_blank": True},
        }

    def get_token_configured(self, obj):
        return bool(obj.token)

    def validate_proxy(self, value):
        proxy = (value or "").strip()
        if proxy and not proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
            raise serializers.ValidationError("Proxy must start with http://, https://, socks4://, or socks5://.")
        return proxy

    def validate(self, attrs):
        attrs = super().validate(attrs)
        token = attrs.get("token")
        if token is None and self.instance is not None:
            token = self.instance.token
        if not str(token or "").strip():
            raise serializers.ValidationError({"token": "API token is required."})
        return attrs

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not self.context.get("reveal_secrets"):
            data["token"] = ""
        return data


class SiemSplunkConfigSerializer(serializers.ModelSerializer):
    password_configured = serializers.SerializerMethodField()

    class Meta:
        model = SiemSplunkConfig
        fields = (
            "host",
            "port",
            "username",
            "password",
            "password_configured",
            "scheme",
            "verify",
            "updated_at",
        )
        read_only_fields = ("password_configured", "updated_at")
        extra_kwargs = {
            "host": {"required": True, "allow_blank": False},
            "username": {"required": True, "allow_blank": False},
            "password": {"required": True, "allow_blank": False, "trim_whitespace": False},
        }

    def get_password_configured(self, obj):
        return bool(obj.password)

    def validate_port(self, value):
        if value <= 0 or value > 65535:
            raise serializers.ValidationError("Port must be between 1 and 65535.")
        return value

    def validate_scheme(self, value):
        scheme = (value or "").strip().lower()
        if scheme not in {"http", "https"}:
            raise serializers.ValidationError("Scheme must be http or https.")
        return scheme

    def validate(self, attrs):
        attrs = super().validate(attrs)
        for field in ("host", "username", "password"):
            value = attrs.get(field)
            if value is None and self.instance is not None:
                value = getattr(self.instance, field)
            if not str(value or "").strip():
                raise serializers.ValidationError({field: f"{field.replace('_', ' ').title()} is required."})
        return attrs

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not self.context.get("reveal_secrets"):
            data["password"] = ""
        return data


class SiemElkConfigSerializer(serializers.ModelSerializer):
    api_key_configured = serializers.SerializerMethodField()

    class Meta:
        model = SiemElkConfig
        fields = (
            "host",
            "api_key",
            "api_key_configured",
            "verify_certs",
            "process_alert_from_index_enabled",
            "action_index",
            "action_poll_interval_seconds",
            "action_size",
            "updated_at",
        )
        read_only_fields = ("api_key_configured", "updated_at")
        extra_kwargs = {
            "host": {"required": True, "allow_blank": False},
            "api_key": {"required": True, "allow_blank": False, "trim_whitespace": False},
            "action_index": {"required": False, "allow_blank": True},
            "action_poll_interval_seconds": {"required": False, "allow_null": True},
            "action_size": {"required": False, "allow_null": True},
        }

    def get_api_key_configured(self, obj):
        return bool(obj.api_key)

    def validate_action_poll_interval_seconds(self, value):
        if value is None:
            return value
        if value <= 0:
            raise serializers.ValidationError("Action poll interval must be greater than 0.")
        return value

    def validate_action_size(self, value):
        if value is None:
            return value
        if value <= 0:
            raise serializers.ValidationError("Action size must be greater than 0.")
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        for field in ("host", "api_key"):
            value = attrs.get(field)
            if value is None and self.instance is not None:
                value = getattr(self.instance, field)
            if not str(value or "").strip():
                raise serializers.ValidationError({field: f"{field.replace('_', ' ').title()} is required."})
        process_enabled = attrs.get("process_alert_from_index_enabled")
        if process_enabled is None and self.instance is not None:
            process_enabled = self.instance.process_alert_from_index_enabled
        if process_enabled:
            action_index = attrs.get("action_index")
            if action_index is None and self.instance is not None:
                action_index = self.instance.action_index
            if not str(action_index or "").strip():
                raise serializers.ValidationError({"action_index": "Action index is required when alert processing is enabled."})
            poll_interval = attrs.get("action_poll_interval_seconds")
            if "action_poll_interval_seconds" in attrs and poll_interval is None:
                raise serializers.ValidationError({
                    "action_poll_interval_seconds": "Action poll interval is required when alert processing is enabled."
                })
            if poll_interval is None and self.instance is not None:
                poll_interval = self.instance.action_poll_interval_seconds
            if poll_interval is None:
                raise serializers.ValidationError({
                    "action_poll_interval_seconds": "Action poll interval is required when alert processing is enabled."
                })
            action_size = attrs.get("action_size")
            if "action_size" in attrs and action_size is None:
                raise serializers.ValidationError({
                    "action_size": "Action size is required when alert processing is enabled."
                })
            if action_size is None and self.instance is not None:
                action_size = self.instance.action_size
            if action_size is None:
                raise serializers.ValidationError({"action_size": "Action size is required when alert processing is enabled."})
        elif attrs.get("action_poll_interval_seconds") is None:
            attrs.pop("action_poll_interval_seconds", None)
        if not process_enabled and attrs.get("action_size") is None:
            attrs.pop("action_size", None)
        return attrs

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not self.context.get("reveal_secrets"):
            data["api_key"] = ""
        return data


class LdapConfigSerializer(serializers.ModelSerializer):
    bind_password_configured = serializers.SerializerMethodField()

    class Meta:
        model = LdapConfig
        fields = (
            "enabled",
            "server_uri",
            "domain",
            "bind_dn",
            "bind_password",
            "bind_password_configured",
            "user_search_base_dn",
            "user_login_attr",
            "updated_at",
        )
        read_only_fields = ("bind_password_configured", "updated_at")
        extra_kwargs = {
            "server_uri": {"required": False, "allow_blank": True},
            "domain": {"required": False, "allow_blank": True},
            "bind_dn": {"required": False, "allow_blank": True},
            "bind_password": {"required": False, "allow_blank": True, "trim_whitespace": False},
            "user_search_base_dn": {"required": False, "allow_blank": True},
            "user_login_attr": {"required": False, "allow_blank": True},
        }

    def get_bind_password_configured(self, obj):
        return bool(obj.bind_password)

    def validate_server_uri(self, value):
        server_uri = (value or "").strip()
        if server_uri and not server_uri.startswith(("ldap://", "ldaps://")):
            raise serializers.ValidationError("Server URI must start with ldap:// or ldaps://.")
        return server_uri

    def validate(self, attrs):
        attrs = super().validate(attrs)
        enabled = attrs.get("enabled")
        if enabled is None and self.instance is not None:
            enabled = self.instance.enabled

        server_uri = attrs.get("server_uri")
        if server_uri is None and self.instance is not None:
            server_uri = self.instance.server_uri
        if enabled and not str(server_uri or "").strip():
            raise serializers.ValidationError({"server_uri": "Server URI is required when LDAP is enabled."})

        bind_dn = attrs.get("bind_dn")
        if bind_dn is None and self.instance is not None:
            bind_dn = self.instance.bind_dn
        bind_password = attrs.get("bind_password")
        if bind_password is None and self.instance is not None:
            bind_password = self.instance.bind_password
        if str(bind_dn or "").strip() and not str(bind_password or "").strip():
            raise serializers.ValidationError({"bind_password": "Bind password is required when bind DN is configured."})

        user_login_attr = attrs.get("user_login_attr")
        if user_login_attr is None and self.instance is not None:
            user_login_attr = self.instance.user_login_attr
        if not str(user_login_attr or "").strip():
            raise serializers.ValidationError({"user_login_attr": "User login attribute is required."})
        return attrs

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not self.context.get("reveal_secrets"):
            data["bind_password"] = ""
        return data


class RuntimeConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuntimeConfig
        fields = (
            "prompt_language",
            "stream_maxlen",
            "updated_at",
        )
        read_only_fields = ("updated_at",)

    def validate_prompt_language(self, value):
        language = (value or "").strip().lower()
        if language not in {"en", "zh"}:
            raise serializers.ValidationError("Prompt language must be en or zh.")
        return language

    def validate_stream_maxlen(self, value):
        if value <= 0:
            raise serializers.ValidationError("Stream maxlen must be greater than 0.")
        return value
