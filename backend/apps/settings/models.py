import uuid

from django.db import models


class LLMProviderConfig(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    base_url = models.URLField(max_length=500)
    model = models.CharField(max_length=200)
    api_key = models.TextField(blank=True, default="")
    proxy = models.CharField(max_length=500, blank=True, default="")
    tags = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_llm_provider_configs"
        ordering = ["priority", "name", "created_at"]

    def __str__(self):
        return self.name


class ThreatIntelAlienVaultOTXConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    api_key = models.TextField(blank=True, default="")
    base_url = models.URLField(max_length=500, default="https://otx.alienvault.com/api/v1")
    proxy = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_ti_alienvault_otx_config"

    def __str__(self):
        return "AlienVault OTX"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class ThreatIntelOpenCTIConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    url = models.URLField(max_length=500, default="http://localhost:8080")
    token = models.TextField(blank=True, default="")
    ssl_verify = models.BooleanField(default=False)
    proxy = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_ti_opencti_config"

    def __str__(self):
        return "OpenCTI"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class SiemSplunkConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    host = models.CharField(max_length=255, blank=True, default="")
    port = models.PositiveIntegerField(default=8089)
    username = models.CharField(max_length=255, blank=True, default="")
    password = models.TextField(blank=True, default="")
    scheme = models.CharField(max_length=10, default="https")
    verify = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_siem_splunk_config"

    def __str__(self):
        return "Splunk"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class SiemElkConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    host = models.URLField(max_length=500, blank=True, default="")
    api_key = models.TextField(blank=True, default="")
    verify_certs = models.BooleanField(default=False)
    process_alert_from_index_enabled = models.BooleanField(default=False)
    action_index = models.CharField(max_length=255, blank=True, default="siem-alert")
    action_poll_interval_seconds = models.PositiveIntegerField(default=60)
    action_size = models.PositiveIntegerField(default=1000)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_siem_elk_config"

    def __str__(self):
        return "ELK"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class LdapConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    server_uri = models.CharField(max_length=500, blank=True, default="")
    domain = models.CharField(max_length=255, blank=True, default="")
    bind_dn = models.CharField(max_length=500, blank=True, default="")
    bind_password = models.TextField(blank=True, default="")
    user_search_base_dn = models.CharField(max_length=500, blank=True, default="")
    user_login_attr = models.CharField(max_length=100, default="uid")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_ldap_config"

    def __str__(self):
        return "LDAP"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class RuntimeConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    prompt_language = models.CharField(max_length=10, default="en")
    stream_maxlen = models.PositiveIntegerField(default=10000)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_runtime_config"

    def __str__(self):
        return "Runtime"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance
