from functools import lru_cache


@lru_cache(maxsize=1)
def get_llm_configs():
    from .models import LLMProviderConfig

    return [
        {
            "name": provider.name,
            "api_key": provider.api_key,
            "base_url": provider.base_url.rstrip("/"),
            "model": provider.model,
            "proxy": provider.proxy,
            "tags": provider.tags or [],
        }
        for provider in LLMProviderConfig.objects.filter(enabled=True).order_by("priority", "name", "created_at")
    ]


@lru_cache(maxsize=1)
def get_otx_config():
    from .models import ThreatIntelAlienVaultOTXConfig

    config = ThreatIntelAlienVaultOTXConfig.get_current()
    return {
        "enabled": config.enabled,
        "api_key": config.api_key,
        "base_url": config.base_url.rstrip("/"),
        "proxy": config.proxy,
    }


@lru_cache(maxsize=1)
def get_opencti_config():
    from .models import ThreatIntelOpenCTIConfig

    config = ThreatIntelOpenCTIConfig.get_current()
    return {
        "enabled": config.enabled,
        "url": config.url.rstrip("/"),
        "token": config.token,
        "ssl_verify": config.ssl_verify,
        "proxy": config.proxy,
    }


@lru_cache(maxsize=1)
def get_splunk_config():
    from .models import SiemSplunkConfig

    config = SiemSplunkConfig.get_current()
    return {
        "host": config.host,
        "port": config.port,
        "username": config.username,
        "password": config.password,
        "scheme": config.scheme,
        "verify": config.verify,
    }


@lru_cache(maxsize=1)
def get_elk_config():
    from .models import SiemElkConfig

    config = SiemElkConfig.get_current()
    return {
        "host": config.host.rstrip("/"),
        "api_key": config.api_key,
        "verify_certs": config.verify_certs,
        "process_alert_from_index_enabled": config.process_alert_from_index_enabled,
        "action_index": config.action_index,
        "action_poll_interval_seconds": config.action_poll_interval_seconds,
        "action_size": config.action_size,
    }


@lru_cache(maxsize=1)
def get_ldap_config():
    from .models import LdapConfig

    config = LdapConfig.get_current()
    return {
        "enabled": config.enabled,
        "server_uri": config.server_uri,
        "domain": config.domain,
        "bind_dn": config.bind_dn,
        "bind_password": config.bind_password,
        "user_search_base_dn": config.user_search_base_dn,
        "user_login_attr": config.user_login_attr,
    }


@lru_cache(maxsize=1)
def get_runtime_config():
    from .models import RuntimeConfig

    config = RuntimeConfig.get_current()
    return {
        "prompt_language": config.prompt_language,
        "stream_maxlen": config.stream_maxlen,
    }


def get_prompt_language():
    return get_runtime_config()["prompt_language"]


def get_stream_maxlen():
    try:
        return get_runtime_config()["stream_maxlen"]
    except Exception as exc:
        if exc.__class__.__name__ == "DatabaseOperationForbidden":
            return 10000
        raise


def invalidate(group=None):
    if group in {None, "llm"}:
        get_llm_configs.cache_clear()
    if group in {None, "threat_intel", "otx"}:
        get_otx_config.cache_clear()
    if group in {None, "threat_intel", "opencti"}:
        get_opencti_config.cache_clear()
    if group in {None, "siem", "splunk"}:
        get_splunk_config.cache_clear()
    if group in {None, "siem", "elk"}:
        get_elk_config.cache_clear()
    if group in {None, "ldap"}:
        get_ldap_config.cache_clear()
    if group in {None, "runtime"}:
        get_runtime_config.cache_clear()
