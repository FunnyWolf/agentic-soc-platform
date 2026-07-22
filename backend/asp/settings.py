import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from botocore.config import Config
from dotenv import load_dotenv

from apps.common.logging import (
    VERBOSE_LOG_FORMAT,
)

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
CUSTOM_DIR = BASE_DIR / "custom"


def _env_int(name, default, *, minimum=1):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-key-change-in-prod-32-byte-minimum")
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")
ASP_WEB_TIMEOUT = _env_int("ASP_WEB_TIMEOUT", 210)
SYNC_OPERATION_TIMEOUT_SECONDS = max(1, ASP_WEB_TIMEOUT - 30)
CONFIG_TEST_TIMEOUT_SECONDS = 10

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third party
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",
    "drf_spectacular_sidecar",
    "corsheaders",
    "django_filters",
    "storages",
    "channels",
    # Local apps
    "apps.common",
    "apps.dashboard",
    "apps.settings",
    "apps.accounts",
    "apps.cases",
    "apps.alerts",
    "apps.artifacts",
    "apps.enrichments",
    "apps.playbooks",
    "apps.knowledge",
    "apps.comments",
    "apps.attachments",
    "apps.audit",
    "apps.inbox",
    "apps.preferences",
    "apps.realtime",
    "apps.webhook",
    "apps.agentic",
    "apps.agent_api",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "asp.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "asp.wsgi.application"
ASGI_APPLICATION = "asp.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "asp"),
        "USER": os.environ.get("POSTGRES_USER", "postgres"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", ""),
        "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": _env_int("POSTGRES_CONN_MAX_AGE", 0, minimum=0),
        "CONN_HEALTH_CHECKS": _env_bool("POSTGRES_CONN_HEALTH_CHECKS", True),
    }
}

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_DB = os.environ.get("REDIS_DB", "1")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")
REDIS_AUTH = f":{quote(REDIS_PASSWORD, safe='')}@" if REDIS_PASSWORD else ""
REDIS_URL = f"redis://{REDIS_AUTH}{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
CHANNEL_REDIS_SOCKET_TIMEOUT = int(os.environ.get("CHANNEL_REDIS_SOCKET_TIMEOUT", "10"))

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [{
                "address": REDIS_URL,
                "socket_timeout": CHANNEL_REDIS_SOCKET_TIMEOUT,
            }],
        },
    },
}

AUTH_USER_MODEL = "accounts.User"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "apps.accounts.authentication.ApiKeyAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_PAGINATION_CLASS": "apps.common.pagination.StandardResultsSetPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_SCHEMA_CLASS": "apps.common.openapi.AspAutoSchema",
    "EXCEPTION_HANDLER": "apps.common.exceptions.custom_exception_handler",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Agentic SOC Platform API",
    "DESCRIPTION": "HTTP API for Agentic SOC Platform. External automation integrations should prefer API keys.",
    "VERSION": "0.5.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "SIDECAR",
    "REDOC_DIST": "SIDECAR",
    "SWAGGER_UI_SETTINGS": {
        "deepLinking": True,
        "persistAuthorization": True,
    },
    "POSTPROCESSING_HOOKS": [
        "drf_spectacular.hooks.postprocess_schema_enums",
        "apps.common.openapi.postprocess_business_tags",
    ],
    "TAGS": [
        {"name": "Auth", "description": "Login, refresh token, profile, and current user operations."},
        {"name": "Users", "description": "User administration APIs."},
        {"name": "API Keys", "description": "Personal API key management APIs."},
        {"name": "Cases", "description": "Case investigation records."},
        {"name": "Alerts", "description": "Security alert records."},
        {"name": "Artifacts", "description": "Indicators, assets, and other related artifacts."},
        {"name": "Enrichments", "description": "Enrichment records and creation APIs."},
        {"name": "Playbooks", "description": "Playbook records and execution APIs."},
        {"name": "Knowledge", "description": "Knowledge base records."},
        {"name": "Comments", "description": "Record comment APIs."},
        {"name": "Attachments", "description": "Attachment upload, metadata, and download APIs."},
        {"name": "Audit", "description": "Audit log query APIs."},
        {"name": "Inbox", "description": "User inbox message APIs."},
        {"name": "Preferences", "description": "User table preference APIs."},
        {"name": "Settings", "description": "System configuration APIs."},
        {"name": "Custom", "description": "Custom module, playbook, and SIEM definition APIs."},
        {"name": "Dashboard", "description": "Dashboard summary APIs."},
        {"name": "Metadata", "description": "Resource metadata APIs."},
        {"name": "Webhooks", "description": "Inbound alert webhook APIs."},
        {"name": "Agent API", "description": "Versioned APIs for agent and CLI integrations."},
        {"name": "System", "description": "System health and utility APIs."},
    ],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=8),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
}

CORS_ALLOW_ALL_ORIGINS = DEBUG

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

STORAGES = {
    "default": {
        "BACKEND": "apps.attachments.storage.AttachmentS3Storage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

AWS_S3_ENDPOINT_URL = os.environ.get("RUSTFS_ENDPOINT_URL", "http://localhost:9000")
AWS_ACCESS_KEY_ID = os.environ.get("RUSTFS_ACCESS_KEY")
AWS_SECRET_ACCESS_KEY = os.environ.get("RUSTFS_SECRET_KEY")
AWS_STORAGE_BUCKET_NAME = os.environ.get("RUSTFS_BUCKET", "asp")
AWS_S3_REGION_NAME = os.environ.get("RUSTFS_REGION", "us-east-1")
AWS_S3_ADDRESSING_STYLE = "path"
AWS_S3_SIGNATURE_VERSION = "s3v4"
AWS_S3_CLIENT_CONFIG = Config(
    proxies={},
    s3={"addressing_style": AWS_S3_ADDRESSING_STYLE},
    signature_version=AWS_S3_SIGNATURE_VERSION,
)
AWS_S3_FILE_OVERWRITE = False
AWS_DEFAULT_ACL = None

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOG_LEVEL = os.environ.get("DJANGO_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("DJANGO_LOG_FORMAT", "text").lower()
LOG_FORMATTER = "json" if LOG_FORMAT == "json" else "verbose"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": VERBOSE_LOG_FORMAT,
        },
        "json": {
            "()": "apps.common.logging.JsonFormatter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": LOG_FORMATTER,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },
    "loggers": {
        "django": {
            "handlers": [],
            "level": os.environ.get("DJANGO_LOG_LEVEL_DJANGO", LOG_LEVEL).upper(),
            "propagate": True,
        },
        "django.request": {
            "handlers": [],
            "level": "WARNING",
            "propagate": True,
        },
        "rest_framework": {
            "handlers": [],
            "level": "WARNING",
            "propagate": True,
        },
    },
}
