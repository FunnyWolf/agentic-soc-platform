from django.urls import path, include

urlpatterns = [
    path("api/", include("apps.accounts.urls")),
    path("api/", include("apps.settings.urls")),
    path("api/", include("apps.common.urls")),
    path("api/", include("apps.dashboard.urls")),
    path("api/", include("apps.cases.urls")),
    path("api/", include("apps.alerts.urls")),
    path("api/", include("apps.artifacts.urls")),
    path("api/", include("apps.enrichments.urls")),
    path("api/", include("apps.playbooks.urls")),
    path("api/", include("apps.knowledge.urls")),
    path("api/", include("apps.comments.urls")),
    path("api/", include("apps.attachments.urls")),
    path("api/", include("apps.audit.urls")),
    path("api/", include("apps.inbox.urls")),
    path("api/", include("apps.preferences.urls")),
    path("api/", include("apps.webhook.urls")),
    path("api/agent/v1/", include("apps.agent_api.urls")),
]
