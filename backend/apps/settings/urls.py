from django.urls import include, path
from rest_framework.routers import DefaultRouter

from apps.audit.views import AdminAuditLogViewSet
from .custom_views import (
    CustomDefinitionsModuleView,
    CustomDefinitionsPlaybookView,
    CustomDefinitionsSiemView,
    CustomModuleStreamMessageView,
    CustomModuleStreamMessagesView,
)
from .views import (
    LLMProviderConfigViewSet,
    LdapConfigView,
    LdapTestView,
    RuntimeConfigView,
    SiemElkConfigView,
    SiemElkTestView,
    SiemSplunkConfigView,
    SiemSplunkTestView,
    ThreatIntelAlienVaultOTXConfigView,
    ThreatIntelAlienVaultOTXTestView,
    ThreatIntelOpenCTIConfigView,
    ThreatIntelOpenCTITestView,
)


router = DefaultRouter()
router.register("llm-providers", LLMProviderConfigViewSet, basename="llm-provider")
router.register("audit-logs", AdminAuditLogViewSet, basename="settings-audit-log")

urlpatterns = [
    path("settings/threat-intel/otx/", ThreatIntelAlienVaultOTXConfigView.as_view(), name="threat-intel-otx-config"),
    path("settings/threat-intel/otx/test/", ThreatIntelAlienVaultOTXTestView.as_view(), name="threat-intel-otx-test"),
    path("settings/threat-intel/opencti/", ThreatIntelOpenCTIConfigView.as_view(), name="threat-intel-opencti-config"),
    path("settings/threat-intel/opencti/test/", ThreatIntelOpenCTITestView.as_view(), name="threat-intel-opencti-test"),
    path("settings/siem/splunk/", SiemSplunkConfigView.as_view(), name="siem-splunk-config"),
    path("settings/siem/splunk/test/", SiemSplunkTestView.as_view(), name="siem-splunk-test"),
    path("settings/siem/elk/", SiemElkConfigView.as_view(), name="siem-elk-config"),
    path("settings/siem/elk/test/", SiemElkTestView.as_view(), name="siem-elk-test"),
    path("settings/ldap/", LdapConfigView.as_view(), name="ldap-config"),
    path("settings/ldap/test/", LdapTestView.as_view(), name="ldap-test"),
    path("settings/runtime/", RuntimeConfigView.as_view(), name="runtime-config"),
    path("custom/modules/", CustomDefinitionsModuleView.as_view(), name="custom-definitions-modules"),
    path("custom/modules/stream/messages/", CustomModuleStreamMessagesView.as_view(), name="custom-module-stream-messages"),
    path("custom/modules/stream/message/", CustomModuleStreamMessageView.as_view(), name="custom-module-stream-message"),
    path("custom/playbooks/", CustomDefinitionsPlaybookView.as_view(), name="custom-definitions-playbooks"),
    path("custom/siem/", CustomDefinitionsSiemView.as_view(), name="custom-definitions-siem"),
    path("settings/", include(router.urls)),
]
