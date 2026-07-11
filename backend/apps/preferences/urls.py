from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import SavedTableFilterViewSet, UserTablePreferenceView


router = DefaultRouter()
router.register("saved-table-filters", SavedTableFilterViewSet, basename="saved-table-filter")

urlpatterns = [
    path("user-table-preferences/<str:table_key>/", UserTablePreferenceView.as_view(), name="user-table-preference"),
    path("", include(router.urls)),
]
