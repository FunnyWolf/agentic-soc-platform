from django.db.models import Q
from rest_framework import permissions, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import SavedTableFilter, UserTablePreference
from .permissions import CanUseSavedTableFilter
from .serializers import SavedTableFilterSerializer, UserTablePreferenceSerializer


class UserTablePreferenceView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, table_key):
        instance = UserTablePreference.objects.filter(user=request.user, table_key=table_key).first()
        if not instance:
            return Response({
                "table_key": table_key,
                "page_size": None,
                "column_settings": None,
            })
        return Response(UserTablePreferenceSerializer(instance).data)

    def patch(self, request, table_key):
        serializer = UserTablePreferenceSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        instance, _ = UserTablePreference.objects.get_or_create(user=request.user, table_key=table_key)
        for field, value in serializer.validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return Response(UserTablePreferenceSerializer(instance).data)


class SavedTableFilterViewSet(viewsets.ModelViewSet):
    serializer_class = SavedTableFilterSerializer
    permission_classes = [permissions.IsAuthenticated, CanUseSavedTableFilter]
    pagination_class = None

    def get_queryset(self):
        queryset = SavedTableFilter.objects.select_related("owner").filter(
            Q(owner=self.request.user) | Q(visibility=SavedTableFilter.Visibility.SHARED)
        )
        table_key = self.request.query_params.get("table_key", "").strip()
        if table_key:
            queryset = queryset.filter(table_key=table_key)
        return queryset

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
