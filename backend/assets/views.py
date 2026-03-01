from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from accounts.models import UserOrganization
from core.models import OrganizationQuerySetMixin
from core.permissions import OrganizationAccessPermission
from .models import Asset
from .serializers import AssetSerializer


class AssetViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD]
    organization_field = "organization"

    def get_queryset(self):
        queryset = self.filter_by_organization(Asset.objects.all(), self.request.user)
        return queryset
