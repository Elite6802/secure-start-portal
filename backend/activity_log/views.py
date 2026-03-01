from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from accounts.models import UserOrganization
from core.models import OrganizationQuerySetMixin
from core.permissions import OrganizationAccessPermission
from .models import ActivityLog
from .serializers import ActivityLogSerializer


class ActivityLogViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = ActivityLogSerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD]
    organization_field = "organization"

    def get_queryset(self):
        return self.filter_by_organization(ActivityLog.objects.all(), self.request.user)
