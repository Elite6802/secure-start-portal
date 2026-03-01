from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from accounts.models import UserOrganization
from core.models import OrganizationQuerySetMixin
from core.permissions import OrganizationAccessPermission
from .models import Incident
from .serializers import IncidentSerializer


class IncidentViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = IncidentSerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD, UserOrganization.ROLE_EXECUTIVE]
    organization_field = "organization"

    def get_queryset(self):
        return self.filter_by_organization(Incident.objects.all(), self.request.user)
