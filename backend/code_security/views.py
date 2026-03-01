from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from accounts.models import UserOrganization
from core.models import OrganizationQuerySetMixin
from core.permissions import OrganizationAccessPermission, requires_role
from core.cvss import CvssError, score_cvss3
from .models import CodeRepository, CodeFinding
from .serializers import CodeRepositorySerializer, CodeFindingSerializer


class CodeRepositoryViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = CodeRepositorySerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD, UserOrganization.ROLE_DEVELOPER]
    organization_field = "organization"

    def get_queryset(self):
        return self.filter_by_organization(CodeRepository.objects.all(), self.request.user)


class CodeFindingViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = CodeFindingSerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD, UserOrganization.ROLE_DEVELOPER]
    organization_field = "repository__organization"

    def get_queryset(self):
        queryset = self.filter_by_organization(CodeFinding.objects.all(), self.request.user).order_by("-created_at")
        service_request_id = self.request.query_params.get("service_request")
        if service_request_id:
            queryset = queryset.filter(service_request_id=service_request_id)
        scan_job_id = self.request.query_params.get("scan_job")
        if scan_job_id:
            queryset = queryset.filter(scan_job_id=scan_job_id)
        return queryset

    @action(detail=True, methods=["post"])
    @requires_role(UserOrganization.ROLE_SECURITY_LEAD)
    def resolve(self, request, pk=None):
        finding = self.get_object()
        if finding.status != CodeFinding.STATUS_RESOLVED:
            finding.status = CodeFinding.STATUS_RESOLVED
            finding.resolved_at = timezone.now()
            finding.save(update_fields=["status", "resolved_at"])
        serializer = self.get_serializer(finding)
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="set-cvss")
    @requires_role(UserOrganization.ROLE_SECURITY_LEAD)
    def set_cvss(self, request, pk=None):
        finding = self.get_object()
        vector = (request.data.get("cvss_vector") or "").strip()
        if not vector:
            finding.cvss_vector = ""
            finding.save(update_fields=["cvss_vector"])
            return Response(self.get_serializer(finding).data)
        try:
            score_cvss3(vector)
        except CvssError as exc:
            return Response({"detail": str(exc)}, status=400)
        finding.cvss_vector = vector
        finding.save(update_fields=["cvss_vector"])
        return Response(self.get_serializer(finding).data)
