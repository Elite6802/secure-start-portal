from rest_framework import viewsets, mixins
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError, PermissionDenied
from django.utils import timezone
from core.models import OrganizationQuerySetMixin
from core.permissions import get_user_role, RolePermissionMixin
from core.cvss import CvssError, score_cvss3
from accounts.models import UserOrganization
from .models import CloudAccount, CloudFinding
from .serializers import CloudAccountSerializer, CloudAccountSecretsSerializer, CloudFindingSerializer


class CloudAccountViewSet(
    RolePermissionMixin,
    OrganizationQuerySetMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = CloudAccountSerializer
    permission_classes = [IsAuthenticated]
    organization_field = "organization"
    role_action_map = {
        "list": [UserOrganization.ROLE_SECURITY_LEAD],
        "create": [UserOrganization.ROLE_SECURITY_LEAD],
        "update": [UserOrganization.ROLE_SECURITY_LEAD],
        "partial_update": [UserOrganization.ROLE_SECURITY_LEAD],
    }

    def get_queryset(self):
        base = CloudAccount.objects.all().order_by("-created_at")
        return self.filter_by_organization(base, self.request.user)

    def perform_create(self, serializer):
        user = self.request.user
        org = serializer.validated_data.get("organization")
        if user.is_staff or user.is_superuser:
            if not org:
                raise ValidationError({"organization": "Organization is required for cloud accounts."})
        else:
            org = getattr(user, "organization", None)
            if not org:
                raise ValidationError({"organization": "No organization assigned to this user."})
        role = get_user_role(user)
        if not role and not (user.is_staff or user.is_superuser):
            raise PermissionDenied("No role assigned to this user.")
        serializer.save(organization=org, created_by=user)

    @action(detail=True, methods=["post"])
    def set_secrets(self, request, pk=None):
        account = self.get_object()
        serializer = CloudAccountSecretsSerializer(account, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        if "azure_client_secret" in serializer.validated_data:
            account.azure_client_secret = serializer.validated_data["azure_client_secret"]
        if "gcp_service_account_json" in serializer.validated_data:
            account.gcp_service_account_json = serializer.validated_data["gcp_service_account_json"]
        account.last_validated_at = timezone.now()
        account.last_error = ""
        account.save(update_fields=["_azure_client_secret", "_gcp_service_account", "last_validated_at", "last_error"])
        return CloudAccountSerializer(account).data


class CloudFindingViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = CloudFindingSerializer
    permission_classes = [IsAuthenticated]
    organization_field = "organization"

    def get_queryset(self):
        base = CloudFinding.objects.all().select_related("cloud_account", "asset", "scan_job")
        return self.filter_by_organization(base, self.request.user)

    @action(detail=True, methods=["post"], url_path="set-cvss")
    def set_cvss(self, request, pk=None):
        user = request.user
        role = get_user_role(user)
        if not (user.is_staff or user.is_superuser or role == UserOrganization.ROLE_SECURITY_LEAD):
            raise PermissionDenied("Only security leads can set CVSS vectors.")
        finding = self.get_object()
        vector = (request.data.get("cvss_vector") or "").strip()
        if not vector:
            finding.cvss_vector = ""
            finding.save(update_fields=["cvss_vector"])
            return CloudFindingSerializer(finding).data
        try:
            score_cvss3(vector)
        except CvssError as exc:
            raise ValidationError({"cvss_vector": str(exc)})
        finding.cvss_vector = vector
        finding.save(update_fields=["cvss_vector"])
        return CloudFindingSerializer(finding).data
