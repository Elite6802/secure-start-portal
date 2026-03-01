from django.db import models
from django.core.exceptions import ValidationError
from core.models import BaseModel
from accounts.models import Organization, User
from scans.models import ScanJob
from service_requests.models import ServiceRequest
from assets.models import Asset
from core.security import encrypt_secret, decrypt_secret


class CloudAccount(BaseModel):
    PROVIDER_AWS = "aws"
    PROVIDER_AZURE = "azure"
    PROVIDER_GCP = "gcp"

    PROVIDER_CHOICES = [
        (PROVIDER_AWS, "AWS"),
        (PROVIDER_AZURE, "Azure"),
        (PROVIDER_GCP, "GCP"),
    ]

    STATUS_ACTIVE = "active"
    STATUS_DISABLED = "disabled"
    STATUS_ERROR = "error"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_DISABLED, "Disabled"),
        (STATUS_ERROR, "Error"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="cloud_accounts")
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="cloud_accounts")
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    name = models.CharField(max_length=255)

    # AWS
    aws_account_id = models.CharField(max_length=32, blank=True)
    aws_role_arn = models.CharField(max_length=512, blank=True)
    aws_external_id = models.CharField(max_length=128, blank=True)

    # Azure
    azure_tenant_id = models.CharField(max_length=128, blank=True)
    azure_client_id = models.CharField(max_length=128, blank=True)
    azure_subscription_id = models.CharField(max_length=128, blank=True)
    _azure_client_secret = models.TextField(blank=True, db_column="azure_client_secret")

    # GCP
    gcp_project_id = models.CharField(max_length=128, blank=True)
    _gcp_service_account = models.TextField(blank=True, db_column="gcp_service_account")

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    last_validated_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    def __str__(self):
        return f"{self.name} ({self.get_provider_display()})"

    @property
    def azure_client_secret(self) -> str:
        if not self._azure_client_secret:
            return ""
        return decrypt_secret(self._azure_client_secret)

    @azure_client_secret.setter
    def azure_client_secret(self, value: str) -> None:
        self._azure_client_secret = encrypt_secret(value) if value else ""

    @property
    def gcp_service_account_json(self) -> str:
        if not self._gcp_service_account:
            return ""
        return decrypt_secret(self._gcp_service_account)

    @gcp_service_account_json.setter
    def gcp_service_account_json(self, value: str) -> None:
        self._gcp_service_account = encrypt_secret(value) if value else ""

    def clean(self):
        if self.provider == self.PROVIDER_AWS and not self.aws_role_arn:
            raise ValidationError({"aws_role_arn": "AWS role ARN is required for AWS cloud accounts."})
        if self.provider == self.PROVIDER_AZURE:
            missing = [f for f in ["azure_tenant_id", "azure_client_id", "azure_subscription_id"] if not getattr(self, f)]
            if missing:
                raise ValidationError({f: "Required for Azure cloud accounts." for f in missing})
        if self.provider == self.PROVIDER_GCP and not (self.gcp_project_id and self._gcp_service_account):
            raise ValidationError({"gcp_service_account_json": "GCP service account JSON is required."})


class CloudFinding(BaseModel):
    SEVERITY_CRITICAL = "critical"
    SEVERITY_HIGH = "high"
    SEVERITY_MODERATE = "moderate"
    SEVERITY_LOW = "low"

    SEVERITY_CHOICES = [
        (SEVERITY_CRITICAL, "Critical"),
        (SEVERITY_HIGH, "High"),
        (SEVERITY_MODERATE, "Moderate"),
        (SEVERITY_LOW, "Low"),
    ]

    STATUS_OPEN = "open"
    STATUS_RESOLVED = "resolved"

    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_RESOLVED, "Resolved"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="cloud_findings")
    cloud_account = models.ForeignKey(CloudAccount, on_delete=models.CASCADE, related_name="findings")
    asset = models.ForeignKey(Asset, on_delete=models.SET_NULL, null=True, blank=True, related_name="cloud_findings")
    scan_job = models.ForeignKey(ScanJob, on_delete=models.SET_NULL, null=True, blank=True, related_name="cloud_findings")
    service_request = models.ForeignKey(ServiceRequest, on_delete=models.SET_NULL, null=True, blank=True, related_name="cloud_findings")

    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default=SEVERITY_MODERATE)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN)
    resolved_at = models.DateTimeField(null=True, blank=True)
    description = models.TextField()
    remediation = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    compliance = models.JSONField(default=list, blank=True)
    cvss_vector = models.CharField(max_length=128, blank=True, default="")

    def __str__(self):
        return f"{self.title} ({self.severity})"
