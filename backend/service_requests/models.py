from django.db import models
from django.core.exceptions import ValidationError
from core.models import BaseModel
from accounts.models import Organization, User, UserOrganization


class ServiceRequest(BaseModel):
    ROLE_EXECUTIVE = UserOrganization.ROLE_EXECUTIVE
    ROLE_DEVELOPER = UserOrganization.ROLE_DEVELOPER
    ROLE_SECURITY_LEAD = UserOrganization.ROLE_SECURITY_LEAD

    REQUESTED_ROLE_CHOICES = [
        (ROLE_EXECUTIVE, "Executive"),
        (ROLE_DEVELOPER, "Developer"),
        (ROLE_SECURITY_LEAD, "Security Lead"),
    ]

    SERVICE_CODE_SECRETS = "CODE_SECRETS_SCAN"
    SERVICE_DEPENDENCY = "DEPENDENCY_VULN_SCAN"
    SERVICE_CODE_COMPLIANCE = "CODE_COMPLIANCE_SCAN"
    SERVICE_CODE_COMPLIANCE_PYTHON = "CODE_COMPLIANCE_PYTHON"
    SERVICE_CODE_COMPLIANCE_HTML = "CODE_COMPLIANCE_HTML"
    SERVICE_CODE_COMPLIANCE_CSS = "CODE_COMPLIANCE_CSS"
    SERVICE_CODE_COMPLIANCE_JAVASCRIPT = "CODE_COMPLIANCE_JAVASCRIPT"
    SERVICE_CODE_COMPLIANCE_REACT = "CODE_COMPLIANCE_REACT"
    SERVICE_NETWORK = "NETWORK_CONFIGURATION_SCAN"
    SERVICE_WEB = "WEB_EXPOSURE_SCAN"
    SERVICE_API = "API_SECURITY_SCAN"
    SERVICE_INFRA = "INFRASTRUCTURE_HARDENING_SCAN"
    SERVICE_CLOUD = "CLOUD_POSTURE_SCAN"

    SERVICE_TYPE_CHOICES = [
        (SERVICE_CODE_SECRETS, "Code Secrets Scan"),
        (SERVICE_DEPENDENCY, "Dependency Vulnerability Scan"),
        (SERVICE_CODE_COMPLIANCE, "Code Standards Compliance (Full)"),
        (SERVICE_CODE_COMPLIANCE_PYTHON, "Python PEP8 Compliance"),
        (SERVICE_CODE_COMPLIANCE_HTML, "HTML Standards Compliance"),
        (SERVICE_CODE_COMPLIANCE_CSS, "CSS Standards Compliance"),
        (SERVICE_CODE_COMPLIANCE_JAVASCRIPT, "JavaScript Standards Compliance"),
        (SERVICE_CODE_COMPLIANCE_REACT, "React Standards Compliance"),
        (SERVICE_NETWORK, "Network Configuration Scan"),
        (SERVICE_WEB, "Web Exposure Scan"),
        (SERVICE_API, "API Security Scan"),
        (SERVICE_INFRA, "Infrastructure Hardening Scan"),
        (SERVICE_CLOUD, "Cloud Posture Scan"),
    ]

    SCOPE_REPOSITORY = "repository"
    SCOPE_ASSET = "asset"
    SCOPE_IP_CIDR = "ip_cidr"
    SCOPE_DOMAIN = "domain"
    SCOPE_CLOUD = "cloud"

    SCOPE_CHOICES = [
        (SCOPE_REPOSITORY, "Repository"),
        (SCOPE_ASSET, "Asset"),
        (SCOPE_IP_CIDR, "IP / CIDR"),
        (SCOPE_DOMAIN, "Domain / URL"),
        (SCOPE_CLOUD, "Cloud Account"),
    ]

    STATUS_PENDING = "PENDING"
    STATUS_APPROVED = "APPROVED"
    STATUS_REJECTED = "REJECTED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_FAILED = "FAILED"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
        (STATUS_RUNNING, "Running"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="service_requests")
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="service_requests")
    requested_role = models.CharField(max_length=40, choices=REQUESTED_ROLE_CHOICES)
    service_type = models.CharField(max_length=60, choices=SERVICE_TYPE_CHOICES)
    scope = models.CharField(max_length=40, choices=SCOPE_CHOICES, blank=True)
    repository_url = models.URLField(blank=True)
    asset = models.ForeignKey("assets.Asset", on_delete=models.SET_NULL, null=True, blank=True, related_name="service_requests")
    cloud_account = models.ForeignKey("cloud_security.CloudAccount", on_delete=models.SET_NULL, null=True, blank=True, related_name="service_requests")
    ip_cidr = models.CharField(max_length=64, blank=True)
    domain_url = models.CharField(max_length=255, blank=True)
    justification = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="approved_service_requests")
    linked_scan_job = models.ForeignKey(
        "scans.ScanJob",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="service_requests",
    )

    # High-risk validation controls (disabled by default).
    # These are only meaningful for WEB_EXPOSURE_SCAN / API_SECURITY_SCAN and are guarded at runtime.
    ownership_confirmed = models.BooleanField(default=False)
    high_risk_ssrf = models.BooleanField(default=False)

    # Stronger authorization declaration for high-risk scans (e.g., internal ticket / signed approval / change request).
    authorization_reference = models.CharField(max_length=128, blank=True)
    authorization_notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.service_type} ({self.organization})"

    def save(self, *args, **kwargs):
        if self.pk:
            previous = ServiceRequest.objects.filter(pk=self.pk).first()
            if previous and previous.status in {
                self.STATUS_APPROVED,
                self.STATUS_REJECTED,
                self.STATUS_RUNNING,
                self.STATUS_COMPLETED,
                self.STATUS_FAILED,
            }:
                immutable_fields = [
                    "service_type",
                    "scope",
                    "repository_url",
                    "asset_id",
                    "ip_cidr",
                    "domain_url",
                    "justification",
                    "requested_role",
                    "requested_by_id",
                    "organization_id",
                    "ownership_confirmed",
                    "high_risk_ssrf",
                    "authorization_reference",
                    "authorization_notes",
                ]
                for field in immutable_fields:
                    if getattr(previous, field) != getattr(self, field):
                        raise ValidationError("Service requests are immutable after approval.")
        return super().save(*args, **kwargs)
