from django.db import models
from django.db.models import JSONField
from core.models import BaseModel
from accounts.models import Organization
from assets.models import Asset


class NetworkAsset(BaseModel):
    TYPE_INTERNAL = "internal"
    TYPE_EXTERNAL = "external"

    NETWORK_TYPE_CHOICES = [
        (TYPE_INTERNAL, "Internal"),
        (TYPE_EXTERNAL, "External"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="network_assets")
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="network_assets")
    network_type = models.CharField(max_length=20, choices=NETWORK_TYPE_CHOICES, default=TYPE_INTERNAL)

    def __str__(self):
        return f"{self.asset.name} ({self.network_type})"


class NetworkFinding(BaseModel):
    TYPE_EXPOSED_SERVICE = "exposed_service"
    TYPE_SEGMENTATION_RISK = "segmentation_risk"
    TYPE_MISCONFIGURATION = "misconfiguration"
    TYPE_ACTIVE_VALIDATION = "active_validation"

    FINDING_TYPE_CHOICES = [
        (TYPE_EXPOSED_SERVICE, "Exposed Service"),
        (TYPE_SEGMENTATION_RISK, "Segmentation Risk"),
        (TYPE_MISCONFIGURATION, "Misconfiguration"),
        (TYPE_ACTIVE_VALIDATION, "Active Security Validation"),
    ]

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

    network_asset = models.ForeignKey(NetworkAsset, on_delete=models.CASCADE, related_name="findings")
    finding_type = models.CharField(max_length=50, choices=FINDING_TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    resolved_at = models.DateTimeField(null=True, blank=True)
    confidence_score = models.PositiveSmallIntegerField(null=True, blank=True)
    summary = models.CharField(max_length=255)
    recommendation = models.TextField(blank=True)
    rationale = models.TextField(blank=True)
    evidence = JSONField(default=dict, blank=True)
    cvss_vector = models.CharField(max_length=128, blank=True, default="")
    scan_job = models.ForeignKey(
        "scans.ScanJob",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="network_findings",
    )
    service_request = models.ForeignKey(
        "service_requests.ServiceRequest",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="network_findings",
    )

    def __str__(self):
        return self.summary
