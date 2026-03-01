from django.db import models
from core.models import BaseModel
from accounts.models import Organization


class Asset(BaseModel):
    TYPE_DOMAIN = "domain"
    TYPE_WEB_APP = "web_app"
    TYPE_API = "api"
    TYPE_CLOUD_RESOURCE = "cloud_resource"
    TYPE_NETWORK_SEGMENT = "network_segment"
    TYPE_IP_RANGE = "ip_range"
    TYPE_CODE_REPOSITORY = "code_repository"

    ASSET_TYPE_CHOICES = [
        (TYPE_DOMAIN, "Domain"),
        (TYPE_WEB_APP, "Web Application"),
        (TYPE_API, "API"),
        (TYPE_CLOUD_RESOURCE, "Cloud Resource"),
        (TYPE_NETWORK_SEGMENT, "Network Segment"),
        (TYPE_IP_RANGE, "IP Range"),
        (TYPE_CODE_REPOSITORY, "Code Repository"),
    ]

    RISK_CRITICAL = "critical"
    RISK_MODERATE = "moderate"
    RISK_LOW = "low"

    RISK_LEVEL_CHOICES = [
        (RISK_CRITICAL, "Critical"),
        (RISK_MODERATE, "Moderate"),
        (RISK_LOW, "Low"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="assets")
    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=50, choices=ASSET_TYPE_CHOICES)
    identifier = models.CharField(max_length=512)
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES, default=RISK_LOW)
    last_scanned_at = models.DateTimeField(null=True, blank=True)

    # Ownership + tagging to support triage workflows (fix-by-owner boards, routing, SLAs).
    owner_team = models.CharField(max_length=120, blank=True)
    owner_contact = models.CharField(max_length=255, blank=True)
    tags = models.JSONField(default=list, blank=True)

    # Authorization controls for higher-risk validation modes (e.g., allowlisted internal SSRF validation).
    # This is an additional guardrail on top of org policy + per-request attestation.
    high_risk_ssrf_authorized = models.BooleanField(default=False)
    high_risk_ssrf_authorization_reference = models.CharField(max_length=128, blank=True)
    high_risk_ssrf_authorization_notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.name} ({self.asset_type})"
