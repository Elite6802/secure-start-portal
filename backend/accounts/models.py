import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models
from core.models import BaseModel


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)

    @property
    def organization(self):
        primary = self.memberships.filter(is_primary=True).first()
        return primary.organization if primary else self.memberships.first().organization if self.memberships.exists() else None

    def __str__(self):
        return self.email or self.username


class Organization(BaseModel):
    name = models.CharField(max_length=255)
    industry = models.CharField(max_length=120, blank=True)
    domain = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.name


class UserOrganization(BaseModel):
    ROLE_SECURITY_LEAD = "security_lead"
    ROLE_DEVELOPER = "developer"
    ROLE_EXECUTIVE = "executive"
    ROLE_SOC_ADMIN = "soc_admin"

    ROLE_CHOICES = [
        (ROLE_SECURITY_LEAD, "Security Lead"),
        (ROLE_DEVELOPER, "Developer"),
        (ROLE_EXECUTIVE, "Executive"),
        (ROLE_SOC_ADMIN, "SOC Admin"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="memberships")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default=ROLE_SECURITY_LEAD)
    is_primary = models.BooleanField(default=False)

    class Meta:
        unique_together = ("user", "organization")

    def __str__(self):
        return f"{self.user} -> {self.organization} ({self.role})"


class OrganizationScanPolicy(BaseModel):
    """
    Organization-level guardrails for potentially high-risk scan behaviors.

    Notes:
    - `ssrf_high_risk_enabled` is disabled by default.
    - `ssrf_allowlist` is intentionally explicit; for high-risk SSRF we only use allowlisted URLs
      and require the scanned target to match allowlisted domains/CIDRs.
    - `ssrf_allow_metadata` remains a separate explicit toggle to reduce accidental metadata probing.
    """

    organization = models.OneToOneField(Organization, on_delete=models.CASCADE, related_name="scan_policy")

    ssrf_high_risk_enabled = models.BooleanField(default=False)
    ssrf_allow_metadata = models.BooleanField(default=False)
    ssrf_allowlist = models.JSONField(
        default=dict,
        blank=True,
        help_text="Expected shape: {\"domains\": [], \"cidrs\": [], \"urls\": []}.",
    )

    # Optional inventory expectations for "coverage & hygiene" dashboards.
    # Expected shape: {"domains": int, "ip_ranges": int, "apis": int, "cloud_accounts": int, "repos": int, "apps": int}
    # Any missing keys will fall back to defaults in dashboard logic.
    inventory_expectations = models.JSONField(
        default=dict,
        blank=True,
        help_text="Optional expected inventory counts by category for completeness scoring.",
    )

    def __str__(self):
        return f"ScanPolicy({self.organization.name})"
