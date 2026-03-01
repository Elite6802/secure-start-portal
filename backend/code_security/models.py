from django.db import models
from django.db.models import JSONField
from core.models import BaseModel
from accounts.models import Organization
from assets.models import Asset


class CodeRepository(BaseModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="code_repositories")
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="code_repository")
    repo_url = models.URLField()
    language = models.CharField(max_length=120, blank=True)

    def __str__(self):
        return self.repo_url


class CodeRepositorySnapshot(BaseModel):
    repository = models.ForeignKey(CodeRepository, on_delete=models.CASCADE, related_name="snapshots")
    service_type = models.CharField(max_length=64)
    file_hashes = JSONField(default=dict, blank=True)
    files_scanned = models.PositiveIntegerField(default=0)
    files_changed = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"{self.repository.repo_url} - {self.service_type}"


class CodeFinding(BaseModel):
    CATEGORY_SAST = "sast"
    CATEGORY_DEPENDENCY = "dependency"
    CATEGORY_SECRETS = "secrets"

    CATEGORY_CHOICES = [
        (CATEGORY_SAST, "SAST"),
        (CATEGORY_DEPENDENCY, "Dependency"),
        (CATEGORY_SECRETS, "Secrets"),
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

    repository = models.ForeignKey(CodeRepository, on_delete=models.CASCADE, related_name="findings")
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    resolved_at = models.DateTimeField(null=True, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    remediation = models.TextField(blank=True)
    standard_mapping = JSONField(default=list, blank=True)
    scan_job = models.ForeignKey(
        "scans.ScanJob",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="code_findings",
    )
    service_request = models.ForeignKey(
        "service_requests.ServiceRequest",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="code_findings",
    )
    secret_type = models.CharField(max_length=120, blank=True, null=True)
    file_path = models.CharField(max_length=500, blank=True, null=True)
    line_number = models.IntegerField(null=True, blank=True)
    masked_value = models.CharField(max_length=255, blank=True, null=True)
    confidence_score = models.PositiveSmallIntegerField(null=True, blank=True)
    rationale = models.TextField(blank=True, null=True)
    cvss_vector = models.CharField(max_length=128, blank=True, default="")

    def __str__(self):
        return self.title
