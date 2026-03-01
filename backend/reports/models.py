from django.db import models
from core.models import BaseModel
from accounts.models import Organization


class Report(BaseModel):
    SCOPE_WEB = "web"
    SCOPE_CODE = "code"
    SCOPE_NETWORK = "network"
    SCOPE_CLOUD = "cloud"
    SCOPE_COMBINED = "combined"

    SCOPE_CHOICES = [
        (SCOPE_WEB, "Web"),
        (SCOPE_CODE, "Code"),
        (SCOPE_NETWORK, "Network"),
        (SCOPE_CLOUD, "Cloud"),
        (SCOPE_COMBINED, "Combined"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="reports")
    scope = models.CharField(max_length=20, choices=SCOPE_CHOICES, default=SCOPE_COMBINED)
    summary = models.TextField()
    generated_at = models.DateTimeField()
    file_path = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    client_visible = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    service_request = models.ForeignKey(
        "service_requests.ServiceRequest",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    scan_job = models.ForeignKey(
        "scans.ScanJob",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )

    def __str__(self):
        return f"{self.scope} report"
