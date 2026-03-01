from django.db import models
from core.models import BaseModel
from accounts.models import Organization


class Incident(BaseModel):
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
    STATUS_INVESTIGATING = "investigating"
    STATUS_RESOLVED = "resolved"

    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_INVESTIGATING, "Investigating"),
        (STATUS_RESOLVED, "Resolved"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="incidents")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    description = models.TextField()
    detected_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.description[:60]
