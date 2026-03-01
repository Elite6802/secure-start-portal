from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey

from core.models import BaseModel
from accounts.models import Organization, User


class FindingDisposition(BaseModel):
    """
    Unified triage state for findings across models (code/network/cloud).

    We use a GenericForeignKey instead of adding multiple columns to every finding table,
    so workflows (suppression, accepted risk, resolution, retest) can operate consistently.
    """

    STATUS_OPEN = "open"
    STATUS_RESOLVED = "resolved"
    STATUS_ACCEPTED_RISK = "accepted_risk"
    STATUS_SUPPRESSED = "suppressed"

    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_ACCEPTED_RISK, "Accepted Risk"),
        (STATUS_SUPPRESSED, "Suppressed"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="finding_dispositions")

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.UUIDField()
    content_object = GenericForeignKey("content_type", "object_id")

    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=STATUS_OPEN)
    justification = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="finding_dispositions")

    class Meta:
        unique_together = [("content_type", "object_id")]
        indexes = [
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["content_type", "object_id"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        return f"{self.status} disposition"

