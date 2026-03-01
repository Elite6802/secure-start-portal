from django.db import models
from django.db.models import JSONField
from django.core.exceptions import ValidationError
from core.models import BaseModel
from accounts.models import Organization, User


class ActivityLog(BaseModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="activity_logs")
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="activity_logs")
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField()
    metadata = JSONField(default=dict, blank=True)

    def __str__(self):
        return self.action

    def save(self, *args, **kwargs):
        if self.pk and not self._state.adding:
            raise ValidationError("Activity logs are immutable.")
        return super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False):
        raise ValidationError("Activity logs are immutable.")
