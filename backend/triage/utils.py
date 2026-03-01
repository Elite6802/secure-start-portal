from __future__ import annotations

from datetime import timedelta
from django.utils import timezone

from .models import FindingDisposition


def disposition_effective_status(d: FindingDisposition | None) -> str:
    """
    Returns the effective status for a disposition, respecting expiry.
    """
    if not d:
        return FindingDisposition.STATUS_OPEN
    if d.status in {FindingDisposition.STATUS_SUPPRESSED, FindingDisposition.STATUS_ACCEPTED_RISK} and d.expires_at:
        if d.expires_at <= timezone.now():
            return FindingDisposition.STATUS_OPEN
    return d.status


def sla_days_for_severity(severity: str) -> int:
    """
    Default SLAs are intentionally conservative.
    Override via env vars in the view layer if needed.
    """
    sev = (severity or "").lower().strip()
    return {"critical": 7, "high": 14, "moderate": 30, "low": 90}.get(sev, 30)


def age_days(created_at) -> int:
    if not created_at:
        return 0
    now = timezone.now()
    delta = now - created_at
    return max(0, int(delta.total_seconds() // 86400))


def is_overdue(severity: str, created_at, sla_days: int | None = None) -> bool:
    days = age_days(created_at)
    threshold = int(sla_days) if sla_days is not None else sla_days_for_severity(severity)
    return days > threshold

