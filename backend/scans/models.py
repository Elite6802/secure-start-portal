from django.db import models
from django.db.models import JSONField
from core.models import BaseModel
from accounts.models import Organization, User
from assets.models import Asset


class Scan(BaseModel):
    TYPE_WEB = "web"
    TYPE_API = "api"
    TYPE_CODE = "code"
    TYPE_NETWORK = "network"
    TYPE_INFRA = "infrastructure"
    TYPE_CLOUD = "cloud"

    SCAN_TYPE_CHOICES = [
        (TYPE_WEB, "Web"),
        (TYPE_API, "API"),
        (TYPE_CODE, "Code"),
        (TYPE_NETWORK, "Network"),
        (TYPE_INFRA, "Infrastructure"),
        (TYPE_CLOUD, "Cloud"),
    ]

    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_RUNNING, "Running"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scans")
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="scans")
    scan_type = models.CharField(max_length=30, choices=SCAN_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    severity_summary = JSONField(default=dict, blank=True)
    metadata = JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.scan_type} - {self.asset.name}"


class ScanRequest(BaseModel):
    TYPE_WEB = "web"
    TYPE_API = "api"
    TYPE_CODE = "code"
    TYPE_NETWORK = "network"
    TYPE_INFRA = "infrastructure"
    TYPE_CLOUD = "cloud"

    SCAN_TYPE_CHOICES = [
        (TYPE_WEB, "Web"),
        (TYPE_API, "API"),
        (TYPE_CODE, "Code"),
        (TYPE_NETWORK, "Network"),
        (TYPE_INFRA, "Infrastructure"),
        (TYPE_CLOUD, "Cloud"),
    ]

    STATUS_REQUESTED = "requested"
    STATUS_QUEUED = "queued"
    STATUS_IN_PROGRESS = "in_progress"
    STATUS_COMPLETED = "completed"
    STATUS_REJECTED = "rejected"
    STATUS_FAILED = "failed"

    STATUS_CHOICES = [
        (STATUS_REQUESTED, "Requested"),
        (STATUS_QUEUED, "Queued"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_REJECTED, "Rejected"),
        (STATUS_FAILED, "Failed"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scan_requests")
    requested_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_requests",
    )
    scan_type = models.CharField(max_length=30, choices=SCAN_TYPE_CHOICES)
    target = models.CharField(max_length=512)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_REQUESTED)
    client_notes = models.TextField(blank=True)
    admin_notes = models.TextField(blank=True)
    asset = models.ForeignKey(Asset, on_delete=models.SET_NULL, null=True, blank=True, related_name="scan_requests")
    repository = models.ForeignKey(
        "code_security.CodeRepository",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_requests",
    )
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.scan_type} request"


class ScanSchedule(BaseModel):
    SCOPE_REPOSITORY = "repository"
    SCOPE_ASSET = "asset"
    SCOPE_IP_CIDR = "ip_cidr"
    SCOPE_DOMAIN = "domain"

    SCOPE_CHOICES = [
        (SCOPE_REPOSITORY, "Repository"),
        (SCOPE_ASSET, "Asset"),
        (SCOPE_IP_CIDR, "IP/CIDR"),
        (SCOPE_DOMAIN, "Domain/URL"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scan_schedules")
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="scan_schedules")
    service_type = models.CharField(max_length=64)
    requested_role = models.CharField(max_length=32, default="security_lead")
    scope = models.CharField(max_length=32, choices=SCOPE_CHOICES, default=SCOPE_REPOSITORY)
    repository_url = models.TextField(blank=True)
    asset = models.ForeignKey(Asset, on_delete=models.SET_NULL, null=True, blank=True, related_name="scan_schedules")
    cloud_account = models.ForeignKey(
        "cloud_security.CloudAccount",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_schedules",
    )
    ip_cidr = models.CharField(max_length=255, blank=True)
    domain_url = models.CharField(max_length=255, blank=True)
    interval_minutes = models.PositiveIntegerField(default=1440)
    next_run_at = models.DateTimeField()
    last_run_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.organization.name} schedule {self.service_type}"


class ScanAlert(BaseModel):
    SEVERITY_INFO = "info"
    SEVERITY_WARNING = "warning"
    SEVERITY_CRITICAL = "critical"

    SEVERITY_CHOICES = [
        (SEVERITY_INFO, "Info"),
        (SEVERITY_WARNING, "Warning"),
        (SEVERITY_CRITICAL, "Critical"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scan_alerts")
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="scan_alerts")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default=SEVERITY_INFO)
    title = models.CharField(max_length=255)
    message = models.TextField()
    link = models.CharField(max_length=255, blank=True)
    metadata = JSONField(default=dict, blank=True)
    read_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title


class ScanJob(BaseModel):
    TYPE_CODE = "code"
    TYPE_NETWORK = "network"
    TYPE_WEB = "web"
    TYPE_API = "api"
    TYPE_INFRA = "infrastructure"
    TYPE_CLOUD = "cloud"

    SCAN_TYPE_CHOICES = [
        (TYPE_CODE, "Code"),
        (TYPE_NETWORK, "Network"),
        (TYPE_WEB, "Web"),
        (TYPE_API, "API"),
        (TYPE_INFRA, "Infrastructure"),
        (TYPE_CLOUD, "Cloud"),
    ]

    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scan_jobs")
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="scan_jobs", null=True, blank=True)
    repository = models.ForeignKey("code_security.CodeRepository", on_delete=models.CASCADE, related_name="scan_jobs", null=True, blank=True)
    scan_request = models.ForeignKey("ScanRequest", on_delete=models.SET_NULL, null=True, blank=True, related_name="scan_jobs")
    service_request = models.ForeignKey(
        "service_requests.ServiceRequest",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_jobs",
    )
    cloud_account = models.ForeignKey(
        "cloud_security.CloudAccount",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_jobs",
    )
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_QUEUED)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    failure_reason = models.TextField(blank=True)
    created_by = models.ForeignKey("accounts.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="scan_jobs")
    initiated_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="initiated_scan_jobs",
    )

    def __str__(self):
        return f"{self.scan_type} job"
