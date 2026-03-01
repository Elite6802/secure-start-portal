from django.db.models import Count
from rest_framework import serializers
from accounts.models import Organization, User, UserOrganization, OrganizationScanPolicy
from assets.models import Asset
from code_security.models import CodeRepository
from scans.models import ScanJob, ScanRequest, ScanSchedule, ScanAlert
from service_requests.models import ServiceRequest
from incidents.models import Incident
from reports.models import Report
from activity_log.models import ActivityLog


class OrganizationAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ["id", "name", "industry", "domain", "created_at", "updated_at"]


class OrganizationScanPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = OrganizationScanPolicy
        fields = [
            "id",
            "organization",
            "ssrf_high_risk_enabled",
            "ssrf_allow_metadata",
            "ssrf_allowlist",
            "inventory_expectations",
            "created_at",
            "updated_at",
        ]


class UserOrganizationAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserOrganization
        fields = ["id", "organization", "role", "is_primary", "created_at"]


class UserAdminSerializer(serializers.ModelSerializer):
    memberships = UserOrganizationAdminSerializer(many=True, read_only=True)
    password = serializers.CharField(write_only=True, required=False)
    organization = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        write_only=True,
        required=False,
        allow_null=True,
    )
    role = serializers.ChoiceField(
        choices=UserOrganization.ROLE_CHOICES,
        write_only=True,
        required=False,
    )
    is_primary = serializers.BooleanField(write_only=True, required=False, default=True)

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "is_staff",
            "is_active",
            "memberships",
            "date_joined",
            "password",
            "organization",
            "role",
            "is_primary",
        ]

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if self.instance is None and not attrs.get("organization"):
            raise serializers.ValidationError({"organization": "organization is required when creating a user."})
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        organization = validated_data.pop("organization", None)
        if not organization:
            raise serializers.ValidationError({"organization": "organization is required when creating a user."})
        role = validated_data.pop("role", UserOrganization.ROLE_DEVELOPER)
        is_primary = validated_data.pop("is_primary", True)
        user = User(**validated_data)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save()
        if organization:
            UserOrganization.objects.get_or_create(
                user=user,
                organization=organization,
                defaults={"role": role, "is_primary": is_primary},
            )
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        organization = validated_data.pop("organization", None)
        role = validated_data.pop("role", None)
        is_primary = validated_data.pop("is_primary", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        if organization:
            membership, created = UserOrganization.objects.get_or_create(
                user=instance,
                organization=organization,
                defaults={
                    "role": role or UserOrganization.ROLE_DEVELOPER,
                    "is_primary": True if is_primary is None else is_primary,
                },
            )
            if not created:
                if role:
                    membership.role = role
                if is_primary is not None:
                    membership.is_primary = is_primary
                membership.save()
        elif role is not None or is_primary is not None:
            membership = instance.memberships.filter(is_primary=True).first() or instance.memberships.first()
            if membership:
                if role:
                    membership.role = role
                if is_primary is not None:
                    membership.is_primary = is_primary
                membership.save()
        return instance


class ScanJobAdminSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    repository_url = serializers.CharField(source="repository.repo_url", read_only=True)
    service_request_type = serializers.CharField(source="service_request.service_type", read_only=True)
    created_by_email = serializers.CharField(source="created_by.email", read_only=True)
    duration_seconds = serializers.SerializerMethodField()
    scope_summary = serializers.SerializerMethodField()
    assets_scanned = serializers.SerializerMethodField()
    files_scanned = serializers.SerializerMethodField()
    findings_summary = serializers.SerializerMethodField()
    findings_total = serializers.SerializerMethodField()
    report_id = serializers.SerializerMethodField()
    report_generated_at = serializers.SerializerMethodField()
    report_client_visible = serializers.SerializerMethodField()

    class Meta:
        model = ScanJob
        fields = [
            "id",
            "organization",
            "organization_name",
            "scan_type",
            "asset",
            "asset_name",
            "repository",
            "repository_url",
            "scan_request",
            "service_request",
            "service_request_type",
            "status",
            "started_at",
            "completed_at",
            "failure_reason",
            "created_by",
            "created_by_email",
            "duration_seconds",
            "scope_summary",
            "assets_scanned",
            "files_scanned",
            "findings_summary",
            "findings_total",
            "report_id",
            "report_generated_at",
            "report_client_visible",
            "created_at",
        ]

    def get_duration_seconds(self, obj: ScanJob):
        if obj.started_at and obj.completed_at:
            return int((obj.completed_at - obj.started_at).total_seconds())
        return None

    def _latest_report(self, obj: ScanJob):
        reports = getattr(obj, "reports", None)
        if reports is not None:
            return reports.order_by("-generated_at", "-created_at").first()
        return None

    def _report_metadata(self, obj: ScanJob):
        report = self._latest_report(obj)
        return report.metadata if report and report.metadata else {}

    def get_scope_summary(self, obj: ScanJob):
        request_obj = obj.service_request
        if request_obj:
            if request_obj.repository_url:
                return f"Repository: {request_obj.repository_url}"
            if request_obj.domain_url:
                return f"Domain: {request_obj.domain_url}"
            if request_obj.ip_cidr:
                return f"IP/CIDR: {request_obj.ip_cidr}"
            if request_obj.asset:
                return f"Asset: {request_obj.asset.name}"
        if obj.repository:
            return f"Repository: {obj.repository.repo_url}"
        if obj.asset:
            return f"Asset: {obj.asset.name}"
        return "Scope not specified"

    def get_assets_scanned(self, obj: ScanJob):
        metadata = self._report_metadata(obj)
        hosts = metadata.get("hosts_alive") or metadata.get("hosts_scanned")
        if hosts is not None:
            try:
                return int(hosts)
            except (TypeError, ValueError):
                pass
        return 1 if obj.asset or obj.repository else 0

    def get_files_scanned(self, obj: ScanJob):
        metadata = self._report_metadata(obj)
        compliance = metadata.get("compliance") if isinstance(metadata, dict) else {}
        if isinstance(compliance, dict):
            files_scanned = compliance.get("files_scanned") or compliance.get("files_total")
            if files_scanned is not None:
                try:
                    return int(files_scanned)
                except (TypeError, ValueError):
                    pass
        return None

    def get_findings_summary(self, obj: ScanJob):
        summary = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
        for row in obj.code_findings.values("severity").annotate(total=Count("id")):
            severity = row.get("severity")
            if severity in summary:
                summary[severity] += row["total"]
        for row in obj.network_findings.values("severity").annotate(total=Count("id")):
            severity = row.get("severity")
            if severity in summary:
                summary[severity] += row["total"]
        for row in obj.cloud_findings.values("severity").annotate(total=Count("id")):
            severity = row.get("severity")
            if severity in summary:
                summary[severity] += row["total"]
        return summary

    def get_findings_total(self, obj: ScanJob):
        return obj.code_findings.count() + obj.network_findings.count() + obj.cloud_findings.count()

    def get_report_id(self, obj: ScanJob):
        report = self._latest_report(obj)
        return str(report.id) if report else None

    def get_report_generated_at(self, obj: ScanJob):
        report = self._latest_report(obj)
        return report.generated_at if report else None

    def get_report_client_visible(self, obj: ScanJob):
        report = self._latest_report(obj)
        return report.client_visible if report else None


class ScanScheduleAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanSchedule
        fields = [
            "id",
            "organization",
            "created_by",
            "service_type",
            "requested_role",
            "scope",
            "repository_url",
            "asset",
            "ip_cidr",
            "domain_url",
            "interval_minutes",
            "next_run_at",
            "last_run_at",
            "is_active",
            "created_at",
        ]


class ScanAlertAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanAlert
        fields = [
            "id",
            "organization",
            "user",
            "severity",
            "title",
            "message",
            "link",
            "metadata",
            "read_at",
            "created_at",
        ]


class ScanRequestAdminSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    requested_by_email = serializers.CharField(source="requested_by.email", read_only=True)
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    repository_url = serializers.CharField(source="repository.repo_url", read_only=True)

    class Meta:
        model = ScanRequest
        fields = [
            "id",
            "organization",
            "organization_name",
            "requested_by",
            "requested_by_email",
            "scan_type",
            "target",
            "status",
            "client_notes",
            "admin_notes",
            "asset",
            "asset_name",
            "repository",
            "repository_url",
            "completed_at",
            "created_at",
        ]


class ServiceRequestAdminSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    requested_by_email = serializers.CharField(source="requested_by.email", read_only=True)
    approved_by_email = serializers.CharField(source="approved_by.email", read_only=True)
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    linked_scan_job_type = serializers.CharField(source="linked_scan_job.scan_type", read_only=True)
    scan_failure_reason = serializers.CharField(source="linked_scan_job.failure_reason", read_only=True)

    class Meta:
        model = ServiceRequest
        fields = [
            "id",
            "organization",
            "organization_name",
            "requested_by",
            "requested_by_email",
            "requested_role",
            "service_type",
            "scope",
            "repository_url",
            "asset",
            "asset_name",
            "ip_cidr",
            "domain_url",
            "justification",
            "status",
            "approved_by",
            "approved_by_email",
            "linked_scan_job",
            "linked_scan_job_type",
            "scan_failure_reason",
            "created_at",
            "updated_at",
        ]


class IncidentAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Incident
        fields = [
            "id",
            "organization",
            "severity",
            "status",
            "description",
            "detected_at",
            "resolved_at",
            "created_at",
        ]


class ActivityLogAdminSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    user_email = serializers.CharField(source="user.email", read_only=True)
    detail = serializers.SerializerMethodField()

    class Meta:
        model = ActivityLog
        fields = [
            "id",
            "organization",
            "organization_name",
            "user",
            "user_email",
            "action",
            "timestamp",
            "metadata",
            "detail",
            "created_at",
        ]

    def get_detail(self, obj: ActivityLog) -> str:
        metadata = obj.metadata or {}
        if isinstance(metadata, dict):
            if isinstance(metadata.get("detail"), str):
                return metadata["detail"]
        action = obj.action or "Activity logged"
        identifier = metadata.get("service_request") or metadata.get("service_request_id")
        if identifier:
            request = ServiceRequest.objects.filter(id=identifier).select_related("asset").first()
            if request:
                service_labels = {
                    "CODE_SECRETS_SCAN": "Code Secrets Scan",
                    "DEPENDENCY_VULN_SCAN": "Dependency Vulnerability Scan",
                    "CODE_COMPLIANCE_SCAN": "Code Standards Compliance",
                    "CODE_COMPLIANCE_PYTHON": "Python PEP8 Compliance",
                    "CODE_COMPLIANCE_HTML": "HTML Standards Compliance",
                    "CODE_COMPLIANCE_CSS": "CSS Standards Compliance",
                    "CODE_COMPLIANCE_JAVASCRIPT": "JavaScript Standards Compliance",
                    "CODE_COMPLIANCE_REACT": "React Standards Compliance",
                    "NETWORK_CONFIGURATION_SCAN": "Network Configuration Scan",
                    "WEB_EXPOSURE_SCAN": "Web Exposure Scan",
                    "API_SECURITY_SCAN": "API Security Scan",
                    "INFRASTRUCTURE_HARDENING_SCAN": "Infrastructure Hardening Scan",
                }
                target = request.repository_url or request.domain_url or request.ip_cidr or (request.asset.name if request.asset else "")
                service = service_labels.get(request.service_type, request.service_type)
                return f"{action}: {service} · {target or 'No target'}"
        scan_id = metadata.get("scan_job") or metadata.get("scan_job_id")
        if scan_id:
            job = ScanJob.objects.filter(id=scan_id).select_related("asset", "repository").first()
            if job:
                target = job.repository.repo_url if job.repository else job.asset.name if job.asset else ""
                return f"{action}: {job.scan_type} · {target or 'No target'}"
        report_id = metadata.get("report") or metadata.get("report_id")
        if report_id:
            report = Report.objects.filter(id=report_id).first()
            if report:
                return f"{action}: {report.scope} report"
        asset_id = metadata.get("asset") or metadata.get("asset_id")
        if asset_id:
            asset = Asset.objects.filter(id=asset_id).first()
            if asset:
                return f"{action}: {asset.name}"
        repo_id = metadata.get("repository") or metadata.get("repository_id")
        if repo_id:
            repo = CodeRepository.objects.filter(id=repo_id).first()
            if repo:
                return f"{action}: {repo.repo_url}"
        org_id = metadata.get("organization") or metadata.get("organization_id")
        if org_id:
            org = Organization.objects.filter(id=org_id).first()
            if org:
                return f"{action}: {org.name}"
        return action


class ReportAdminSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    service_request_type = serializers.CharField(source="service_request.service_type", read_only=True)
    scan_job_type = serializers.CharField(source="scan_job.scan_type", read_only=True)

    class Meta:
        model = Report
        fields = [
            "id",
            "organization",
            "organization_name",
            "scope",
            "summary",
            "generated_at",
            "file_path",
            "metadata",
            "client_visible",
            "sent_at",
            "service_request",
            "service_request_type",
            "scan_job",
            "scan_job_type",
            "created_at",
        ]
