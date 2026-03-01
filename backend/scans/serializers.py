from django.db.models import Count
from rest_framework import serializers
from .models import Scan, ScanJob, ScanRequest, ScanSchedule, ScanAlert


class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = [
            "id",
            "organization",
            "asset",
            "scan_type",
            "status",
            "severity_summary",
            "metadata",
            "started_at",
            "completed_at",
            "created_at",
        ]


class ScanJobSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    asset_name = serializers.SerializerMethodField()
    repository_url = serializers.SerializerMethodField()
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
            "initiated_by",
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

    def get_asset_name(self, obj: ScanJob):
        if obj.asset:
            return obj.asset.name
        if obj.repository and obj.repository.asset:
            return obj.repository.asset.name
        return None

    def get_repository_url(self, obj: ScanJob):
        if obj.repository:
            return obj.repository.repo_url
        return None

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


class ScanRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanRequest
        fields = [
            "id",
            "organization",
            "requested_by",
            "scan_type",
            "target",
            "status",
            "client_notes",
            "admin_notes",
            "asset",
            "repository",
            "completed_at",
            "created_at",
        ]
        read_only_fields = [
            "organization",
            "requested_by",
            "status",
            "admin_notes",
            "asset",
            "repository",
            "completed_at",
            "created_at",
        ]


class ScanScheduleSerializer(serializers.ModelSerializer):
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
        read_only_fields = [
            "organization",
            "created_by",
            "last_run_at",
            "created_at",
        ]


class ScanAlertSerializer(serializers.ModelSerializer):
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
