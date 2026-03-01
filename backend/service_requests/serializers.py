from rest_framework import serializers
from .models import ServiceRequest


class ServiceRequestSerializer(serializers.ModelSerializer):
    report_id = serializers.SerializerMethodField()
    report_client_visible = serializers.SerializerMethodField()
    report_generated_at = serializers.SerializerMethodField()
    class Meta:
        model = ServiceRequest
        fields = [
            "id",
            "organization",
            "requested_by",
            "requested_role",
            "service_type",
            "scope",
            "repository_url",
            "asset",
            "cloud_account",
            "ip_cidr",
            "domain_url",
            "ownership_confirmed",
            "high_risk_ssrf",
            "authorization_reference",
            "authorization_notes",
            "justification",
            "status",
            "approved_by",
            "linked_scan_job",
            "report_id",
            "report_client_visible",
            "report_generated_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "organization",
            "requested_by",
            "requested_role",
            "status",
            "approved_by",
            "linked_scan_job",
            "report_id",
            "report_client_visible",
            "report_generated_at",
            "created_at",
            "updated_at",
        ]

    def _latest_report(self, obj):
        if hasattr(obj, "_prefetched_objects_cache") and "reports" in obj._prefetched_objects_cache:
            reports = obj._prefetched_objects_cache["reports"]
            return max(reports, key=lambda report: report.generated_at, default=None)
        return obj.reports.order_by("-generated_at").first()

    def get_report_id(self, obj):
        report = self._latest_report(obj)
        return str(report.id) if report else None

    def get_report_client_visible(self, obj):
        report = self._latest_report(obj)
        return report.client_visible if report else None

    def get_report_generated_at(self, obj):
        report = self._latest_report(obj)
        return report.generated_at if report else None


class ServiceRequestAdminSerializer(serializers.ModelSerializer):
    report_id = serializers.SerializerMethodField()
    report_client_visible = serializers.SerializerMethodField()
    report_generated_at = serializers.SerializerMethodField()
    class Meta:
        model = ServiceRequest
        fields = [
            "id",
            "organization",
            "requested_by",
            "requested_role",
            "service_type",
            "scope",
            "repository_url",
            "asset",
            "cloud_account",
            "ip_cidr",
            "domain_url",
            "ownership_confirmed",
            "high_risk_ssrf",
            "authorization_reference",
            "authorization_notes",
            "justification",
            "status",
            "approved_by",
            "linked_scan_job",
            "report_id",
            "report_client_visible",
            "report_generated_at",
            "created_at",
            "updated_at",
        ]

    def _latest_report(self, obj):
        if hasattr(obj, "_prefetched_objects_cache") and "reports" in obj._prefetched_objects_cache:
            reports = obj._prefetched_objects_cache["reports"]
            return max(reports, key=lambda report: report.generated_at, default=None)
        return obj.reports.order_by("-generated_at").first()

    def get_report_id(self, obj):
        report = self._latest_report(obj)
        return str(report.id) if report else None

    def get_report_client_visible(self, obj):
        report = self._latest_report(obj)
        return report.client_visible if report else None

    def get_report_generated_at(self, obj):
        report = self._latest_report(obj)
        return report.generated_at if report else None
