from rest_framework import serializers
from .models import Report


class ReportSerializer(serializers.ModelSerializer):
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
