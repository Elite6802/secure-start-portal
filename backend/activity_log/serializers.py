from rest_framework import serializers
from accounts.models import Organization
from assets.models import Asset
from code_security.models import CodeRepository
from reports.models import Report
from scans.models import ScanJob
from service_requests.models import ServiceRequest
from .models import ActivityLog


class ActivityLogSerializer(serializers.ModelSerializer):
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
