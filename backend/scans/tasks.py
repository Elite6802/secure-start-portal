import time
import hashlib
import re
import socket
import http.client
from datetime import timedelta
from django.utils import timezone
from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from scans.models import ScanJob, Scan, ScanRequest, ScanSchedule, ScanAlert
from reports.models import Report
from code_security.models import CodeFinding
from network_security.models import NetworkAsset, NetworkFinding
from service_requests.models import ServiceRequest
from service_requests.tasks import execute_service_request_job


SECRET_PATTERNS = [
    {
        "title": "AWS access key exposed",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": CodeFinding.SEVERITY_CRITICAL,
        "remediation": "Revoke the key immediately and rotate credentials in AWS IAM.",
        "mapping": ["OWASP Top 10 A02", "NIST 800-53 IA-5"],
    },
    {
        "title": "GitHub personal access token leaked",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": CodeFinding.SEVERITY_HIGH,
        "remediation": "Revoke the token and replace with a scoped, short-lived token.",
        "mapping": ["OWASP Top 10 A02", "ISO 27001 A.9"],
    },
    {
        "title": "Google API key hardcoded",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": CodeFinding.SEVERITY_MODERATE,
        "remediation": "Move the API key to a secrets manager and restrict by referrer/IP.",
        "mapping": ["OWASP Top 10 A02", "NIST 800-53 SC-12"],
    },
    {
        "title": "Slack token embedded in source",
        "pattern": r"xox[baprs]-[0-9A-Za-z-]{10,48}",
        "severity": CodeFinding.SEVERITY_MODERATE,
        "remediation": "Rotate the token and store it in environment variables.",
        "mapping": ["OWASP Top 10 A02", "ISO 27001 A.9"],
    },
    {
        "title": "Private key committed to repository",
        "pattern": r"-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----",
        "severity": CodeFinding.SEVERITY_CRITICAL,
        "remediation": "Remove the key, rotate certificates, and update dependent services.",
        "mapping": ["OWASP Top 10 A02", "NIST 800-53 SC-13"],
    },
    {
        "title": "Hardcoded password detected",
        "pattern": r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "severity": CodeFinding.SEVERITY_HIGH,
        "remediation": "Replace with a secret reference and rotate the password.",
        "mapping": ["OWASP Top 10 A02", "NIST 800-53 IA-5"],
    },
]


def _mock_repo_content(repo_url: str) -> list[str]:
    seed = int(hashlib.sha256(repo_url.encode("utf-8")).hexdigest(), 16)
    samples = [
        'const API_KEY = "AIzaSyD3m0KeyThatLooksReal00000000000";',
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
        "GH_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",
        "SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghijklmnopqrstuvwx",
        'password = "P@ssw0rd!"',
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----",
    ]
    content = []
    for idx, sample in enumerate(samples):
        if (seed >> idx) & 1:
            content.append(sample)
    if not content:
        content.append(samples[seed % len(samples)])
    return content


def _create_secret_findings(repository):
    content = "\n".join(_mock_repo_content(repository.repo_url))
    findings = []
    for pattern in SECRET_PATTERNS:
        if re.search(pattern["pattern"], content):
            findings.append(pattern)
    for finding in findings:
        CodeFinding.objects.get_or_create(
            repository=repository,
            category=CodeFinding.CATEGORY_SECRETS,
            title=finding["title"],
            defaults={
                "severity": finding["severity"],
                "description": "Potential secret detected during repository scan. Validate and rotate immediately.",
                "remediation": finding["remediation"],
                "standard_mapping": finding["mapping"],
            },
        )


def _severity_summary_for_code(repository):
    summary = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    for severity in (
        CodeFinding.objects.filter(repository=repository)
        .values_list("severity", flat=True)
    ):
        summary[severity] = summary.get(severity, 0) + 1
    return summary


def _severity_summary_for_network(network_asset):
    summary = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    for severity in (
        NetworkFinding.objects.filter(network_asset=network_asset)
        .values_list("severity", flat=True)
    ):
        summary[severity] = summary.get(severity, 0) + 1
    return summary


def _create_scan_record(job, scan_type, severity_summary):
    asset = job.asset
    if not asset and job.repository:
        asset = job.repository.asset
    if not asset:
        return
    Scan.objects.create(
        organization=job.organization,
        asset=asset,
        scan_type=scan_type,
        status=Scan.STATUS_COMPLETED,
        severity_summary=severity_summary,
        started_at=job.started_at or timezone.now(),
        completed_at=timezone.now(),
    )
    asset.last_scanned_at = timezone.now()
    asset.save(update_fields=["last_scanned_at"])


def _create_report_for_job(job, severity_summary):
    if Report.objects.filter(scan_job=job).exists():
        return
    scope_map = {
        ScanJob.TYPE_CODE: Report.SCOPE_CODE,
        ScanJob.TYPE_NETWORK: Report.SCOPE_NETWORK,
        ScanJob.TYPE_WEB: Report.SCOPE_WEB,
        ScanJob.TYPE_API: Report.SCOPE_WEB,
        ScanJob.TYPE_INFRA: Report.SCOPE_COMBINED,
    }
    scope = scope_map.get(job.scan_type, Report.SCOPE_COMBINED)
    summary = (
        f"Automated {scope} scan completed. "
        f"Findings: critical {severity_summary.get('critical', 0)}, "
        f"high {severity_summary.get('high', 0)}, "
        f"moderate {severity_summary.get('moderate', 0)}, "
        f"low {severity_summary.get('low', 0)}."
    )
    Report.objects.create(
        organization=job.organization,
        scope=scope,
        summary=summary,
        generated_at=timezone.now(),
        file_path=f"reports/{job.id}.pdf",
        metadata={"severity_summary": severity_summary},
        client_visible=False,
        scan_job=job,
        service_request=job.service_request,
    )


def _update_request_status(job, status, completed=False):
    if not job.scan_request_id:
        return
    updates = {"status": status}
    if completed:
        updates["completed_at"] = timezone.now()
    ScanRequest.objects.filter(id=job.scan_request_id).update(**updates)


def _create_alert(organization, user, severity: str, title: str, message: str, link: str = "", metadata: dict | None = None):
    ScanAlert.objects.create(
        organization=organization,
        user=user,
        severity=severity,
        title=title,
        message=message,
        link=link,
        metadata=metadata or {},
    )


def _is_retriable_error(exc: Exception) -> bool:
    if isinstance(exc, ValueError):
        return False
    return isinstance(
        exc,
        (
            TimeoutError,
            ConnectionError,
            OSError,
            socket.error,
            http.client.HTTPException,
        ),
    )


@shared_task(bind=True, max_retries=2, default_retry_delay=5)
def execute_scan_job(self, scan_job_id: str):
    job = (
        ScanJob.objects.filter(id=scan_job_id)
        .select_related("repository", "asset", "organization", "scan_request", "service_request")
        .first()
    )
    if not job:
        return

    # Preferred path: scan jobs created from service requests should use the
    # service-request execution pipeline (real scanners + richer metadata).
    if job.service_request_id:
        execute_service_request_job.apply_async(args=[str(job.id)], queue="scanner")
        return

    job.status = ScanJob.STATUS_RUNNING
    job.started_at = timezone.now()
    job.failure_reason = ""
    job.save(update_fields=["status", "started_at", "failure_reason"])
    _update_request_status(job, ScanRequest.STATUS_IN_PROGRESS)

    time.sleep(3)

    try:
        summary = None
        if job.scan_type == ScanJob.TYPE_CODE and job.repository:
            CodeFinding.objects.get_or_create(
                repository=job.repository,
                category=CodeFinding.CATEGORY_DEPENDENCY,
                title="Outdated dependency detected",
                scan_job=job,
                service_request=job.service_request,
                defaults={
                    "severity": CodeFinding.SEVERITY_MODERATE,
                    "description": "Dependency is behind recommended security version.",
                    "remediation": "Upgrade to the latest patched release.",
                    "standard_mapping": ["OWASP Top 10 A06", "NIST 800-53 SI-2"],
                },
            )
            _create_secret_findings(job.repository)
            summary = _severity_summary_for_code(job.repository)
            _create_scan_record(job, Scan.TYPE_CODE, summary)
        elif job.scan_type == ScanJob.TYPE_NETWORK and job.asset:
            network_asset, _ = NetworkAsset.objects.get_or_create(
                organization=job.organization,
                asset=job.asset,
                defaults={"network_type": "external"},
            )
            NetworkFinding.objects.create(
                network_asset=network_asset,
                finding_type="exposed_service",
                severity="high",
                summary="Exposed administrative service detected",
                recommendation="Restrict exposure and enforce MFA.",
                scan_job=job,
                service_request=job.service_request,
                evidence={"host": job.asset.identifier, "port": 22, "protocol": "tcp"},
            )
            NetworkFinding.objects.create(
                network_asset=network_asset,
                finding_type="segmentation_risk",
                severity="moderate",
                summary="East-west traffic controls require tightening",
                recommendation="Review segmentation policies and enforce micro-segmentation.",
                scan_job=job,
                service_request=job.service_request,
            )
            summary = _severity_summary_for_network(network_asset)
            _create_scan_record(job, Scan.TYPE_NETWORK, summary)
        elif job.scan_type == ScanJob.TYPE_WEB and job.asset:
            summary = {"high": 0, "moderate": 2, "low": 5}
            _create_scan_record(job, Scan.TYPE_WEB, summary)
        elif job.scan_type == ScanJob.TYPE_API and job.asset:
            summary = {"high": 1, "moderate": 1, "low": 2}
            _create_scan_record(job, Scan.TYPE_API, summary)
        elif job.scan_type == ScanJob.TYPE_INFRA and job.asset:
            summary = {"high": 0, "moderate": 3, "low": 4}
            _create_scan_record(job, Scan.TYPE_INFRA, summary)

        if summary is not None:
            _create_report_for_job(job, summary)

        job.status = ScanJob.STATUS_COMPLETED
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "completed_at"])
        _update_request_status(job, ScanRequest.STATUS_COMPLETED, completed=True)
        if job.scan_request_id:
            _create_alert(
                job.organization,
                job.created_by,
                ScanAlert.SEVERITY_INFO,
                "Scan completed",
                "Your scheduled scan completed. A report is ready for review.",
                link="/dashboard/reports",
                metadata={"scan_job_id": str(job.id)},
            )
    except Exception as exc:
        if _is_retriable_error(exc):
            try:
                job.status = ScanJob.STATUS_QUEUED
                job.failure_reason = f"Transient error: {exc}"
                job.save(update_fields=["status", "failure_reason"])
                _update_request_status(job, ScanRequest.STATUS_QUEUED)
                raise self.retry(exc=exc)
            except MaxRetriesExceededError:
                pass

        job.status = ScanJob.STATUS_FAILED
        job.failure_reason = str(exc)
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "completed_at", "failure_reason"])
        _update_request_status(job, ScanRequest.STATUS_FAILED, completed=True)
        if job.scan_request_id:
            _create_alert(
                job.organization,
                job.created_by,
                ScanAlert.SEVERITY_WARNING,
                "Scan failed",
                "A scheduled scan failed during execution. Please retry or contact support.",
                link="/dashboard/requests",
                metadata={"scan_job_id": str(job.id), "error": str(exc)},
            )
        raise


@shared_task
def run_scan_schedules():
    now = timezone.now()
    schedules = ScanSchedule.objects.filter(is_active=True, next_run_at__lte=now).select_related("organization", "created_by")
    for schedule in schedules:
        scan_type_map = {
            ServiceRequest.SERVICE_CODE_SECRETS: ScanJob.TYPE_CODE,
            ServiceRequest.SERVICE_DEPENDENCY: ScanJob.TYPE_CODE,
            ServiceRequest.SERVICE_CODE_COMPLIANCE: ScanJob.TYPE_CODE,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_PYTHON: ScanJob.TYPE_CODE,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_HTML: ScanJob.TYPE_CODE,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_CSS: ScanJob.TYPE_CODE,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_JAVASCRIPT: ScanJob.TYPE_CODE,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_REACT: ScanJob.TYPE_CODE,
            ServiceRequest.SERVICE_NETWORK: ScanJob.TYPE_NETWORK,
            ServiceRequest.SERVICE_WEB: ScanJob.TYPE_WEB,
            ServiceRequest.SERVICE_API: ScanJob.TYPE_API,
            ServiceRequest.SERVICE_INFRA: ScanJob.TYPE_INFRA,
        }
        request_obj = ServiceRequest.objects.create(
            organization=schedule.organization,
            requested_by=schedule.created_by,
            requested_role=schedule.requested_role,
            service_type=schedule.service_type,
            scope=schedule.scope,
            repository_url=schedule.repository_url or "",
            asset=schedule.asset,
            ip_cidr=schedule.ip_cidr or "",
            domain_url=schedule.domain_url or "",
            justification="Scheduled scan run.",
            status=ServiceRequest.STATUS_APPROVED,
            approved_by=schedule.created_by,
        )
        job = ScanJob.objects.create(
            organization=schedule.organization,
            scan_type=scan_type_map.get(schedule.service_type, ScanJob.TYPE_CODE),
            asset=schedule.asset,
            created_by=schedule.created_by,
            service_request=request_obj,
        )
        request_obj.linked_scan_job = job
        request_obj.status = ServiceRequest.STATUS_APPROVED
        request_obj.save(update_fields=["linked_scan_job", "status"])
        execute_service_request_job.apply_async(args=[str(job.id)], queue="scanner")

        schedule.last_run_at = now
        schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
        schedule.save(update_fields=["last_run_at", "next_run_at"])
