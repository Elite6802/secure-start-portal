import hashlib
import os
import time
import socket
import http.client
from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from django.utils import timezone
from activity_log.models import ActivityLog
from assets.models import Asset
from code_security.models import CodeRepository, CodeFinding, CodeRepositorySnapshot
from network_security.models import NetworkAsset, NetworkFinding
from scans.models import Scan, ScanJob, ScanAlert
from reports.models import Report
from core.posture import compute_posture_score, posture_payload
from core.insights import compute_exploit_chains, compute_security_maturity, compute_threat_model_snapshot
from .models import ServiceRequest
from accounts.models import OrganizationScanPolicy
from scanners.code.secrets_scanner import scan_repository
from scanners.code.repo_fetcher import ensure_repo_snapshot
from scanners.code.compliance_scanner import scan_repository as scan_compliance
from scanners.code.dependency_scanner import scan_dependencies
from scanners.code.risk_scanner import scan_repository as scan_code_risks
from scanners.network.config_scanner import (
    scan_api_target,
    scan_asset as scan_network_asset,
    scan_infra_target,
    scan_web_target,
)
from scanners.network.web_safety_scanner import scan_web_security
from scanners.network.active_validation import validate_web_target_detailed
from cloud_security.models import CloudAccount, CloudFinding
from scanners.cloud.cspm import scan_cloud_account



def _log_activity(request_obj: ServiceRequest, action: str, user=None, metadata: dict | None = None):
    payload = dict(metadata or {})
    payload.setdefault("service_request_id", str(request_obj.id))
    ActivityLog.objects.create(
        organization=request_obj.organization,
        user=user,
        action=action,
        timestamp=timezone.now(),
        metadata=payload,
    )


def _log_job_step(
    request_obj: ServiceRequest,
    job: ScanJob,
    action: str,
    detail: str = "",
    level: str = "info",
    extra: dict | None = None,
):
    metadata = {
        "service_request_id": str(request_obj.id),
        "scan_job_id": str(job.id),
        "level": level,
    }
    if detail:
        metadata["detail"] = detail
    if extra:
        metadata.update(extra)
    _log_activity(request_obj, action, user=request_obj.approved_by, metadata=metadata)


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



def _resolve_asset_by_identifier(request_obj: ServiceRequest, identifier: str, defaults: dict):
    # Avoid MultipleObjectsReturned when duplicate identifiers exist in an org.
    qs = Asset.objects.filter(organization=request_obj.organization, identifier=identifier).order_by("-updated_at", "-created_at")
    asset = qs.first()
    if asset:
        duplicate_count = qs.count()
        if duplicate_count > 1:
            _log_activity(
                request_obj,
                "Duplicate assets detected for scan target",
                user=request_obj.approved_by,
                metadata={
                    "identifier": identifier,
                    "selected_asset_id": str(asset.id),
                    "duplicate_count": duplicate_count,
                },
            )
        return asset, False
    return Asset.objects.create(organization=request_obj.organization, identifier=identifier, **defaults), True


def _resolve_repository(request_obj: ServiceRequest):
    repo_url = request_obj.repository_url.strip()
    asset, _ = _resolve_asset_by_identifier(
        request_obj,
        repo_url,
        {
            "name": repo_url,
            "asset_type": Asset.TYPE_CODE_REPOSITORY,
            "risk_level": Asset.RISK_LOW,
        },
    )
    repository, _ = CodeRepository.objects.get_or_create(
        organization=request_obj.organization,
        asset=asset,
        repo_url=repo_url,
        defaults={"language": ""},
    )
    return asset, repository


def _resolve_network_asset(request_obj: ServiceRequest):
    if request_obj.asset:
        asset = request_obj.asset
    else:
        identifier = request_obj.domain_url or request_obj.ip_cidr
        asset_type = Asset.TYPE_NETWORK_SEGMENT if request_obj.ip_cidr else Asset.TYPE_DOMAIN
        asset, _ = _resolve_asset_by_identifier(
            request_obj,
            identifier,
            {
                "name": identifier,
                "asset_type": asset_type,
                "risk_level": Asset.RISK_LOW,
            },
        )
    network_asset, _ = NetworkAsset.objects.get_or_create(
        organization=request_obj.organization,
        asset=asset,
        defaults={"network_type": NetworkAsset.TYPE_EXTERNAL},
    )
    return asset, network_asset


def _resolve_cloud_asset(request_obj: ServiceRequest):
    account = request_obj.cloud_account
    if not account:
        return None, None
    identifier = account.aws_account_id or account.azure_subscription_id or account.gcp_project_id or account.name
    asset, _ = _resolve_asset_by_identifier(
        request_obj,
        identifier,
        {
            "name": f"{account.name} ({account.get_provider_display()})",
            "asset_type": Asset.TYPE_CLOUD_RESOURCE,
            "risk_level": Asset.RISK_LOW,
        },
    )
    return asset, account


def _create_scan_record(job: ScanJob, scan_type: str, severity_summary: dict, metadata: dict | None = None):
    asset = job.asset or (job.repository.asset if job.repository else None)
    if not asset:
        return
    Scan.objects.create(
        organization=job.organization,
        asset=asset,
        scan_type=scan_type,
        status=Scan.STATUS_COMPLETED,
        severity_summary=severity_summary,
        metadata=metadata or {},
        started_at=job.started_at or timezone.now(),
        completed_at=timezone.now(),
    )
    asset.last_scanned_at = timezone.now()
    asset.save(update_fields=["last_scanned_at"])


def _create_report(request_obj: ServiceRequest, job: ScanJob, severity_summary: dict, metadata: dict | None = None):
    # We keep reports stable per service request (UI expects a single "current" report),
    # but allow re-runs to refresh the existing report with the latest scan_job + metadata.
    existing_report = (
        Report.objects.filter(service_request=request_obj)
        .order_by("-generated_at", "-created_at")
        .first()
    )
    code_services = {
        ServiceRequest.SERVICE_CODE_SECRETS,
        ServiceRequest.SERVICE_DEPENDENCY,
        ServiceRequest.SERVICE_CODE_COMPLIANCE,
        ServiceRequest.SERVICE_CODE_COMPLIANCE_PYTHON,
        ServiceRequest.SERVICE_CODE_COMPLIANCE_HTML,
        ServiceRequest.SERVICE_CODE_COMPLIANCE_CSS,
        ServiceRequest.SERVICE_CODE_COMPLIANCE_JAVASCRIPT,
        ServiceRequest.SERVICE_CODE_COMPLIANCE_REACT,
    }
    if request_obj.service_type in code_services:
        scope = Report.SCOPE_CODE
    elif request_obj.service_type in {
        ServiceRequest.SERVICE_WEB,
        ServiceRequest.SERVICE_API,
    }:
        scope = Report.SCOPE_WEB
    elif request_obj.service_type == ServiceRequest.SERVICE_CLOUD:
        scope = Report.SCOPE_CLOUD
    else:
        scope = Report.SCOPE_NETWORK
    summary = (
        f"Automated {scope} scan completed. "
        f"Findings: critical {severity_summary.get('critical', 0)}, "
        f"high {severity_summary.get('high', 0)}, "
        f"moderate {severity_summary.get('moderate', 0)}, "
        f"low {severity_summary.get('low', 0)}."
    )
    report_metadata = {
        "severity_summary": severity_summary,
        **(metadata or {}),
    }
    # Posture score is derived and stored for historical trend views.
    try:
        report_metadata["posture"] = posture_payload(
            compute_posture_score(severity_counts=severity_summary, metadata=report_metadata)
        )
    except Exception:
        # Never block report creation on scoring.
        report_metadata["posture"] = {}

    # Store "excellent report" insights for UI + PDFs (threat model, exploit chains, maturity).
    # These are heuristic summaries derived from recorded findings (no exploitation).
    try:
        raw_findings: list[dict] = []
        for f in CodeFinding.objects.filter(scan_job=job):
            raw_findings.append(
                {
                    "type": "code",
                    "title": f.title,
                    "severity": f.severity,
                    "standard_mapping": f.standard_mapping or [],
                    "evidence": {"category": f.category, "file_path": f.file_path, "line_number": f.line_number},
                }
            )
        for f in NetworkFinding.objects.filter(scan_job=job):
            ev = f.evidence or {}
            raw_findings.append(
                {
                    "type": "network",
                    "title": f.summary,
                    "severity": f.severity,
                    "standard_mapping": [],
                    "validation_type": ev.get("validation_type"),
                    "evidence": ev,
                }
            )
        for f in CloudFinding.objects.filter(scan_job=job):
            raw_findings.append(
                {
                    "type": "cloud",
                    "title": f.title,
                    "severity": f.severity,
                    "standard_mapping": f.compliance or [],
                    "evidence": f.evidence or {},
                }
            )

        report_metadata["threat_model"] = compute_threat_model_snapshot(
            findings=raw_findings, metadata=report_metadata, service_type=request_obj.service_type
        )
        report_metadata["exploit_chains"] = compute_exploit_chains(findings=raw_findings)
        report_metadata["maturity"] = compute_security_maturity(findings=raw_findings, metadata=report_metadata)
    except Exception:
        report_metadata.setdefault("threat_model", {})
        report_metadata.setdefault("exploit_chains", [])
        report_metadata.setdefault("maturity", {})
    if request_obj.cloud_account:
        report_metadata["cloud_account_id"] = str(request_obj.cloud_account_id)
        report_metadata["cloud_account_name"] = request_obj.cloud_account.name
        report_metadata["cloud_provider"] = request_obj.cloud_account.provider

    if existing_report:
        existing_report.organization = request_obj.organization
        existing_report.scope = scope
        existing_report.summary = summary
        existing_report.generated_at = timezone.now()
        existing_report.file_path = f"reports/{request_obj.id}.pdf"
        existing_report.metadata = report_metadata
        existing_report.client_visible = False
        existing_report.scan_job = job
        existing_report.save(
            update_fields=[
                "organization",
                "scope",
                "summary",
                "generated_at",
                "file_path",
                "metadata",
                "client_visible",
                "scan_job",
                "updated_at",
            ]
        )
        return existing_report

    return Report.objects.create(
        organization=request_obj.organization,
        scope=scope,
        summary=summary,
        generated_at=timezone.now(),
        file_path=f"reports/{request_obj.id}.pdf",
        metadata=report_metadata,
        client_visible=False,
        service_request=request_obj,
        scan_job=job,
    )


def _create_secret_findings(repository: CodeRepository, request_obj: ServiceRequest, job: ScanJob):
    repo_path = _resolve_repo_snapshot_path(request_obj, repository)
    findings = scan_repository(repo_path) if repo_path else []
    for finding in findings:
        CodeFinding.objects.get_or_create(
            repository=repository,
            category=CodeFinding.CATEGORY_SECRETS,
            title=finding.secret_type,
            service_request=request_obj,
            scan_job=job,
            defaults={
                "severity": finding.severity,
                "description": (
                    "Potential secret detected during repository scan. "
                    f"File: {finding.file_path}, Line: {finding.line_number}."
                ),
                "remediation": finding.remediation,
                "standard_mapping": finding.standard_mapping,
                "secret_type": finding.secret_type,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "masked_value": finding.masked_value,
                "confidence_score": finding.confidence_score,
                "rationale": finding.rationale,
            },
        )


def _resolve_repo_snapshot_path(request_obj: ServiceRequest, repository: CodeRepository) -> str | None:
    candidate = (request_obj.repository_url or "").strip()
    if candidate.startswith("file://"):
        candidate = candidate[7:]
    if candidate and (os.path.isdir(candidate) or os.path.isfile(candidate)):
        return candidate

    if request_obj.repository_url and request_obj.repository_url.startswith(("http://", "https://")):
        snapshot = ensure_repo_snapshot(request_obj.repository_url)
        if snapshot:
            return snapshot.snapshot_path

    base_dir = os.getenv("AEGIS_REPO_SNAPSHOT_DIR", "/app/repo_snapshots")
    if not base_dir:
        return None
    slug = hashlib.sha256(repository.repo_url.encode("utf-8")).hexdigest()[:16]
    for suffix in ("", ".zip"):
        path = os.path.join(base_dir, f"{slug}{suffix}")
        if os.path.exists(path):
            return path
    return None


def _create_dependency_findings(repository: CodeRepository, request_obj: ServiceRequest, job: ScanJob):
    repo_path = _resolve_repo_snapshot_path(request_obj, repository)
    findings = scan_dependencies(repo_path) if repo_path else []
    for finding in findings:
        CodeFinding.objects.get_or_create(
            repository=repository,
            category=CodeFinding.CATEGORY_DEPENDENCY,
            title=f"{finding.cve_id} {finding.dependency_name}",
            service_request=request_obj,
            scan_job=job,
            defaults={
                "severity": finding.severity,
                "description": (
                    f"{finding.description} "
                    f"Affected files: {', '.join(finding.affected_files)}. "
                    f"Detected version: {finding.detected_version}."
                ),
                "remediation": f"Upgrade to {finding.remediation_version}.",
                "standard_mapping": finding.compliance_mapping,
                "cvss_vector": (finding.cvss_vector or ""),
            },
        )


def _create_cloud_findings(account: CloudAccount, request_obj: ServiceRequest, job: ScanJob):
    results = scan_cloud_account(account)
    for finding in results:
        CloudFinding.objects.create(
            organization=request_obj.organization,
            cloud_account=account,
            asset=job.asset,
            scan_job=job,
            service_request=request_obj,
            title=finding.title,
            severity=finding.severity,
            description=finding.description,
            remediation=finding.remediation,
            evidence=finding.evidence,
            compliance=finding.compliance,
        )


def _create_risk_findings(repository: CodeRepository, request_obj: ServiceRequest, job: ScanJob):
    repo_path = _resolve_repo_snapshot_path(request_obj, repository)
    findings = scan_code_risks(repo_path) if repo_path else []
    for finding in findings:
        CodeFinding.objects.get_or_create(
            repository=repository,
            category=CodeFinding.CATEGORY_SAST,
            title=finding.title,
            service_request=request_obj,
            scan_job=job,
            file_path=finding.file_path,
            line_number=finding.line_number,
            defaults={
                "severity": finding.severity,
                "description": finding.description,
                "remediation": finding.remediation,
                "standard_mapping": finding.standard_mapping,
                "confidence_score": finding.confidence_score,
                "rationale": finding.rationale,
            },
        )


def _compliance_languages(service_type: str | None) -> list[str] | None:
    mapping = {
        ServiceRequest.SERVICE_CODE_COMPLIANCE_PYTHON: ["python"],
        ServiceRequest.SERVICE_CODE_COMPLIANCE_HTML: ["html"],
        ServiceRequest.SERVICE_CODE_COMPLIANCE_CSS: ["css"],
        ServiceRequest.SERVICE_CODE_COMPLIANCE_JAVASCRIPT: ["javascript"],
        ServiceRequest.SERVICE_CODE_COMPLIANCE_REACT: ["react"],
    }
    return mapping.get(service_type)


def _create_compliance_findings(repository: CodeRepository, request_obj: ServiceRequest, job: ScanJob):
    repo_path = _resolve_repo_snapshot_path(request_obj, repository)
    if not repo_path:
        return {"metrics": {}, "files_scanned": 0, "files_changed": 0}

    baseline = (
        CodeRepositorySnapshot.objects.filter(
            repository=repository,
            service_type=request_obj.service_type,
        )
        .order_by("-created_at")
        .first()
    )
    result = scan_compliance(
        repo_path,
        baseline_hashes=baseline.file_hashes if baseline else None,
        languages=_compliance_languages(request_obj.service_type),
    )
    for finding in result.findings:
        CodeFinding.objects.get_or_create(
            repository=repository,
            category=CodeFinding.CATEGORY_SAST,
            title=f"{finding.rule_id}: {finding.title}",
            service_request=request_obj,
            scan_job=job,
            defaults={
                "severity": finding.severity,
                "description": finding.description,
                "remediation": finding.remediation,
                "standard_mapping": finding.standard_mapping,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "confidence_score": finding.confidence_score,
                "rationale": finding.rationale,
            },
        )

    CodeRepositorySnapshot.objects.create(
        repository=repository,
        service_type=request_obj.service_type,
        file_hashes=result.file_hashes,
        files_scanned=result.files_scanned,
        files_changed=result.files_changed,
    )
    return {
        "metrics": result.metrics,
        "files_scanned": result.files_scanned,
        "files_changed": result.files_changed,
    }


def _severity_summary_for_code(repository: CodeRepository, job: ScanJob | None = None) -> dict:
    summary = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    queryset = CodeFinding.objects.filter(repository=repository)
    if job:
        queryset = queryset.filter(scan_job=job)
    for severity in queryset.values_list("severity", flat=True):
        summary[severity] = summary.get(severity, 0) + 1
    return summary


def _severity_summary_for_network(network_asset: NetworkAsset, job: ScanJob | None = None) -> dict:
    summary = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    queryset = NetworkFinding.objects.filter(network_asset=network_asset)
    if job:
        queryset = queryset.filter(scan_job=job)
    for severity in queryset.values_list("severity", flat=True):
        summary[severity] = summary.get(severity, 0) + 1
    return summary


def _severity_summary_for_cloud(account: CloudAccount, job: ScanJob | None = None) -> dict:
    summary = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    queryset = CloudFinding.objects.filter(cloud_account=account)
    if job:
        queryset = queryset.filter(scan_job=job)
    for severity in queryset.values_list("severity", flat=True):
        summary[severity] = summary.get(severity, 0) + 1
    return summary


def _create_network_findings(network_asset: NetworkAsset, request_obj: ServiceRequest, job: ScanJob, scanner_fn=scan_network_asset):
    target = request_obj.domain_url or request_obj.ip_cidr or network_asset.asset.identifier
    scope = request_obj.scope
    scan_result = scanner_fn(target, scope)
    findings = scan_result.findings
    type_map = {
        "exposed_service": NetworkFinding.TYPE_EXPOSED_SERVICE,
        "misconfiguration": NetworkFinding.TYPE_MISCONFIGURATION,
        "segmentation_risk": NetworkFinding.TYPE_SEGMENTATION_RISK,
    }
    for finding in findings:
        summary = finding.summary
        evidence_payload = finding.evidence_data or {
            "host": finding.host,
            "port": finding.port,
            "protocol": finding.protocol,
            "note": finding.evidence,
        }
        NetworkFinding.objects.create(
            network_asset=network_asset,
            finding_type=type_map.get(finding.issue_type, NetworkFinding.TYPE_MISCONFIGURATION),
            severity=finding.severity,
            confidence_score=finding.confidence_score,
            summary=summary,
            recommendation=finding.recommendation,
            rationale=finding.rationale or "",
            evidence=evidence_payload,
            cvss_vector=str((evidence_payload or {}).get("cvss_vector") or ""),
            service_request=request_obj,
            scan_job=job,
        )
    return {
        "hosts_scanned": scan_result.metrics.hosts_scanned,
        "hosts_alive": scan_result.metrics.hosts_alive,
        "open_ports": scan_result.metrics.open_ports,
        "ports_checked": scan_result.metrics.ports_checked,
        "environment_summary": scan_result.metrics.environment_summary,
        "os_summary": scan_result.metrics.os_summary,
    }


def _create_web_safety_findings(network_asset: NetworkAsset, request_obj: ServiceRequest, job: ScanJob):
    target = request_obj.domain_url or request_obj.ip_cidr or network_asset.asset.identifier
    scan_result = scan_web_security(target)
    for finding in scan_result.findings:
        evidence_payload = finding.evidence_data or {
            "host": finding.host,
            "port": finding.port,
            "protocol": finding.protocol,
        }
        NetworkFinding.objects.create(
            network_asset=network_asset,
            finding_type=NetworkFinding.TYPE_MISCONFIGURATION,
            severity=finding.severity,
            confidence_score=finding.confidence_score,
            summary=finding.summary,
            recommendation=finding.recommendation,
            rationale=finding.rationale or "",
            evidence=evidence_payload,
            cvss_vector=str((evidence_payload or {}).get("cvss_vector") or ""),
            service_request=request_obj,
            scan_job=job,
        )
    return {
        "hosts_scanned": scan_result.metrics.hosts_scanned,
        "hosts_alive": scan_result.metrics.hosts_alive,
        "open_ports": scan_result.metrics.open_ports,
        "ports_checked": scan_result.metrics.ports_checked,
        "environment_summary": scan_result.metrics.environment_summary,
        "os_summary": scan_result.metrics.os_summary,
    }


def _create_active_validation_findings(network_asset: NetworkAsset, request_obj: ServiceRequest, job: ScanJob):
    target = request_obj.domain_url or request_obj.ip_cidr or network_asset.asset.identifier
    mode = "api" if request_obj.service_type == ServiceRequest.SERVICE_API else "web"

    policy = OrganizationScanPolicy.objects.filter(organization=request_obj.organization).first()
    high_risk_requested = bool(request_obj.high_risk_ssrf and request_obj.ownership_confirmed)
    high_risk_allowed = bool(
        high_risk_requested
        and policy
        and policy.ssrf_high_risk_enabled
        and request_obj.service_type in {ServiceRequest.SERVICE_WEB, ServiceRequest.SERVICE_API}
    )
    allowlist = policy.ssrf_allowlist if (high_risk_allowed and policy) else None
    allow_metadata = bool(policy.ssrf_allow_metadata) if (high_risk_allowed and policy) else False

    findings, meta = validate_web_target_detailed(
        target,
        mode=mode,
        high_risk_ssrf=high_risk_allowed,
        ssrf_allowlist=allowlist,
        allow_metadata=allow_metadata,
    )

    attempts = meta.get("high_risk_ssrf_attempts") if isinstance(meta, dict) else None
    if isinstance(attempts, list) and attempts:
        # Log attempted probe URLs for auditability (truncate to avoid DB bloat).
        _log_activity(
            request_obj,
            "High-risk SSRF validation attempted",
            user=request_obj.approved_by,
            metadata={
                "service_request_id": str(request_obj.id),
                "scan_job_id": str(job.id),
                "authorization_reference": (request_obj.authorization_reference or "").strip(),
                "attempts": attempts[:20],
                "truncated": len(attempts) > 20,
            },
        )
    for finding in findings:
        NetworkFinding.objects.create(
            network_asset=network_asset,
            finding_type=NetworkFinding.TYPE_ACTIVE_VALIDATION,
            severity=finding.severity,
            confidence_score=70,
            summary=finding.summary,
            recommendation=finding.recommendation,
            rationale=f"{finding.rationale} Safe, non-destructive, no exploitation performed.",
            evidence={
                "validation_type": finding.validation_type,
                "tested_url": finding.tested_url,
                "status_code": finding.status_code,
                **(finding.evidence or {}),
            },
            cvss_vector=str((finding.evidence or {}).get("cvss_vector") or ""),
            service_request=request_obj,
            scan_job=job,
        )

    metrics = {"validations_run": len(findings)}
    if isinstance(meta, dict):
        used = meta.get("validation_requests_used")
        budget = meta.get("validation_requests_budget")
        if used is not None:
            try:
                metrics["validation_requests_used"] = int(used)
            except Exception:
                pass
        if budget is not None:
            try:
                metrics["validation_requests_budget"] = int(budget)
            except Exception:
                pass
        attempts = meta.get("high_risk_ssrf_attempts")
        if isinstance(attempts, list):
            metrics["high_risk_ssrf_attempts"] = len(attempts)
        blocked_reason = meta.get("high_risk_ssrf_blocked_reason")
        if isinstance(blocked_reason, str) and blocked_reason:
            metrics["high_risk_ssrf_blocked_reason"] = blocked_reason

    return metrics


def _merge_metrics(primary: dict, secondary: dict | None) -> dict:
    if not secondary:
        return primary
    merged = dict(primary)
    for key in ("hosts_scanned", "hosts_alive", "open_ports", "ports_checked"):
        merged[key] = int(primary.get(key, 0)) + int(secondary.get(key, 0))
    for key in ("environment_summary", "os_summary"):
        combined = dict(primary.get(key, {}) or {})
        for item_key, value in (secondary.get(key, {}) or {}).items():
            combined[item_key] = combined.get(item_key, 0) + int(value)
        merged[key] = combined
    return merged


@shared_task(bind=True, max_retries=2, default_retry_delay=5)
def execute_service_request_job(self, scan_job_id: str):
    job = (
        ScanJob.objects.filter(id=scan_job_id)
        .select_related("service_request", "repository", "asset", "organization", "cloud_account")
        .first()
    )
    if not job or not job.service_request:
        return

    request_obj = job.service_request
    job.status = ScanJob.STATUS_RUNNING
    job.started_at = timezone.now()
    job.failure_reason = ""
    job.save(update_fields=["status", "started_at", "failure_reason"])

    request_obj.status = ServiceRequest.STATUS_RUNNING
    request_obj.save(update_fields=["status"])
    _log_job_step(
        request_obj,
        job,
        "Service request running",
        detail=(
            f"service={request_obj.service_type} "
            f"target={request_obj.domain_url or request_obj.ip_cidr or request_obj.repository_url or (request_obj.asset.identifier if request_obj.asset else '-')}"
        ),
    )

    time.sleep(2)

    try:
        code_compliance_types = {
            ServiceRequest.SERVICE_CODE_COMPLIANCE,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_PYTHON,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_HTML,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_CSS,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_JAVASCRIPT,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_REACT,
        }
        if request_obj.service_type in {
            ServiceRequest.SERVICE_CODE_SECRETS,
            ServiceRequest.SERVICE_DEPENDENCY,
            *code_compliance_types,
        }:
            _log_job_step(request_obj, job, "Code scan pipeline started", detail="Resolving repository and snapshot")
            asset, repository = _resolve_repository(request_obj)
            _log_job_step(
                request_obj,
                job,
                "Repository resolved",
                detail=f"repo={repository.repo_url} asset={asset.identifier}",
            )
            if job.asset_id != asset.id or job.repository_id != repository.id:
                job.asset = asset
                job.repository = repository
                job.save(update_fields=["asset", "repository"])
            if request_obj.service_type == ServiceRequest.SERVICE_CODE_SECRETS:
                _log_job_step(request_obj, job, "Secrets scan started")
                _create_secret_findings(repository, request_obj, job)
                secrets_count = CodeFinding.objects.filter(repository=repository, scan_job=job, category=CodeFinding.CATEGORY_SECRETS).count()
                _log_job_step(request_obj, job, "Secrets scan completed", detail=f"findings={secrets_count}", level="ok")
            if request_obj.service_type == ServiceRequest.SERVICE_DEPENDENCY:
                _log_job_step(request_obj, job, "Dependency scan started")
                _create_dependency_findings(repository, request_obj, job)
                dep_count = CodeFinding.objects.filter(repository=repository, scan_job=job, category=CodeFinding.CATEGORY_DEPENDENCY).count()
                _log_job_step(request_obj, job, "Dependency scan completed", detail=f"findings={dep_count}", level="ok")
            _log_job_step(request_obj, job, "Code risk scan started")
            _create_risk_findings(repository, request_obj, job)
            risk_count = CodeFinding.objects.filter(repository=repository, scan_job=job, category=CodeFinding.CATEGORY_SAST).count()
            _log_job_step(request_obj, job, "Code risk scan completed", detail=f"findings={risk_count}", level="ok")
            compliance_metrics = {}
            if request_obj.service_type in code_compliance_types:
                _log_job_step(request_obj, job, "Compliance scan started")
                compliance_metrics = _create_compliance_findings(repository, request_obj, job)
                _log_job_step(
                    request_obj,
                    job,
                    "Compliance scan completed",
                    detail=(
                        f"files_scanned={compliance_metrics.get('files_scanned', 0)} "
                        f"files_changed={compliance_metrics.get('files_changed', 0)}"
                    ),
                    level="ok",
                )
            summary = _severity_summary_for_code(repository, job=job)
            metadata = {"compliance": compliance_metrics} if compliance_metrics else {}
            _log_job_step(request_obj, job, "Code severity summary computed", detail=str(summary))
            _create_scan_record(job, Scan.TYPE_CODE, summary, metadata=metadata)
            _create_report(request_obj, job, summary, metadata=metadata)
            _log_job_step(request_obj, job, "Code report generated", level="ok")

        elif request_obj.service_type in {
            ServiceRequest.SERVICE_NETWORK,
            ServiceRequest.SERVICE_WEB,
            ServiceRequest.SERVICE_API,
            ServiceRequest.SERVICE_INFRA,
        }:
            _log_job_step(request_obj, job, "Network scan pipeline started", detail="Resolving network target")
            asset, network_asset = _resolve_network_asset(request_obj)
            target = request_obj.domain_url or request_obj.ip_cidr or network_asset.asset.identifier
            _log_job_step(request_obj, job, "Network target resolved", detail=f"target={target} scope={request_obj.scope or 'auto'}")
            if job.asset_id != asset.id:
                job.asset = asset
                job.save(update_fields=["asset"])
            if request_obj.service_type == ServiceRequest.SERVICE_WEB:
                _log_job_step(request_obj, job, "Web exposure port scan started")
                port_metrics = _create_network_findings(network_asset, request_obj, job, scanner_fn=scan_web_target)
                _log_job_step(request_obj, job, "Web exposure port scan completed", detail=str(port_metrics), level="ok")
                _log_job_step(request_obj, job, "Web safety header scan started")
                header_metrics = _create_web_safety_findings(network_asset, request_obj, job)
                _log_job_step(request_obj, job, "Web safety header scan completed", detail=str(header_metrics), level="ok")
                _log_job_step(request_obj, job, "Active validation started")
                validation_metrics = _create_active_validation_findings(network_asset, request_obj, job)
                _log_job_step(request_obj, job, "Active validation completed", detail=str(validation_metrics), level="ok")
                metrics = _merge_metrics(port_metrics, header_metrics)
                metrics.update(validation_metrics)
                scan_type = Scan.TYPE_WEB
            elif request_obj.service_type == ServiceRequest.SERVICE_API:
                _log_job_step(request_obj, job, "API baseline scan started")
                port_metrics = _create_network_findings(network_asset, request_obj, job, scanner_fn=scan_api_target)
                _log_job_step(request_obj, job, "API baseline scan completed", detail=str(port_metrics), level="ok")
                _log_job_step(request_obj, job, "API safety header scan started")
                header_metrics = _create_web_safety_findings(network_asset, request_obj, job)
                _log_job_step(request_obj, job, "API safety header scan completed", detail=str(header_metrics), level="ok")
                _log_job_step(request_obj, job, "API active validation started")
                validation_metrics = _create_active_validation_findings(network_asset, request_obj, job)
                _log_job_step(request_obj, job, "API active validation completed", detail=str(validation_metrics), level="ok")
                metrics = _merge_metrics(port_metrics, header_metrics)
                metrics.update(validation_metrics)
                scan_type = Scan.TYPE_API
            elif request_obj.service_type == ServiceRequest.SERVICE_INFRA:
                _log_job_step(request_obj, job, "Infrastructure scan started")
                metrics = _create_network_findings(network_asset, request_obj, job, scanner_fn=scan_infra_target)
                _log_job_step(request_obj, job, "Infrastructure scan completed", detail=str(metrics), level="ok")
                scan_type = Scan.TYPE_INFRA
            else:
                _log_job_step(request_obj, job, "Network configuration scan started")
                metrics = _create_network_findings(network_asset, request_obj, job, scanner_fn=scan_network_asset)
                _log_job_step(request_obj, job, "Network configuration scan completed", detail=str(metrics), level="ok")
                scan_type = Scan.TYPE_NETWORK
            summary = _severity_summary_for_network(network_asset, job=job)
            _log_job_step(request_obj, job, "Network severity summary computed", detail=str(summary))
            _create_scan_record(job, scan_type, summary, metadata=metrics)
            _create_report(request_obj, job, summary, metadata=metrics)
            _log_job_step(request_obj, job, "Network report generated", level="ok")

        elif request_obj.service_type == ServiceRequest.SERVICE_CLOUD:
            _log_job_step(request_obj, job, "Cloud scan pipeline started", detail="Resolving cloud account")
            asset, account = _resolve_cloud_asset(request_obj)
            if account and job.cloud_account_id != account.id:
                job.cloud_account = account
            if asset and job.asset_id != asset.id:
                job.asset = asset
            job.save(update_fields=["asset", "cloud_account"])

            if account:
                _log_job_step(
                    request_obj,
                    job,
                    "Cloud account resolved",
                    detail=f"provider={account.provider} account={account.name}",
                )
                _log_job_step(request_obj, job, "Cloud posture scan started")
                _create_cloud_findings(account, request_obj, job)
                summary = _severity_summary_for_cloud(account, job=job)
                finding_count = CloudFinding.objects.filter(scan_job=job).count()
                _log_job_step(request_obj, job, "Cloud posture scan completed", detail=f"findings={finding_count}", level="ok")
            else:
                summary = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
            metadata = {"provider": account.provider if account else "", "account_name": account.name if account else ""}
            _log_job_step(request_obj, job, "Cloud severity summary computed", detail=str(summary))
            _create_scan_record(job, Scan.TYPE_CLOUD, summary, metadata=metadata)
            _create_report(request_obj, job, summary, metadata=metadata)
            _log_job_step(request_obj, job, "Cloud report generated", level="ok")

        job.status = ScanJob.STATUS_COMPLETED
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "completed_at"])

        request_obj.status = ServiceRequest.STATUS_COMPLETED
        request_obj.save(update_fields=["status"])
        _log_job_step(request_obj, job, "Service request completed", level="ok")
        ScanAlert.objects.create(
            organization=request_obj.organization,
            user=request_obj.requested_by,
            severity=ScanAlert.SEVERITY_INFO,
            title="Scan completed",
            message="Your scan completed. A report is ready for review.",
            link="/dashboard/reports",
            metadata={"service_request_id": str(request_obj.id), "scan_job_id": str(job.id)},
        )
    except Exception as exc:
        if _is_retriable_error(exc):
            try:
                job.status = ScanJob.STATUS_QUEUED
                job.failure_reason = f"Transient error: {exc}"
                job.save(update_fields=["status", "failure_reason"])
                request_obj.status = ServiceRequest.STATUS_APPROVED
                request_obj.save(update_fields=["status"])
                _log_job_step(request_obj, job, "Service request retry scheduled", detail=f"error={exc}", level="warn")
                raise self.retry(exc=exc)
            except MaxRetriesExceededError:
                pass

        job.status = ScanJob.STATUS_FAILED
        job.failure_reason = str(exc)
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "completed_at", "failure_reason"])
        request_obj.status = ServiceRequest.STATUS_FAILED
        request_obj.save(update_fields=["status"])
        _log_job_step(request_obj, job, "Service request failed", detail=str(exc), level="err")
        ScanAlert.objects.create(
            organization=request_obj.organization,
            user=request_obj.requested_by,
            severity=ScanAlert.SEVERITY_WARNING,
            title="Scan failed",
            message="The scan failed during execution. The platform team has been notified.",
            link="/dashboard/requests",
            metadata={"service_request_id": str(request_obj.id), "error": str(exc)},
        )
        raise
