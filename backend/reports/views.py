import io
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from urllib.parse import urlparse

from django.http import HttpResponse
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated

from accounts.models import UserOrganization
from code_security.models import CodeFinding
from core.models import OrganizationQuerySetMixin
from core.ai_explanations import (
    explain_code_finding,
    explain_network_finding,
    explain_cloud_finding,
    explain_report_summary,
)
from core.permissions import OrganizationAccessPermission
from network_security.models import NetworkFinding
from cloud_security.models import CloudFinding
from service_requests.models import ServiceRequest

from .models import Report
from .serializers import ReportSerializer
from core.cvss import CvssError, score_cvss3
from core.posture import compute_posture_score
from core.insights import compute_exploit_chains, compute_security_maturity, compute_threat_model_snapshot


class ReportViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD, UserOrganization.ROLE_EXECUTIVE]
    organization_field = "organization"

    def get_queryset(self):
        queryset = self.filter_by_organization(Report.objects.all(), self.request.user).order_by("-generated_at", "-created_at")
        user = self.request.user
        if not (user.is_staff or user.is_superuser):
            queryset = queryset.filter(client_visible=True)
        scan_job_id = self.request.query_params.get("scan_job")
        if scan_job_id:
            queryset = queryset.filter(scan_job_id=scan_job_id)
        service_request_id = self.request.query_params.get("service_request")
        if service_request_id:
            queryset = queryset.filter(service_request_id=service_request_id)
        return queryset

    @action(detail=True, methods=["get"])
    def download(self, request, pk=None):
        report = self.get_object()
        pdf_bytes = build_report_pdf(report)
        filename = f"aegis-report-{report.id}.pdf"
        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @action(detail=True, methods=["get"])
    def appendix(self, request, pk=None):
        report = self.get_object()
        bundle_bytes = build_report_appendix_bundle(report)
        filename = f"aegis-report-{report.id}-appendix.zip"
        response = HttpResponse(bundle_bytes, content_type="application/zip")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _report_role_hint(service_request):
    if not service_request:
        return "security_lead"
    role = getattr(service_request, "requested_role", None)
    if role == UserOrganization.ROLE_EXECUTIVE:
        return "executive"
    if role == UserOrganization.ROLE_DEVELOPER:
        return "developer"
    return "security_lead"


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _estimated_cvss_score(item: dict) -> float:
    """
    CVSS scoring requires a full vector. We provide a conservative estimate so reports can include a CVSS-like score.
    """
    severity = (item.get("severity") or "low").lower()
    base = {"critical": 9.4, "high": 8.0, "moderate": 5.6, "low": 3.1}.get(severity, 3.1)
    evidence = item.get("evidence") or {}
    issue_type = (item.get("issue_type") or item.get("type") or "").lower()
    # Nudge upward for direct exposure / confirmed reachability.
    if issue_type in {"exposed_service", "segmentation_risk"}:
        base = min(10.0, base + 0.4)
    if evidence.get("host") and evidence.get("port") and issue_type in {"network", "exposed_service"}:
        base = min(10.0, base + 0.2)
    # Nudge upward for mapped CVEs.
    if evidence.get("cve"):
        base = min(10.0, base + 0.3)
    return round(base, 1)


def _impact_likelihood(item: dict) -> tuple[str, str]:
    severity = (item.get("severity") or "low").lower()
    confidence = item.get("confidence_score")
    evidence = item.get("evidence") or {}

    impact = "Low"
    if severity in {"critical", "high"}:
        impact = "High"
    elif severity == "moderate":
        impact = "Medium"

    likelihood = "Medium"
    if isinstance(confidence, int):
        if confidence >= 80:
            likelihood = "High"
        elif confidence <= 50:
            likelihood = "Low"
    else:
        # Fallback: treat confirmed reachability as higher likelihood.
        if evidence.get("host") and evidence.get("port"):
            likelihood = "High" if severity in {"critical", "high"} else "Medium"
    return impact, likelihood


def _priority_from_matrix(impact: str, likelihood: str) -> str:
    matrix = {
        ("High", "High"): "Critical",
        ("High", "Medium"): "High",
        ("High", "Low"): "High",
        ("Medium", "High"): "High",
        ("Medium", "Medium"): "Medium",
        ("Medium", "Low"): "Medium",
        ("Low", "High"): "Medium",
        ("Low", "Medium"): "Low",
        ("Low", "Low"): "Low",
    }
    return matrix.get((impact, likelihood), "Low")


def _references_for_item(item: dict) -> list[str]:
    refs: list[str] = []
    evidence = item.get("evidence") or {}
    cve = evidence.get("cve")
    if isinstance(cve, str) and "CVE-" in cve:
        # Keep as plain text; PDF isn't a rich link surface in our minimal generator.
        for token in cve.replace(",", " ").replace("/", " ").split():
            token = token.strip()
            if token.startswith("CVE-"):
                refs.append(f"NVD: {token}")
    mapping = item.get("standard_mapping") or []
    if isinstance(mapping, list) and mapping:
        refs.extend([str(m) for m in mapping[:4]])
    if not refs:
        refs.append("OWASP Top 10")
    return refs[:6]


def _reproduction_steps(item: dict) -> list[str]:
    evidence = item.get("evidence") or {}
    kind = (item.get("type") or "").lower()
    steps: list[str] = []
    if kind == "network":
        host = evidence.get("host")
        port = evidence.get("port")
        if host and port:
            steps.append(f"Attempt TCP connect to {host}:{port}.")
        else:
            steps.append("Validate service exposure using a TCP connect to the reported host/port.")
    elif kind == "code":
        file_path = evidence.get("file_path")
        line = evidence.get("line_number")
        if file_path:
            steps.append(f"Open {file_path} and review the flagged pattern (line {line or 'n/a'}).")
        steps.append("Confirm whether user input can reach the sink without validation/encoding.")
    elif kind == "cloud":
        steps.append("Review the referenced cloud resource configuration in your control plane.")
        steps.append("Validate whether the setting is required and apply least-privilege defaults.")
    else:
        steps.append("Re-test the target endpoint and confirm the behavior described in evidence.")
    return steps


def _enrich_findings(findings: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    for item in findings:
        evidence = item.get("evidence") or {}
        cvss_vector = (item.get("cvss_vector") or evidence.get("cvss_vector") or "").strip()
        cvss_is_estimated = True
        cvss_score = _estimated_cvss_score(item)
        if cvss_vector:
            try:
                cvss_score = score_cvss3(cvss_vector).base_score
                cvss_is_estimated = False
            except CvssError:
                # Keep estimated score but preserve the vector for appendix review.
                cvss_is_estimated = True

        impact, likelihood = _impact_likelihood(item)
        enriched.append(
            {
                **item,
                "cvss_vector": cvss_vector,
                "cvss_score": cvss_score,
                "cvss_is_estimated": cvss_is_estimated,
                "impact": impact,
                "likelihood": likelihood,
                "priority": _priority_from_matrix(impact, likelihood),
                "references": _references_for_item(item),
                "reproduction_steps": _reproduction_steps(item),
            }
        )
    return enriched


def build_report_appendix_bundle(report: Report) -> bytes:
    """
    Returns an in-memory ZIP bundle containing raw findings and scan metadata.
    Intended to supplement the 2-3 page executive PDF with engineer-grade details.
    """
    organization = report.organization
    service_request = report.service_request
    scan_job = report.scan_job
    metadata = report.metadata or {}

    role_hint = _report_role_hint(service_request)
    findings = _collect_findings(report, role_hint=role_hint)
    findings = _enrich_findings(findings)

    severity_counts = _severity_counts_for_report(report)
    posture = _posture_for_report(report, severity_counts, metadata)
    scope_lines = _derive_scope_lines(service_request)
    methodology_lines = _methodology_lines(report.scope, service_request.service_type if service_request else None)

    manifest = {
        "generated_at": _now_utc_iso(),
        "report_id": str(report.id),
        "organization": {"id": str(organization.id), "name": organization.name},
        "scope": report.scope,
        "scan_job_id": str(scan_job.id) if scan_job else None,
        "service_request_id": str(service_request.id) if service_request else None,
        "severity_summary": severity_counts,
        "notes": "This appendix bundle contains raw scan outputs and evidence fields captured during safe scanning.",
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        zf.writestr("scan_metadata.json", json.dumps(metadata, indent=2, sort_keys=True, default=str))
        zf.writestr("scope.txt", "\n".join(scope_lines) + "\n")
        zf.writestr("methodology.txt", "\n".join(methodology_lines) + "\n")
        zf.writestr("findings.json", json.dumps(findings, indent=2, sort_keys=True, default=str))
        zf.writestr(
            "README.txt",
            "\n".join(
                [
                    "Aegis Report Appendix Bundle",
                    "",
                    "Files:",
                    "- manifest.json: bundle metadata",
                    "- scan_metadata.json: raw scan metadata stored on the report",
                    "- findings.json: findings with evidence, estimated CVSS, impact/likelihood, and references",
                    "- scope.txt / methodology.txt: report scope and methodology lines",
                    "",
                    "Notes:",
                    "- CVSS scores in findings.json are estimates unless a specific CVE mapping exists in evidence.",
                    "- Scans are safe and non-destructive; no exploitation is performed.",
                ]
            )
            + "\n",
        )
    return buf.getvalue()


def build_basic_report_pdf(report: Report) -> bytes:
    organization = report.organization
    service_request = report.service_request
    scan_job = report.scan_job
    metadata = report.metadata or {}

    scope_label = report.get_scope_display() if hasattr(report, "get_scope_display") else str(report.scope)
    service_label = service_request.get_service_type_display() if service_request else scope_label
    requested_by = service_request.requested_by.email if service_request and service_request.requested_by else "Platform Admin"
    requested_role = service_request.get_requested_role_display() if service_request else "Platform Admin"
    scan_id = scan_job.id if scan_job else report.id
    scan_start = scan_job.started_at if scan_job and scan_job.started_at else report.generated_at
    scan_end = scan_job.completed_at if scan_job and scan_job.completed_at else report.generated_at

    role_hint = _report_role_hint(service_request)
    findings: list[dict] = []
    if report.scope in {Report.SCOPE_CODE, Report.SCOPE_COMBINED}:
        code_qs = CodeFinding.objects.filter(scan_job=scan_job) if scan_job else CodeFinding.objects.none()
        for finding in code_qs:
            cve_token = ""
            try:
                import re as _re

                match = _re.search(r"(CVE-\d{4}-\d+)", finding.title or "")
                if match:
                    cve_token = match.group(1)
            except Exception:
                cve_token = ""
            findings.append(
                {
                    "type": "code",
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "recommendation": finding.remediation,
                    "standard_mapping": finding.standard_mapping,
                    "asset": getattr(finding.repository, "repo_url", "Unknown repository"),
                    "ai_explanation": explain_code_finding(finding, role_hint),
                    "cvss_vector": getattr(finding, "cvss_vector", "") or "",
                    "evidence": {
                        "cve": cve_token,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "masked_value": finding.masked_value,
                        "secret_type": finding.secret_type,
                        "category": finding.category,
                    },
                }
            )

    if report.scope in {Report.SCOPE_NETWORK, Report.SCOPE_COMBINED, Report.SCOPE_WEB}:
        network_qs = NetworkFinding.objects.filter(scan_job=scan_job) if scan_job else NetworkFinding.objects.none()
        for finding in network_qs:
            asset_name = getattr(finding.network_asset.asset, "name", "Unknown asset") if finding.network_asset else "Unknown asset"
            network_type = finding.network_asset.network_type if finding.network_asset else ""
            findings.append(
                {
                    "type": "network",
                    "title": finding.summary,
                    "severity": finding.severity,
                    "description": finding.summary,
                    "recommendation": finding.recommendation,
                    "standard_mapping": [],
                    "asset": f"{asset_name} ({network_type})" if network_type else asset_name,
                    "ai_explanation": explain_network_finding(finding, role_hint),
                    "cvss_vector": getattr(finding, "cvss_vector", "") or "",
                    "evidence": finding.evidence or {},
                }
            )
    if report.scope == Report.SCOPE_CLOUD:
        cloud_qs = CloudFinding.objects.filter(scan_job=scan_job) if scan_job else CloudFinding.objects.none()
        for finding in cloud_qs:
            account = finding.cloud_account
            asset_name = getattr(account, "name", "Cloud account")
            provider = account.get_provider_display() if account else "Cloud"
            findings.append(
                {
                    "type": "cloud",
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "recommendation": finding.remediation,
                    "standard_mapping": finding.compliance or [],
                    "asset": f"{asset_name} ({provider})",
                    "ai_explanation": explain_cloud_finding(finding, role_hint),
                    "cvss_vector": getattr(finding, "cvss_vector", "") or "",
                    "evidence": finding.evidence or {},
                }
            )

    severity_map = {
        "critical": "Critical",
        "high": "High",
        "moderate": "Medium",
        "low": "Low",
    }
    severity_rank = {
        "critical": 4,
        "high": 3,
        "moderate": 2,
        "low": 1,
    }
    severity_counts = {key: 0 for key in severity_map}
    for finding in findings:
        severity = finding.get("severity", "low")
        if severity in severity_counts:
            severity_counts[severity] += 1

    if severity_counts["critical"] > 0:
        overall_risk = "Critical"
    elif severity_counts["high"] > 0:
        overall_risk = "High"
    elif severity_counts["moderate"] > 0:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    findings_sorted = sorted(findings, key=lambda item: severity_rank.get(item.get("severity", "low"), 0), reverse=True)
    key_risks = [item["title"] for item in findings_sorted[:3]]

    network_hosts = {item["evidence"].get("host") for item in findings_sorted if item["type"] == "network" and item["evidence"].get("host")}
    network_ports = {
        (item["evidence"].get("host"), item["evidence"].get("port"))
        for item in findings_sorted
        if item["type"] == "network" and item["evidence"].get("host") and item["evidence"].get("port")
    }
    hosts_identified = len(network_hosts) if network_hosts else int(metadata.get("hosts_alive") or metadata.get("hosts_scanned") or 0)
    ports_discovered = len(network_ports) if network_ports else int(metadata.get("open_ports") or 0)

    evidence_lines: list[str] = []
    for item in findings_sorted:
        if item["type"] == "code":
            evidence = item["evidence"]
            file_path = evidence.get("file_path")
            if file_path:
                line_no = evidence.get("line_number")
                masked = evidence.get("masked_value")
                evidence_lines.append(
                    f"Repo: {item['asset']} | File: {file_path} | Line: {line_no or 'n/a'} | Secret: {masked or 'masked'}"
                )
        elif item["type"] == "network":
            evidence = item["evidence"]
            host = evidence.get("host") or "unknown"
            port = evidence.get("port")
            service = evidence.get("service")
            version = evidence.get("version")
            cve = evidence.get("cve")
            service_label = f"{service} {version}".strip() if service else "service"
            port_label = f":{port}" if port else ""
            cve_label = f" | CVE: {cve}" if cve else ""
            os_guess = evidence.get("os_guess")
            environment = evidence.get("environment")
            os_label = f" | OS: {os_guess}" if os_guess else ""
            env_label = f" | Env: {environment}" if environment else ""
            evidence_lines.append(f"Host: {host}{port_label} | {service_label}{cve_label}{os_label}{env_label}")
        elif item["type"] == "cloud":
            evidence = item["evidence"]
            resource = evidence.get("resource") or evidence.get("control") or "Cloud control"
            account = item.get("asset", "Cloud account")
            evidence_lines.append(f"{account} | {resource}")

    title_map = {
        Report.SCOPE_NETWORK: "Network Security Assessment Report",
        Report.SCOPE_CODE: "Code Security Assessment Report",
        Report.SCOPE_WEB: "Web Security Assessment Report",
        Report.SCOPE_COMBINED: "Security Assessment Report",
        Report.SCOPE_CLOUD: "Cloud Security Posture Report",
    }
    title = title_map.get(report.scope, "Security Assessment Report")

    lines: list[dict] = []
    _add_line(lines, title, font="F2", size=16, spacing=20)
    _add_line(lines, "Confidential - Internal Use Only", font="F1", size=9, spacing=14)
    _add_blank(lines, 10)

    _add_line(lines, "1. Executive Summary", font="F2", size=12, spacing=16)
    _add_line(lines, f"Organization: {organization.name}", font="F1", size=10)
    _add_line(lines, f"Scan ID: {scan_id}", font="F1", size=10)
    _add_line(lines, f"Scan Type: {service_label}", font="F1", size=10)
    _add_line(lines, f"Scan Date: {scan_start:%Y-%m-%d %H:%M UTC} - {scan_end:%Y-%m-%d %H:%M UTC}", font="F1", size=10)
    _add_line(lines, f"Requested By: {requested_role} ({requested_by})", font="F1", size=10)
    _add_line(lines, f"Report Generated: {report.generated_at:%Y-%m-%d %H:%M UTC}", font="F1", size=10)
    _add_line(lines, f"Overall Risk Rating: {overall_risk}", font="F1", size=10)
    if hosts_identified:
        _add_line(lines, f"Total Hosts Identified: {hosts_identified}", font="F1", size=10)
    if ports_discovered:
        _add_line(lines, f"Total Open Ports Discovered: {ports_discovered}", font="F1", size=10)
    _add_blank(lines, 8)
    _add_paragraph(
        lines,
        f"This assessment evaluated the exposed security posture of {organization.name} to identify configuration weaknesses, exposed services, and potential attack paths.",
        max_chars=92,
    )
    if key_risks:
        _add_blank(lines, 6)
        _add_line(lines, "Key Risks Identified:", font="F2", size=11, spacing=14)
        for risk in key_risks:
            _add_paragraph(lines, f"- {risk}", max_chars=92)
    _add_blank(lines, 6)
    _add_line(lines, "Business Impact:", font="F2", size=11, spacing=14)
    summary_text = report.summary or explain_report_summary(report.scope, severity_counts)
    _add_paragraph(lines, summary_text, max_chars=92)

    _add_blank(lines, 10)
    _add_line(lines, "2. Scan Scope & Methodology", font="F2", size=12, spacing=16)
    _add_line(lines, "Scope:", font="F2", size=11, spacing=14)
    scope_lines = _derive_scope_lines(service_request)
    for scope_line in scope_lines:
        _add_paragraph(lines, f"- {scope_line}", max_chars=92)
    environment_summary = metadata.get("environment_summary") or {}
    if environment_summary:
        summary_text = ", ".join(f"{key}: {value}" for key, value in environment_summary.items())
        _add_paragraph(lines, f"- Environment summary: {summary_text}", max_chars=92)
    os_summary = metadata.get("os_summary") or {}
    if os_summary:
        summary_text = ", ".join(f"{key}: {value}" for key, value in os_summary.items())
        _add_paragraph(lines, f"- OS fingerprint summary: {summary_text}", max_chars=92)
    _add_blank(lines, 6)
    _add_line(lines, "Methodology:", font="F2", size=11, spacing=14)
    for line in _methodology_lines(report.scope, service_request.service_type if service_request else None):
        _add_paragraph(lines, f"- {line}", max_chars=92)
    _add_blank(lines, 6)
    _add_line(lines, "Limitations:", font="F2", size=11, spacing=14)
    for line in _limitations_lines():
        _add_paragraph(lines, f"- {line}", max_chars=92)

    _add_blank(lines, 10)
    _add_line(lines, "3. Findings Overview", font="F2", size=12, spacing=16)
    _add_line(
        lines,
        f"Critical: {severity_counts['critical']}  High: {severity_counts['high']}  Medium: {severity_counts['moderate']}  Low: {severity_counts['low']}",
        font="F1",
        size=10,
    )

    _add_blank(lines, 8)
    _add_line(lines, "4. Impact by Severity", font="F2", size=12, spacing=16)
    for line in _severity_impact_lines():
        _add_paragraph(lines, f"- {line}", max_chars=92)

    _add_blank(lines, 10)
    _add_line(lines, "5. Detailed Findings", font="F2", size=12, spacing=16)
    if not findings_sorted:
        _add_paragraph(lines, "No findings were recorded for this scan.", max_chars=92)
    else:
        max_findings = 10
        for idx, finding in enumerate(findings_sorted[:max_findings], start=1):
            severity_label = severity_map.get(finding.get("severity", "low"), "Low")
            _add_line(lines, f"Finding {idx}: {finding['title']}", font="F2", size=11, spacing=14)
            _add_line(lines, f"Severity: {severity_label}", font="F1", size=10)
            _add_line(lines, f"Affected Asset: {finding['asset']}", font="F1", size=10)
            _add_paragraph(lines, f"What was found: {finding['description']}", max_chars=92)
            ai_explanation = finding.get("ai_explanation") or _why_it_matters(finding)
            _add_paragraph(lines, f"AI guidance: {ai_explanation}", max_chars=92)
            remediation = finding.get("recommendation") or _default_remediation(finding)
            _add_paragraph(lines, f"Recommended remediation: {remediation}", max_chars=92)
            compliance = finding.get("standard_mapping") or []
            if compliance:
                _add_paragraph(lines, f"Compliance mapping: {', '.join(compliance)}", max_chars=92)
            _add_blank(lines, 6)
        if len(findings_sorted) > max_findings:
            _add_paragraph(lines, f"Additional findings omitted ({len(findings_sorted) - max_findings} more).", max_chars=92)

    _add_blank(lines, 10)
    _add_line(lines, "6. Risk Scenarios", font="F2", size=12, spacing=16)
    scenario_lines = _risk_scenarios(findings_sorted[:2])
    for line in scenario_lines:
        _add_paragraph(lines, f"- {line}", max_chars=92)

    _add_blank(lines, 10)
    _add_line(lines, "7. Remediation Roadmap", font="F2", size=12, spacing=16)
    for line in _remediation_roadmap(report.scope):
        _add_paragraph(lines, f"- {line}", max_chars=92)

    _add_blank(lines, 10)
    _add_line(lines, "8. Security Posture Trend", font="F2", size=12, spacing=16)
    trend_lines = _trend_lines(report, severity_counts)
    for line in trend_lines:
        _add_paragraph(lines, f"- {line}", max_chars=92)

    if evidence_lines:
        _add_blank(lines, 10)
        _add_line(lines, "9. Appendix - Technical Evidence", font="F2", size=12, spacing=16)
        for line in evidence_lines[:12]:
            _add_paragraph(lines, f"- {line}", max_chars=92)

    pages = _build_pages(lines)
    return _build_pdf_from_pages(pages)


def build_report_pdf(report: Report) -> bytes:
    return build_styled_report_pdf(report)


def _text_line(text: str, y: int, font: str = "F1", size: int = 10) -> str:
    return f"BT /{font} {size} Tf 72 {y} Td ({_escape_pdf_text(text)}) Tj ET"


def _wrap_text(text: str, max_chars: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for word in words:
        if length + len(word) + (1 if current else 0) > max_chars:
            lines.append(" ".join(current))
            current = [word]
            length = len(word)
        else:
            current.append(word)
            length += len(word) + (1 if current else 0)
    if current:
        lines.append(" ".join(current))
    return lines


def _add_line(lines: list[dict], text: str, font: str = "F1", size: int = 10, spacing: int | None = None) -> None:
    lines.append(
        {
            "text": text,
            "font": font,
            "size": size,
            "spacing": spacing or (size + 2),
        }
    )


def _add_blank(lines: list[dict], spacing: int = 10) -> None:
    lines.append({"text": None, "font": "F1", "size": 10, "spacing": spacing})


def _add_paragraph(lines: list[dict], text: str, font: str = "F1", size: int = 10, max_chars: int = 92) -> None:
    for line in _wrap_text(text, max_chars=max_chars):
        _add_line(lines, line, font=font, size=size)


def _build_pages(lines: list[dict]) -> list[bytes]:
    pages: list[bytes] = []
    current: list[str] = []
    y = 760
    for entry in lines:
        spacing = entry.get("spacing", 12)
        if y - spacing < 70:
            pages.append("\n".join(current).encode("utf-8"))
            current = []
            y = 760
        if entry.get("text") is not None:
            current.append(_text_line(entry["text"], y, font=entry["font"], size=entry["size"]))
        y -= spacing
    if current:
        pages.append("\n".join(current).encode("utf-8"))
    if not pages:
        pages.append(b"")
    return pages


def _build_pdf_from_pages(page_contents: list[bytes]) -> bytes:
    objects: list[bytes] = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    page_refs = []
    base_page_id = 3
    for idx in range(len(page_contents)):
        page_id = base_page_id + idx * 2
        page_refs.append(f"{page_id} 0 R".encode("ascii"))
    kids = b" ".join(page_refs)
    objects.append(
        b"2 0 obj\n<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(page_contents)).encode("ascii") + b" >>\nendobj\n"
    )

    for idx, content in enumerate(page_contents):
        page_id = base_page_id + idx * 2
        content_id = page_id + 1
        objects.append(
            f"{page_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Contents {content_id} 0 R /Resources << /Font << /F1 {base_page_id + len(page_contents) * 2} 0 R /F2 {base_page_id + len(page_contents) * 2 + 1} 0 R >> >> >>\nendobj\n".encode("ascii")
        )
        objects.append(
            f"{content_id} 0 obj\n<< /Length {len(content)} >>\nstream\n".encode("ascii")
            + content
            + b"\nendstream\nendobj\n"
        )

    font1_id = base_page_id + len(page_contents) * 2
    font2_id = font1_id + 1
    objects.append(f"{font1_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".encode("ascii"))
    objects.append(f"{font2_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n".encode("ascii"))

    xref_positions = []
    pdf = b"%PDF-1.4\n"
    for obj in objects:
        xref_positions.append(len(pdf))
        pdf += obj
    xref_start = len(pdf)
    pdf += b"xref\n0 " + str(len(objects) + 1).encode("ascii") + b"\n"
    pdf += b"0000000000 65535 f \n"
    for pos in xref_positions:
        pdf += f"{pos:010d} 00000 n \n".encode("ascii")
    pdf += b"trailer\n<< /Size " + str(len(objects) + 1).encode("ascii") + b" /Root 1 0 R >>\n"
    pdf += b"startxref\n" + str(xref_start).encode("ascii") + b"\n%%EOF"
    return pdf


def _rgb(color: tuple[float, float, float]) -> str:
    return f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f}"


def _draw_rect(x: float, y: float, w: float, h: float, fill: tuple[float, float, float] | None = None, stroke: tuple[float, float, float] | None = None, stroke_width: float = 1.0) -> str:
    cmds = []
    if fill:
        cmds.append(f"{_rgb(fill)} rg")
        cmds.append(f"{x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")
    if stroke:
        cmds.append(f"{stroke_width:.1f} w")
        cmds.append(f"{_rgb(stroke)} RG")
        cmds.append(f"{x:.1f} {y:.1f} {w:.1f} {h:.1f} re S")
    return "\n".join(cmds)


def _draw_text(x: float, y: float, text: str, font: str = "F1", size: int = 12, color: tuple[float, float, float] = (1, 1, 1)) -> str:
    return f"q {_rgb(color)} rg BT /{font} {size} Tf {x:.1f} {y:.1f} Td ({_escape_pdf_text(text)}) Tj ET Q"


def _draw_polyline(points: list[tuple[float, float]], stroke: tuple[float, float, float], stroke_width: float = 1.0) -> str:
    if len(points) < 2:
        return ""
    cmds = ["q", f"{stroke_width:.1f} w", f"{_rgb(stroke)} RG"]
    x0, y0 = points[0]
    cmds.append(f"{x0:.1f} {y0:.1f} m")
    for x, y in points[1:]:
        cmds.append(f"{x:.1f} {y:.1f} l")
    cmds.append("S Q")
    return "\n".join(cmds)


def _draw_paragraph(x: float, y: float, text: str, max_chars: int = 80, leading: int = 16, font: str = "F1", size: int = 12, color: tuple[float, float, float] = (1, 1, 1)) -> tuple[list[str], float]:
    cmds: list[str] = []
    for line in _wrap_text(text, max_chars=max_chars):
        cmds.append(_draw_text(x, y, line, font=font, size=size, color=color))
        y -= leading
    return cmds, y


def _collect_findings(report: Report, role_hint: str | None = None):
    role_hint = role_hint or _report_role_hint(report.service_request)
    scan_job = report.scan_job
    service_request = report.service_request
    findings: list[dict] = []
    if report.scope in {Report.SCOPE_CODE, Report.SCOPE_COMBINED}:
        code_qs = CodeFinding.objects.filter(scan_job=scan_job) if scan_job else CodeFinding.objects.none()
        # Backward-compat: older scan paths recorded findings without scan_job linkage.
        if scan_job and not code_qs.exists():
            if service_request:
                code_qs = CodeFinding.objects.filter(service_request=service_request)
            elif getattr(scan_job, "repository_id", None):
                code_qs = CodeFinding.objects.filter(repository=scan_job.repository, scan_job__isnull=True)
        for finding in code_qs:
            findings.append(
                {
                    "type": "code",
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "recommendation": finding.remediation,
                    "standard_mapping": finding.standard_mapping,
                    "asset": getattr(finding.repository, "repo_url", "Unknown repository"),
                    "ai_explanation": explain_code_finding(finding, role_hint),
                    "evidence": {
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "masked_value": finding.masked_value,
                        "secret_type": finding.secret_type,
                        "category": finding.category,
                    },
                }
            )
    if report.scope in {Report.SCOPE_NETWORK, Report.SCOPE_COMBINED, Report.SCOPE_WEB}:
        network_qs = NetworkFinding.objects.filter(scan_job=scan_job) if scan_job else NetworkFinding.objects.none()
        # Backward-compat: older scan paths recorded findings without scan_job linkage.
        if scan_job and not network_qs.exists():
            if service_request:
                network_qs = NetworkFinding.objects.filter(service_request=service_request)
            elif getattr(scan_job, "asset_id", None):
                network_qs = NetworkFinding.objects.filter(
                    network_asset__organization=report.organization,
                    network_asset__asset=scan_job.asset,
                    scan_job__isnull=True,
                )
        for finding in network_qs:
            asset_name = getattr(finding.network_asset.asset, "name", "Unknown asset") if finding.network_asset else "Unknown asset"
            network_type = finding.network_asset.network_type if finding.network_asset else ""
            evidence = finding.evidence or {}
            findings.append(
                {
                    "type": "network",
                    "title": finding.summary,
                    "severity": finding.severity,
                    "description": finding.summary,
                    "recommendation": finding.recommendation,
                    "standard_mapping": [],
                    "asset": f"{asset_name} ({network_type})" if network_type else asset_name,
                    "ai_explanation": explain_network_finding(finding, role_hint),
                    "evidence": evidence,
                    "finding_type": finding.finding_type,
                    # Present for active validation findings; used to group API report signals.
                    "validation_type": evidence.get("validation_type"),
                }
            )
    if report.scope == Report.SCOPE_CLOUD:
        cloud_qs = CloudFinding.objects.filter(scan_job=scan_job) if scan_job else CloudFinding.objects.none()
        # Backward-compat: older scan paths recorded findings without scan_job linkage.
        if scan_job and not cloud_qs.exists() and service_request:
            cloud_qs = CloudFinding.objects.filter(service_request=service_request)
        for finding in cloud_qs:
            account = finding.cloud_account
            asset_name = getattr(account, "name", "Cloud account")
            provider = account.get_provider_display() if account else "Cloud"
            findings.append(
                {
                    "type": "cloud",
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "recommendation": finding.remediation,
                    "standard_mapping": finding.compliance or [],
                    "asset": f"{asset_name} ({provider})",
                    "ai_explanation": explain_cloud_finding(finding, role_hint),
                    "evidence": finding.evidence or {},
                }
            )
    return findings


def build_styled_report_pdf(report: Report) -> bytes:
    organization = report.organization
    service_request = report.service_request
    scan_job = report.scan_job
    metadata = report.metadata or {}

    service_label = service_request.get_service_type_display() if service_request else report.get_scope_display()
    scan_id = scan_job.id if scan_job else report.id
    scan_start = scan_job.started_at if scan_job and scan_job.started_at else report.generated_at
    scan_end = scan_job.completed_at if scan_job and scan_job.completed_at else report.generated_at

    role_hint = _report_role_hint(service_request)
    findings = _collect_findings(report, role_hint=role_hint)
    severity_rank = {"critical": 4, "high": 3, "moderate": 2, "low": 1}
    findings_sorted = sorted(findings, key=lambda item: severity_rank.get(item.get("severity", "low"), 0), reverse=True)
    findings_sorted = _enrich_findings(findings_sorted)
    severity_counts = _severity_counts_for_report(report)
    posture = _posture_for_report(report, severity_counts, metadata)
    insights = _insights_for_report(report, findings_sorted, metadata)

    def _trim(value: str, max_len: int) -> str:
        text_value = (value or "").strip()
        if len(text_value) <= max_len:
            return text_value
        return text_value[: max_len - 1].rstrip() + "..."

    def _severity_color(severity: str) -> tuple[float, float, float]:
        return {
            "critical": (0.80, 0.16, 0.16),
            "high": (0.87, 0.36, 0.10),
            "moderate": (0.82, 0.56, 0.08),
            "low": (0.10, 0.42, 0.70),
        }.get((severity or "").lower(), (0.20, 0.32, 0.55))

    overall_risk = "Low"
    if severity_counts["critical"] > 0:
        overall_risk = "Critical"
    elif severity_counts["high"] > 0:
        overall_risk = "High"
    elif severity_counts["moderate"] > 0:
        overall_risk = "Medium"

    hosts_identified = int(metadata.get("hosts_alive") or metadata.get("hosts_scanned") or 0)
    open_ports = int(metadata.get("open_ports") or 0)
    key_risks = [_trim(item.get("title", "Finding"), 90) for item in findings_sorted[:3]] or ["No high-priority risks identified."]

    if report.scope == Report.SCOPE_CODE:
        primary_label = "Repositories"
        primary_value = str(metadata.get("repositories_scanned") or metadata.get("repos_scanned") or 0)
    elif report.scope == Report.SCOPE_CLOUD:
        primary_label = "Accounts"
        primary_value = "1" if service_request and service_request.cloud_account_id else "0"
    elif report.scope == Report.SCOPE_WEB:
        primary_label = "Endpoints"
        primary_value = str(metadata.get("endpoints_scanned") or metadata.get("endpoints_assessed") or 0)
    else:
        primary_label = "Hosts"
        primary_value = str(hosts_identified)

    page_bg = (0.985, 0.992, 1.00)
    panel = (0.95, 0.97, 1.00)
    panel_alt = (0.90, 0.95, 1.00)
    accent = (0.10, 0.46, 0.96)
    accent_alt = (0.13, 0.63, 0.67)
    text_color = (0.10, 0.12, 0.16)
    muted = (0.32, 0.37, 0.45)
    border = (0.82, 0.87, 0.96)
    brand_wordmark = (os.getenv("REPORT_BRAND_WORDMARK", "AEGIS") or "AEGIS").strip().upper()[:18]
    brand_tagline = (os.getenv("REPORT_BRAND_TAGLINE", "SECURITY") or "SECURITY").strip().upper()[:20]

    title_map = {
        Report.SCOPE_NETWORK: "Network Security Assessment",
        Report.SCOPE_WEB: "Web Security Assessment",
        Report.SCOPE_CODE: "Code Security Assessment",
        Report.SCOPE_COMBINED: "Security Assessment",
        Report.SCOPE_CLOUD: "Cloud Security Posture Assessment",
    }
    report_title = title_map.get(report.scope, "Security Assessment")
    scope_lines = _derive_scope_lines(service_request)[:4]
    methodology_lines = _methodology_lines(report.scope, service_request.service_type if service_request else None)[:4]

    pages: list[bytes] = []

    # Page 1: Overview
    cmds: list[str] = []
    cmds.append(_draw_rect(0, 0, 612, 792, fill=page_bg))
    cmds.append(_draw_rect(0, 718, 612, 74, fill=panel_alt))
    cmds.append(_draw_rect(0, 718, 612, 6, fill=accent))
    cmds.append(_draw_rect(40, 728, 72, 44, fill=accent_alt))
    cmds.append(_draw_text(52, 747, brand_wordmark, font="F2", size=12, color=(1, 1, 1)))
    cmds.append(_draw_text(52, 734, brand_tagline, font="F1", size=7, color=(1, 1, 1)))
    cmds.append(_draw_text(124, 756, report_title, font="F2", size=22, color=accent))
    cmds.append(_draw_text(124, 736, organization.name, font="F1", size=12, color=text_color))
    cmds.append(_draw_text(420, 736, f"Risk: {overall_risk}", font="F2", size=12, color=_severity_color(overall_risk.lower())))

    cmds.append(_draw_rect(40, 635, 532, 70, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_text(56, 682, "Assessment Summary", font="F2", size=12, color=accent))
    summary = report.summary or explain_report_summary(report.scope, severity_counts)
    summary_cmds, _ = _draw_paragraph(56, 662, _trim(summary, 520), max_chars=98, leading=14, font="F1", size=10, color=muted)
    cmds.extend(summary_cmds)

    card_y = 555
    card_w = 125
    metrics = [
        (primary_label, primary_value, accent),
        ("Critical", str(severity_counts["critical"]), _severity_color("critical")),
        ("High", str(severity_counts["high"]), _severity_color("high")),
        ("Medium", str(severity_counts["moderate"]), _severity_color("moderate")),
    ]
    for idx, (label, value, color) in enumerate(metrics):
        x = 40 + idx * (card_w + 12)
        cmds.append(_draw_rect(x, card_y, card_w, 68, fill=panel, stroke=border, stroke_width=1.0))
        cmds.append(_draw_text(x + 10, card_y + 44, label, font="F2", size=10, color=muted))
        cmds.append(_draw_text(x + 10, card_y + 20, value, font="F2", size=16, color=color))

    cmds.append(_draw_rect(40, 450, 260, 84, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_text(52, 517, "Scan Metadata", font="F2", size=11, color=accent))
    cmds.append(_draw_text(52, 495, f"Scan ID: {scan_id}", font="F1", size=10, color=muted))
    cmds.append(_draw_text(52, 479, f"Type: {service_label}", font="F1", size=10, color=muted))
    cmds.append(_draw_text(52, 463, f"Date: {scan_start:%Y-%m-%d} to {scan_end:%Y-%m-%d}", font="F1", size=10, color=muted))
    cmds.append(_draw_text(52, 451, f"Posture Score: {posture.get('score', 'n/a')}/100 ({posture.get('grade', '')})", font="F1", size=10, color=muted))

    cmds.append(_draw_rect(312, 450, 260, 84, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_text(324, 517, "Key Risk Highlights", font="F2", size=11, color=accent))
    y = 495
    for risk in key_risks:
        for line in _wrap_text(f"- {risk}", max_chars=42)[:2]:
            cmds.append(_draw_text(324, y, line, font="F1", size=10, color=muted))
            y -= 14
        if y < 458:
            break

    # Two-column "Scope/Method" + "Toolchain/Standards" so stakeholders can see what was actually run.
    left_x, right_x = 40, 312
    box_y, box_h, box_w = 230, 190, 260
    cmds.append(_draw_rect(left_x, box_y, box_w, box_h, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_rect(right_x, box_y, box_w, box_h, fill=panel, stroke=border, stroke_width=1.0))

    # Left: Scope & Methodology
    cmds.append(_draw_text(left_x + 12, box_y + box_h - 22, "Scope & Methodology", font="F2", size=11, color=accent))
    y = box_y + box_h - 44
    cmds.append(_draw_text(left_x + 12, y, "Scope", font="F2", size=9, color=text_color))
    y -= 14
    for line in scope_lines:
        for wrapped in _wrap_text(f"- {line}", max_chars=44)[:2]:
            cmds.append(_draw_text(left_x + 18, y, wrapped, font="F1", size=8, color=muted))
            y -= 12
        if y < box_y + 74:
            break

    cmds.append(_draw_text(left_x + 12, y - 2, "Method", font="F2", size=9, color=text_color))
    y -= 16
    for line in methodology_lines:
        for wrapped in _wrap_text(f"- {line}", max_chars=44)[:2]:
            cmds.append(_draw_text(left_x + 18, y, wrapped, font="F1", size=8, color=muted))
            y -= 12
        if y < box_y + 16:
            break

    # Right: Toolchain & Standards (crisp table)
    tool_rows = _toolchain_rows(report.scope, service_request.service_type if service_request else None)
    standards = _standards_referenced(report.scope, service_request.service_type if service_request else None)
    cmds.append(_draw_text(right_x + 12, box_y + box_h - 22, "Toolchain & Standards", font="F2", size=11, color=accent))
    cmds.append(_draw_text(right_x + 12, box_y + box_h - 38, "What we ran (summary)", font="F1", size=8, color=muted))
    y = box_y + box_h - 56
    for label, value in tool_rows:
        cmds.append(_draw_text(right_x + 12, y, f"{label}:", font="F2", size=8, color=text_color))
        for wrapped in _wrap_text(value, max_chars=34)[:2]:
            cmds.append(_draw_text(right_x + 66, y, wrapped, font="F1", size=8, color=muted))
            y -= 12
        y -= 2
        if y < box_y + 50:
            break

    cmds.append(_draw_text(right_x + 12, box_y + 34, "Referenced frameworks:", font="F2", size=8, color=text_color))
    y_std = box_y + 22
    for wrapped in _wrap_text(standards, max_chars=44)[:2]:
        cmds.append(_draw_text(right_x + 12, y_std, wrapped, font="F1", size=8, color=muted))
        y_std -= 12

    cmds.append(_draw_rect(40, 180, 532, 42, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_text(52, 204, "Safe Scan Notice", font="F2", size=10, color=accent))
    cmds.append(_draw_text(52, 188, "No exploit execution or denial-of-service techniques were used in this assessment.", font="F1", size=9, color=muted))
    pages.append("\n".join(cmds).encode("utf-8"))

    # Page 2: Findings and action plan
    cmds = []
    cmds.append(_draw_rect(0, 0, 612, 792, fill=page_bg))
    cmds.append(_draw_rect(0, 735, 612, 57, fill=panel_alt))
    cmds.append(_draw_rect(0, 735, 612, 5, fill=accent))
    cmds.append(_draw_text(46, 758, "Findings Summary and Action Plan", font="F2", size=18, color=accent))
    cmds.append(_draw_text(46, 742, f"Generated: {report.generated_at:%Y-%m-%d %H:%M UTC}", font="F1", size=10, color=muted))

    sev_rows = [
        ("Critical", severity_counts["critical"]),
        ("High", severity_counts["high"]),
        ("Medium", severity_counts["moderate"]),
        ("Low", severity_counts["low"]),
    ]
    table_y = 690
    for idx, (label, count) in enumerate(sev_rows):
        y = table_y - idx * 28
        cmds.append(_draw_rect(46, y - 18, 255, 22, fill=panel, stroke=border, stroke_width=0.8))
        cmds.append(_draw_text(58, y - 5, label, font="F2", size=10, color=_severity_color(label.lower())))
        cmds.append(_draw_text(138, y - 5, str(count), font="F2", size=10, color=text_color))
        cmds.append(_draw_text(184, y - 5, "findings", font="F1", size=9, color=muted))

    top_findings_x = 46
    top_findings_w = 255
    top_findings_title_y = 555
    top_findings_row_y = 535
    top_findings_min_y = 392  # keep clear of the risk-matrix panel below
    cmds.append(_draw_text(top_findings_x, top_findings_title_y, "Top Findings", font="F2", size=12, color=accent))
    y = top_findings_row_y
    top_findings_bottom = top_findings_row_y
    for index, item in enumerate(findings_sorted[:8], start=1):
        if y < top_findings_min_y:
            break
        sev = (item.get("severity") or "low").lower()
        cvss = item.get("cvss_score")
        cvss_tag = "CVSS"
        if item.get("cvss_is_estimated"):
            cvss_tag = "CVSS~"
        title = _trim(item.get("title", "Finding"), 38)
        cmds.append(_draw_rect(top_findings_x, y - 16, top_findings_w, 20, fill=panel, stroke=border, stroke_width=0.8))
        cmds.append(_draw_text(top_findings_x + 8, y - 3, f"{index}.", font="F2", size=9, color=accent))
        cmds.append(_draw_text(top_findings_x + 26, y - 3, title, font="F1", size=8, color=text_color))
        cmds.append(_draw_text(top_findings_x + top_findings_w - 64, y - 3, f"{cvss_tag} {cvss}", font="F2", size=8, color=muted))
        top_findings_bottom = y - 16
        y -= 24

    # Keep inventory data for right-column card (below recommendation).
    inventory_rows = _inventory_rows(report, findings_sorted, metadata)

    # Reserve the lower-left zone for the risk matrix.
    matrix_x, matrix_w, matrix_h = 46, 255, 118
    matrix_y = 246

    # Risk matrix (impact x likelihood)
    cmds.append(_draw_rect(matrix_x, matrix_y, matrix_w, matrix_h, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_text(matrix_x + 12, matrix_y + matrix_h - 14, "Risk Prioritization Matrix", font="F2", size=10, color=accent))
    cmds.append(_draw_text(matrix_x + 12, matrix_y + matrix_h - 28, "Impact vs Likelihood (count)", font="F1", size=8, color=muted))
    buckets = {(i, l): 0 for i in ("High", "Medium", "Low") for l in ("High", "Medium", "Low")}
    for item in findings_sorted:
        i = item.get("impact") or "Low"
        l = item.get("likelihood") or "Low"
        if (i, l) in buckets:
            buckets[(i, l)] += 1
    grid_x = matrix_x + 12
    grid_y = matrix_y + matrix_h - 50
    cell_w = 68
    cell_h = 22
    for col_idx, l in enumerate(["High", "Medium", "Low"]):
        cmds.append(_draw_text(grid_x + 52 + col_idx * cell_w, grid_y + 26, l[0], font="F2", size=8, color=muted))
    for row_idx, i in enumerate(["High", "Medium", "Low"]):
        cmds.append(_draw_text(grid_x, grid_y - row_idx * cell_h, i[0], font="F2", size=8, color=muted))
        for col_idx, l in enumerate(["High", "Medium", "Low"]):
            x = grid_x + 18 + col_idx * cell_w
            y_cell = grid_y - row_idx * cell_h - 12
            cmds.append(_draw_rect(x, y_cell, cell_w - 6, cell_h, fill=panel_alt, stroke=border, stroke_width=0.8))
            cmds.append(_draw_text(x + 24, y_cell + 7, str(buckets[(i, l)]), font="F2", size=9, color=text_color))

    # API validation section (only for API scan reports; kept compact to stay within 2-3 pages when printed).
    is_api_report = bool(service_request and service_request.service_type == ServiceRequest.SERVICE_API)
    if is_api_report:
        api_validation: dict[str, dict] = {}
        for item in findings_sorted:
            if item.get("type") != "network":
                continue
            if item.get("finding_type") != NetworkFinding.TYPE_ACTIVE_VALIDATION:
                continue
            validation_type = (item.get("validation_type") or (item.get("evidence") or {}).get("validation_type") or "").strip()
            if not validation_type:
                continue
            sev = (item.get("severity") or "low").lower()
            current = api_validation.get(validation_type)
            if not current or severity_rank.get(sev, 0) > severity_rank.get(current["severity"], 0):
                api_validation[validation_type] = {
                    "validation_type": validation_type,
                    "severity": sev,
                    "summary": _trim(item.get("description") or item.get("title") or "Signal observed.", 120),
                }

        card_x, card_y, card_w, card_h = 316, 246, 260, 188
        cmds.append(_draw_rect(card_x, card_y, card_w, card_h, fill=panel, stroke=border, stroke_width=1.0))
        cmds.append(_draw_text(card_x + 12, card_y + card_h - 22, "API Validation Signals", font="F2", size=11, color=accent))
        cmds.append(_draw_text(card_x + 12, card_y + card_h - 38, "Safe heuristic checks (no exploitation).", font="F1", size=8, color=muted))

        rows = sorted(api_validation.values(), key=lambda r: severity_rank.get(r["severity"], 0), reverse=True)
        if not rows:
            cmds.append(_draw_text(card_x + 12, card_y + card_h - 62, "No API validation signals were recorded.", font="F1", size=9, color=muted))
        else:
            sev_label_map = {"critical": "CRIT", "high": "HIGH", "moderate": "MED", "low": "LOW"}
            y = card_y + card_h - 66
            for row in rows[:4]:
                sev = row["severity"]
                sev_label = sev_label_map.get(sev, (sev or "low")[:4].upper())
                cmds.append(_draw_rect(card_x + 12, y - 6, 6, 6, fill=_severity_color(sev)))
                cmds.append(_draw_text(card_x + 22, y - 2, _trim(row["validation_type"], 26), font="F2", size=9, color=text_color))
                cmds.append(_draw_text(card_x + 218, y - 2, sev_label, font="F2", size=8, color=_severity_color(sev)))
                summary_line = _wrap_text(row.get("summary") or "", max_chars=44)[:1]
                if summary_line:
                    cmds.append(_draw_text(card_x + 22, y - 16, _trim(summary_line[0], 60), font="F1", size=8, color=muted))
                y -= 34

    right_x, right_w = 316, 260
    priority_y, priority_h = 596, 127
    rec_y, rec_h = 440, 132
    inv_y, inv_h = 236, 184

    cmds.append(_draw_rect(right_x, priority_y, right_w, priority_h, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_text(right_x + 12, priority_y + priority_h - 17, "Priority Actions (Next 30 Days)", font="F2", size=11, color=accent))
    action_y = priority_y + priority_h - 37
    for title, action, owner in _roadmap_cards(report.scope)[:3]:
        cmds.append(_draw_text(right_x + 12, action_y, _trim(title, 42), font="F2", size=9, color=text_color))
        action_y -= 14
        for line in _wrap_text(f"Action: {_trim(action, 90)}", max_chars=44)[:2]:
            cmds.append(_draw_text(right_x + 20, action_y, line, font="F1", size=8, color=muted))
            action_y -= 12
        cmds.append(_draw_text(right_x + 20, action_y, f"Owner: {_trim(owner, 40)}", font="F1", size=8, color=muted))
        action_y -= 14
        if action_y < priority_y + 18:
            break

    ai_text = _trim(_ai_recommendations(report, findings_sorted), 420)
    cmds.append(_draw_rect(right_x, rec_y, right_w, rec_h, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_text(right_x + 12, rec_y + rec_h - 18, "Recommendation Narrative", font="F2", size=11, color=accent))
    ai_cmds, _ = _draw_paragraph(right_x + 12, rec_y + rec_h - 36, ai_text, max_chars=44, leading=12, font="F1", size=8, color=muted)
    cmds.extend(ai_cmds[:8])

    # Asset inventory in right column for clearer visual separation.
    if not is_api_report:
        cmds.append(_draw_rect(right_x, inv_y, right_w, inv_h, fill=panel, stroke=border, stroke_width=1.0))
        cmds.append(_draw_text(right_x + 12, inv_y + inv_h - 18, "Asset Inventory", font="F2", size=10, color=accent))
        inv_hdr_y = inv_y + inv_h - 33
        cmds.append(_draw_text(right_x + 12, inv_hdr_y, "Category", font="F2", size=8, color=muted))
        cmds.append(_draw_text(right_x + 112, inv_hdr_y, "Count", font="F2", size=8, color=muted))
        cmds.append(_draw_text(right_x + 152, inv_hdr_y, "Examples", font="F2", size=8, color=muted))
        cmds.append(_draw_rect(right_x + 12, inv_hdr_y - 6, right_w - 24, 0.8, stroke=border, stroke_width=0.8))
        row_y = inv_hdr_y - 16
        inv_row_bottom = inv_y + 12
        for cat, count, examples in inventory_rows[:4]:
            cat_lines = _wrap_text(str(cat or "-"), max_chars=14)[:2]
            ex_lines = _wrap_text(str(examples or "-"), max_chars=22)[:2]
            line_count = max(1, len(cat_lines), len(ex_lines))
            for idx in range(line_count):
                y_line = row_y - (idx * 10)
                if idx < len(cat_lines):
                    cmds.append(_draw_text(right_x + 12, y_line, cat_lines[idx], font="F1", size=8, color=text_color))
                if idx < len(ex_lines):
                    cmds.append(_draw_text(right_x + 152, y_line, ex_lines[idx], font="F1", size=8, color=muted))
            count_y = row_y - ((line_count - 1) * 5)
            cmds.append(_draw_text(right_x + 112, count_y, _trim(count, 4), font="F2", size=8, color=text_color))
            row_y -= max(14, line_count * 10 + 2)
            if row_y < inv_row_bottom:
                break

    duration = str(scan_end - scan_start) if scan_start and scan_end else "n/a"
    cmds.append(_draw_rect(46, 178, 530, 48, fill=panel, stroke=border, stroke_width=1.0))
    cmds.append(_draw_text(58, 206, "Technical Notes", font="F2", size=10, color=accent))
    cmds.append(_draw_text(58, 190, f"Open Ports Observed: {open_ports}    Scan Duration: {duration}    Confidence: {int(metadata.get('confidence', 85))}%", font="F1", size=9, color=muted))
    pages.append("\n".join(cmds).encode("utf-8"))

    # Page 3 is optional for denser reports
    include_detail_page = len(findings_sorted) > 6 or severity_counts["critical"] > 0 or severity_counts["high"] > 3
    if include_detail_page:
        cmds = []
        cmds.append(_draw_rect(0, 0, 612, 792, fill=page_bg))
        cmds.append(_draw_rect(0, 735, 612, 57, fill=panel_alt))
        cmds.append(_draw_rect(0, 735, 612, 5, fill=accent))
        cmds.append(_draw_text(46, 758, "Detailed Findings (Priority Items)", font="F2", size=18, color=accent))

        y = 700
        # Richer "engineer-grade" detail is shown for fewer items to preserve 2-3 page print layout.
        for idx, item in enumerate(findings_sorted[:1], start=1):
            if y < 230:
                break
            sev = (item.get("severity") or "low").lower()
            card_h = 150
            cmds.append(_draw_rect(46, y - card_h, 530, card_h - 8, fill=panel, stroke=border, stroke_width=1.0))
            cmds.append(_draw_text(58, y - 22, f"{idx}. {_trim(item.get('title', 'Finding'), 74)}", font="F2", size=11, color=text_color))
            cmds.append(_draw_text(500, y - 22, sev.upper(), font="F2", size=9, color=_severity_color(sev)))

            asset = _trim(str(item.get("asset") or "Unspecified asset"), 86)
            cvss = item.get("cvss_score")
            cvss_tag = "CVSS" if not item.get("cvss_is_estimated") else "CVSS~"
            cmds.append(_draw_text(58, y - 38, f"Asset: {asset}", font="F1", size=9, color=muted))
            cmds.append(_draw_text(58, y - 52, f"{cvss_tag}: {cvss}  |  Impact: {item.get('impact')}  |  Likelihood: {item.get('likelihood')}", font="F1", size=8, color=muted))

            # Inner grid: left narrative, right evidence/repro.
            left_x, right_x = 58, 328
            inner_y = y - 138
            inner_h = 78
            inner_w = 252
            cmds.append(_draw_rect(left_x, inner_y, inner_w, inner_h, fill=panel_alt, stroke=border, stroke_width=0.8))
            cmds.append(_draw_rect(right_x, inner_y, inner_w, inner_h, fill=panel_alt, stroke=border, stroke_width=0.8))

            # Left: Observed + Remediation (compact)
            desc = _trim(item.get("description", ""), 240)
            rec = _trim(item.get("recommendation", ""), 220)
            cmds.append(_draw_text(left_x + 10, inner_y + inner_h - 14, "Observed", font="F2", size=8, color=text_color))
            y_obs = inner_y + inner_h - 28
            for wrapped in _wrap_text(desc, max_chars=44):
                if y_obs < inner_y + 34:
                    break
                cmds.append(_draw_text(left_x + 10, y_obs, wrapped, font="F1", size=8, color=muted))
                y_obs -= 10
            y_rem_hdr = max(inner_y + 22, y_obs - 2)
            cmds.append(_draw_text(left_x + 10, y_rem_hdr, "Remediation", font="F2", size=8, color=text_color))
            y_rem = y_rem_hdr - 12
            for wrapped in _wrap_text(rec, max_chars=44):
                if y_rem < inner_y + 8:
                    break
                cmds.append(_draw_text(left_x + 10, y_rem, wrapped, font="F1", size=8, color=muted))
                y_rem -= 10

            # Right: Evidence + Repro steps (PoC-style)
            cmds.append(_draw_text(right_x + 10, inner_y + inner_h - 14, "Evidence (excerpt)", font="F2", size=8, color=text_color))
            ev_lines = _evidence_lines_for_finding(item)
            ev_display: list[str] = []
            if ev_lines:
                ev_display.extend(ev_lines[:2])
                if len(ev_lines) > 2:
                    ev_display.append(ev_lines[-1])
            y_ev = inner_y + inner_h - 28
            for line in ev_display[:3]:
                for wrapped in _wrap_text(line, max_chars=44):
                    if y_ev < inner_y + 34:
                        break
                    cmds.append(_draw_text(right_x + 10, y_ev, wrapped, font="F1", size=8, color=muted))
                    y_ev -= 10

            y_rep_hdr = max(inner_y + 22, y_ev - 2)
            cmds.append(_draw_text(right_x + 10, y_rep_hdr, "Reproduction steps", font="F2", size=8, color=text_color))
            y_rep = y_rep_hdr - 12
            for step in _repro_steps_for_finding(item)[:3]:
                for wrapped in _wrap_text(f"- {step}", max_chars=44):
                    if y_rep < inner_y + 8:
                        break
                    cmds.append(_draw_text(right_x + 10, y_rep, wrapped, font="F1", size=8, color=muted))
                    y_rep -= 10

            refs = item.get("references") or []
            if refs:
                cmds.append(_draw_text(58, y - (card_h - 6), f"Refs: {_trim(', '.join(refs), 120)}", font="F1", size=8, color=muted))

            y -= (card_h + 22)

        # Threat modeling + exploit chain hypotheses (data-backed, no exploitation claims).
        threat = (insights.get("threat_model") or {}) if isinstance(insights, dict) else {}
        chains = insights.get("exploit_chains") if isinstance(insights, dict) else None
        if not isinstance(chains, list):
            chains = []

        tm_x, tm_y, tm_w, tm_h = 46, 392, 260, 128
        cmds.append(_draw_rect(tm_x, tm_y, tm_w, tm_h, fill=panel, stroke=border, stroke_width=1.0))
        cmds.append(_draw_text(tm_x + 12, tm_y + tm_h - 18, "Threat Model Snapshot", font="F2", size=10, color=accent))
        cmds.append(_draw_text(tm_x + 12, tm_y + tm_h - 32, "Likely actors and threats (heuristic).", font="F1", size=8, color=muted))
        y_tm = tm_y + tm_h - 48
        for actor in (threat.get("actors") or [])[:2]:
            cmds.append(_draw_text(tm_x + 12, y_tm, _trim(f"- {actor}", 44), font="F1", size=8, color=muted))
            y_tm -= 10
        for tline in (threat.get("top_threats") or [])[:2]:
            cmds.append(_draw_text(tm_x + 12, y_tm, _trim(f"* {tline}", 44), font="F1", size=8, color=muted))
            y_tm -= 10

        ec_x, ec_y, ec_w, ec_h = 316, 392, 260, 128
        cmds.append(_draw_rect(ec_x, ec_y, ec_w, ec_h, fill=panel, stroke=border, stroke_width=1.0))
        cmds.append(_draw_text(ec_x + 12, ec_y + ec_h - 18, "Exploit Chain Hypotheses", font="F2", size=10, color=accent))
        cmds.append(_draw_text(ec_x + 12, ec_y + ec_h - 32, "Narratives derived from findings.", font="F1", size=8, color=muted))
        if chains:
            c0 = chains[0] if isinstance(chains[0], dict) else {}
            cmds.append(_draw_text(ec_x + 12, ec_y + ec_h - 48, _trim(str(c0.get("title") or "Attack path"), 40), font="F2", size=9, color=text_color))
            y_ec = ec_y + ec_h - 62
            for step in (c0.get("steps") or [])[:3]:
                for wrapped in _wrap_text(f"- {step}", max_chars=44)[:1]:
                    cmds.append(_draw_text(ec_x + 12, y_ec, _trim(wrapped, 58), font="F1", size=8, color=muted))
                    y_ec -= 10
        else:
            cmds.append(_draw_text(ec_x + 12, ec_y + ec_h - 54, "No chains synthesized for this scan.", font="F1", size=9, color=muted))

        # Posture scoring + maturity (dedicated section; includes historical trend sparkline).
        trend = _posture_trend_for_report(report, limit=6)
        cur_score = int((posture or {}).get("score") or 0)
        prev_score = int(trend[-2]["score"]) if len(trend) >= 2 else cur_score
        delta = cur_score - prev_score
        delta_text = f"{delta:+d}" if delta else "0"

        ps_x, ps_y, ps_w, ps_h = 46, 296, 530, 88
        cmds.append(_draw_rect(ps_x, ps_y, ps_w, ps_h, fill=panel, stroke=border, stroke_width=1.0))
        cmds.append(_draw_text(ps_x + 12, ps_y + ps_h - 18, "Posture & Maturity", font="F2", size=10, color=accent))
        cmds.append(_draw_text(ps_x + 12, ps_y + ps_h - 34, f"Posture: {cur_score}/100 ({posture.get('grade','')})   Change: {delta_text} vs prior", font="F1", size=8, color=muted))

        # Sparkline (0..100)
        chart_x, chart_y, chart_w, chart_h = ps_x + 12, ps_y + 12, 300, 22
        cmds.append(_draw_rect(chart_x, chart_y, chart_w, chart_h, fill=panel_alt, stroke=border, stroke_width=0.8))
        # light grid
        cmds.append(_draw_rect(chart_x, chart_y + chart_h / 2.0, chart_w, 0.6, stroke=border, stroke_width=0.6))
        if trend:
            values = [max(0, min(100, int(p.get("score") or 0))) for p in trend]
            if len(values) == 1:
                values = values * 2
            pts: list[tuple[float, float]] = []
            for i, v in enumerate(values):
                x = chart_x + (i / (len(values) - 1)) * chart_w
                yv = chart_y + (v / 100.0) * chart_h
                pts.append((x, yv))
            cmds.append(_draw_polyline(pts, stroke=accent, stroke_width=1.2))
            # Labels
            first = trend[0].get("generated_at")
            last = trend[-1].get("generated_at")
            if first and last:
                cmds.append(_draw_text(chart_x, ps_y + 4, f"{first:%Y-%m-%d}", font="F1", size=7, color=muted))
                cmds.append(_draw_text(chart_x + chart_w - 46, ps_y + 4, f"{last:%Y-%m-%d}", font="F1", size=7, color=muted))

        # Maturity mini-table (right side)
        maturity = (insights.get("maturity") or {}) if isinstance(insights, dict) else {}
        domains = maturity.get("domains") if isinstance(maturity, dict) else None
        if not isinstance(domains, list):
            domains = []
        cmds.append(_draw_text(ps_x + 332, ps_y + ps_h - 18, "Maturity", font="F2", size=9, color=text_color))
        lvl = (maturity.get("level") if isinstance(maturity, dict) else "") or ""
        ov = (maturity.get("overall") if isinstance(maturity, dict) else None)
        ov_text = f"{ov}" if ov is not None else "n/a"
        cmds.append(_draw_text(ps_x + 332, ps_y + ps_h - 32, f"Level: {lvl}  Avg: {ov_text}/5", font="F1", size=8, color=muted))
        y_m = ps_y + ps_h - 48
        for d in domains[:4]:
            if not isinstance(d, dict):
                continue
            name = _trim(str(d.get("domain") or "Domain"), 18)
            score = int(d.get("score") or 0)
            bar_w = 70
            filled = max(0.0, min(1.0, score / 5.0)) * bar_w
            cmds.append(_draw_text(ps_x + 332, y_m, name, font="F1", size=8, color=muted))
            cmds.append(_draw_rect(ps_x + 422, y_m - 6, bar_w, 6, fill=panel_alt, stroke=border, stroke_width=0.6))
            cmds.append(_draw_rect(ps_x + 422, y_m - 6, filled, 6, fill=accent_alt))
            cmds.append(_draw_text(ps_x + 498, y_m - 1, f"{score}/5", font="F2", size=8, color=text_color))
            y_m -= 12

        # Compliance mapping (dedicated section; compact table).
        comp_rows = _compliance_table_rows(findings_sorted)
        comp_x, comp_y, comp_w, comp_h = 46, 196, 530, 92
        cmds.append(_draw_rect(comp_x, comp_y, comp_w, comp_h, fill=panel, stroke=border, stroke_width=1.0))
        cmds.append(_draw_text(comp_x + 12, comp_y + comp_h - 20, "Compliance Mapping", font="F2", size=10, color=accent))
        cmds.append(_draw_text(comp_x + 12, comp_y + comp_h - 34, "Mapped from explicit finding tags (not inferred).", font="F1", size=8, color=muted))

        hdr_y = comp_y + comp_h - 48
        cmds.append(_draw_text(comp_x + 12, hdr_y, "Framework", font="F2", size=8, color=muted))
        cmds.append(_draw_text(comp_x + 160, hdr_y, "Findings", font="F2", size=8, color=muted))
        cmds.append(_draw_text(comp_x + 220, hdr_y, "Controls / Tags", font="F2", size=8, color=muted))
        cmds.append(_draw_rect(comp_x + 12, hdr_y - 6, comp_w - 24, 0.8, stroke=border, stroke_width=0.8))

        row_y = hdr_y - 14
        for fw, count, tags in comp_rows:
            cmds.append(_draw_text(comp_x + 12, row_y, _trim(fw, 18), font="F1", size=8, color=text_color))
            cmds.append(_draw_text(comp_x + 170, row_y, str(count), font="F2", size=8, color=text_color))
            cmds.append(_draw_text(comp_x + 220, row_y, _trim(tags, 64), font="F1", size=8, color=muted))
            row_y -= 12
            if row_y < comp_y + 10:
                break

        disclaimer = (
            "This report reflects posture at scan time only. Re-testing after remediation is recommended to validate closure."
        )
        cmds.append(_draw_rect(46, 146, 530, 44, fill=panel, stroke=border, stroke_width=1.0))
        cmds.append(_draw_text(58, 172, "Disclaimer", font="F2", size=10, color=accent))
        cmds.append(_draw_text(58, 156, disclaimer, font="F1", size=9, color=muted))
        pages.append("\n".join(cmds).encode("utf-8"))

    branded_pages: list[bytes] = []
    total_pages = len(pages)
    admin_signatory = "Platform Administrator"
    if service_request and service_request.approved_by:
        admin_signatory = service_request.approved_by.get_full_name() or service_request.approved_by.email or admin_signatory
    client_signatory = str(metadata.get("client_signatory") or "Client Representative")

    for idx, content in enumerate(pages, start=1):
        footer_cmds: list[str] = []
        if idx == total_pages:
            footer_cmds.extend(
                [
                    _draw_rect(46, 56, 530, 74, fill=panel, stroke=border, stroke_width=1.0),
                    _draw_text(58, 116, "Report Approval Sign-off", font="F2", size=10, color=accent),
                    _draw_text(58, 99, "Client Signature: ____________________", font="F1", size=9, color=text_color),
                    _draw_text(58, 84, f"Name: {client_signatory}", font="F1", size=8, color=muted),
                    _draw_text(58, 70, "Date: ____________________", font="F1", size=8, color=muted),
                    _draw_text(320, 99, "Platform Admin Signature: ____________________", font="F1", size=9, color=text_color),
                    _draw_text(320, 84, f"Name: {admin_signatory}", font="F1", size=8, color=muted),
                    _draw_text(320, 70, "Date: ____________________", font="F1", size=8, color=muted),
                ]
            )
        footer_cmds.extend(
            [
                _draw_text(46, 26, "Aegis Security Assessment Report - Confidential", font="F1", size=8, color=muted),
                _draw_text(530, 26, f"Page {idx}/{total_pages}", font="F1", size=8, color=muted),
            ]
        )
        branded_pages.append(content + b"\n" + "\n".join(footer_cmds).encode("utf-8"))

    return _build_pdf_from_pages(branded_pages)


def build_network_report_pdf(report: Report) -> bytes:
    return build_styled_report_pdf(report)


def _derive_scope_lines(service_request) -> list[str]:
    if not service_request:
        return ["Scope details unavailable for this report."]
    lines = []
    if service_request.repository_url:
        lines.append(f"Repository: {service_request.repository_url}")
    if service_request.asset:
        lines.append(f"Asset: {service_request.asset.name}")
    if service_request.ip_cidr:
        lines.append(f"IP / CIDR: {service_request.ip_cidr}")
    if service_request.domain_url:
        lines.append(f"Domain / URL: {service_request.domain_url}")
    if service_request.cloud_account:
        account = service_request.cloud_account
        provider = account.get_provider_display()
        lines.append(f"Cloud Provider: {provider}")
        lines.append(f"Cloud Account: {account.name}")
        if account.aws_account_id:
            lines.append(f"AWS Account ID: {account.aws_account_id}")
        if account.azure_subscription_id:
            lines.append(f"Azure Subscription: {account.azure_subscription_id}")
        if account.gcp_project_id:
            lines.append(f"GCP Project: {account.gcp_project_id}")
    if not lines:
        lines.append("Scope details were not provided.")
    return lines


def _methodology_lines(scope: str, service_type: str | None) -> list[str]:
    base = [
        "Network discovery and enumeration (safe, non-intrusive)",
        "Port and service identification with passive checks",
        "Configuration assessment for exposed services",
        "Vulnerability correlation based on observable indicators",
    ]
    if scope == Report.SCOPE_CODE:
        return [
            "Static code inspection for secrets and dependency issues",
            "Manifest parsing and version correlation",
            "No code execution or build steps performed",
        ]
    if scope == Report.SCOPE_WEB or service_type in {"WEB_EXPOSURE_SCAN", "API_SECURITY_SCAN"}:
        return [
            "HTTP header and TLS configuration review",
            "Safe endpoint validation (reflected XSS/SQL error signals, SSRF indicators, upload surface discovery)",
            "No authentication testing or exploitation performed",
        ]
    if scope == Report.SCOPE_NETWORK:
        return [
            "TCP connect checks on a restricted port list",
            "Service fingerprinting and safe exposure validation (DNS AXFR, no-auth service checks)",
            "DNS recursion and SMB legacy-protocol (SMBv1) signals where applicable",
            "Segmentation/pivot-path heuristics based on port combinations",
            "No exploitation performed; optional default credential checks are disabled by default",
        ]
    if scope == Report.SCOPE_CLOUD:
        return [
            "Cloud control-plane assessment using read-only APIs",
            "Baseline posture checks for storage, network, and IAM controls",
            "No data extraction or destructive actions performed",
        ]
    return base


def _limitations_lines() -> list[str]:
    return [
        "Findings are based on observable behavior at scan time.",
        "Firewalls and access controls may reduce visibility.",
        "No exploitation or denial-of-service techniques were used.",
    ]


def _toolchain_rows(scope: str, service_type: str | None) -> list[tuple[str, str]]:
    """
    Compact, truthful toolchain summary for the report PDF.
    Keep phrasing in terms of "heuristics" and "signals" unless we actually validate exploitability.
    """
    rows: list[tuple[str, str]] = []

    if scope in {Report.SCOPE_NETWORK, Report.SCOPE_COMBINED}:
        rows.append(("Network", "TCP port probes, banner/version fingerprinting, DNS/SMB/VPN exposure checks, CVE signature heuristics"))

    if scope in {Report.SCOPE_WEB, Report.SCOPE_COMBINED}:
        if service_type == ServiceRequest.SERVICE_API:
            rows.append(("API", "OpenAPI/Swagger discovery, GraphQL check, rate-limiting probe, BOLA heuristic"))
        else:
            rows.append(("Web", "Header/CORS/TLS heuristics, safe SQL error probe, CSRF indicator heuristic"))
        rows.append(("Validation", "Budgeted safe validation probes (redirects, input-handling signals)"))

    if scope in {Report.SCOPE_CODE, Report.SCOPE_COMBINED}:
        rows.append(("Code", "Secrets patterns, dependency advisories, secure coding heuristics"))

    if scope == Report.SCOPE_CLOUD:
        rows.append(("Cloud", "CSPM checks (public storage exposure, network exposure, IAM hygiene)"))

    return rows[:4]


def _standards_referenced(scope: str, service_type: str | None) -> str:
    # "Referenced" means used for labeling/mapping guidance, not formal certification.
    base = ["OWASP Top 10", "ISO/IEC 27001", "CIS Controls/Benchmarks"]
    if scope in {Report.SCOPE_CODE, Report.SCOPE_COMBINED}:
        base.append("NIST 800-53 (selected mappings)")
    if service_type == ServiceRequest.SERVICE_API:
        base.append("OWASP API Security Top 10 (guidance)")
    return ", ".join(base)


def _inventory_rows(report: Report, findings_sorted: list[dict], metadata: dict) -> list[tuple[str, str, str]]:
    """
    Inventory is intentionally compact to keep the PDF within 2-3 pages.
    Returns rows of (category, count, examples).
    """
    service_request = report.service_request
    domains: set[str] = set()
    ip_ranges: set[str] = set()
    endpoints: set[str] = set()
    apps: set[str] = set()
    cloud_accounts: set[str] = set()

    if service_request:
        domain_url = (service_request.domain_url or "").strip()
        if domain_url:
            # domain_url may be a bare hostname or a full URL.
            if domain_url.startswith(("http://", "https://")):
                endpoints.add(domain_url)
                try:
                    parsed = urlparse(domain_url)
                    domains.add(parsed.netloc or domain_url)
                except Exception:
                    domains.add(domain_url)
            else:
                domains.add(domain_url)
        ip_cidr = (service_request.ip_cidr or "").strip()
        if ip_cidr:
            ip_ranges.add(ip_cidr)
        if getattr(service_request, "asset", None):
            name = (getattr(service_request.asset, "name", "") or "").strip()
            if name:
                apps.add(name)
        if getattr(service_request, "cloud_account", None):
            acct = service_request.cloud_account
            acct_name = (getattr(acct, "name", "") or "").strip() or "Cloud account"
            provider = getattr(acct, "provider", "") or ""
            cloud_accounts.add(f"{acct_name} ({provider})" if provider else acct_name)

    for item in findings_sorted:
        evidence = item.get("evidence") or {}
        if not isinstance(evidence, dict):
            continue
        tested_url = evidence.get("tested_url") or evidence.get("url")
        if isinstance(tested_url, str) and tested_url.startswith(("http://", "https://")):
            endpoints.add(tested_url)
            try:
                parsed = urlparse(tested_url)
                if parsed.netloc:
                    domains.add(parsed.netloc)
            except Exception:
                pass
        host = evidence.get("host")
        if isinstance(host, str) and host:
            domains.add(host)

    endpoints_count = int(metadata.get("endpoints_scanned") or metadata.get("endpoints_assessed") or 0)
    if endpoints_count <= 0 and endpoints:
        endpoints_count = len(endpoints)

    def _examples(values: set[str], limit: int = 2, max_len: int = 54) -> str:
        if not values:
            return "-"
        items = sorted(values)
        trimmed = []
        for v in items[:limit]:
            v = (v or "").strip()
            if len(v) > max_len:
                v = v[: max_len - 1].rstrip() + "..."
            trimmed.append(v)
        extra = len(items) - len(trimmed)
        suffix = f" (+{extra})" if extra > 0 else ""
        return ", ".join(trimmed) + suffix

    rows: list[tuple[str, str, str]] = []
    rows.append(("Domains / URLs", str(len(domains) or (1 if service_request and service_request.domain_url else 0)), _examples(domains)))
    rows.append(("IP Ranges", str(len(ip_ranges) or (1 if service_request and service_request.ip_cidr else 0)), _examples(ip_ranges)))
    rows.append(("API / Endpoints", str(endpoints_count), _examples(endpoints)))
    rows.append(("Apps / Assets", str(len(apps) or (1 if service_request and getattr(service_request, "asset_id", None) else 0)), _examples(apps)))
    rows.append(("Cloud Accounts", str(len(cloud_accounts) or (1 if service_request and getattr(service_request, "cloud_account_id", None) else 0)), _examples(cloud_accounts)))
    return rows


def _evidence_lines_for_finding(item: dict) -> list[str]:
    evidence = item.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}

    lines: list[str] = []
    ftype = item.get("type")

    if ftype == "code":
        file_path = evidence.get("file_path")
        line_number = evidence.get("line_number")
        category = evidence.get("category")
        secret_type = evidence.get("secret_type")
        if file_path:
            where = f"{file_path}:{line_number}" if line_number else str(file_path)
            lines.append(f"Location: {where}")
        if category:
            lines.append(f"Category: {category}")
        if secret_type:
            lines.append(f"Secret type: {secret_type}")
        masked = evidence.get("masked_value")
        if masked:
            lines.append(f"Masked value: {str(masked)[:72]}")

    elif ftype == "network":
        host = evidence.get("host")
        port = evidence.get("port")
        service = evidence.get("service")
        version = evidence.get("version")
        cve = evidence.get("cve")
        tested_url = evidence.get("tested_url")
        status_code = evidence.get("status_code")
        validation_type = evidence.get("validation_type")

        if host:
            lines.append(f"Host: {host}{(':' + str(port)) if port else ''}")
        if service or version:
            lines.append(f"Service: {(service or '').strip()} {(version or '').strip()}".strip())
        if cve:
            lines.append(f"CVE: {cve}")
        if validation_type:
            lines.append(f"Validation: {validation_type}")
        if tested_url:
            lines.append(f"Tested: {tested_url}")
            if isinstance(tested_url, str) and tested_url.startswith(("http://", "https://")):
                # Keep as a safe request example (no exploitation).
                lines.append(f"PoC: curl -i \"{tested_url}\"")
        if status_code:
            lines.append(f"HTTP status: {status_code}")

    elif ftype == "cloud":
        resource = evidence.get("resource") or evidence.get("control")
        if resource:
            lines.append(f"Resource: {resource}")
        provider = evidence.get("provider") or evidence.get("cloud_provider")
        if provider:
            lines.append(f"Provider: {provider}")
        bucket = evidence.get("bucket")
        if bucket:
            lines.append(f"Bucket: {bucket}")
        sg = evidence.get("security_group") or evidence.get("GroupId")
        if sg:
            lines.append(f"Security group: {sg}")

    if not lines:
        lines.append("Evidence: See appendix bundle for raw outputs.")
    lines.append("Screenshots/logs: See appendix bundle.")
    return lines[:6]


def _repro_steps_for_finding(item: dict) -> list[str]:
    evidence = item.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}

    steps: list[str] = []
    ftype = item.get("type")

    if ftype == "code":
        file_path = evidence.get("file_path")
        line_number = evidence.get("line_number")
        if file_path and line_number:
            steps.append(f"Open {file_path} and navigate to line {line_number}.")
        elif file_path:
            steps.append(f"Open {file_path} and search for the referenced pattern.")
        steps.append("Confirm the issue by reviewing the surrounding code/context.")
        steps.append("Apply remediation and re-run the scan to validate closure.")

    elif ftype == "network":
        tested_url = evidence.get("tested_url")
        host = evidence.get("host")
        port = evidence.get("port")
        validation_type = (evidence.get("validation_type") or "").lower()
        parameter = evidence.get("parameter")
        location = evidence.get("location")

        if tested_url and isinstance(tested_url, str) and tested_url.startswith(("http://", "https://")):
            steps.append(f"Request the URL with curl: {tested_url}")
        elif host and port:
            steps.append(f"From an authorized host, verify connectivity to {host}:{port}.")
        else:
            steps.append("Reproduce by re-running the scan against the same target scope.")

        if "redirect" in validation_type and parameter:
            steps.append(f"Confirm redirect behavior with parameter `{parameter}` and inspect the Location header.")
        if location:
            steps.append(f"Observed Location: {str(location)[:80]}")

        steps.append("Capture the response/status code as evidence for remediation verification.")

    elif ftype == "cloud":
        steps.append("Open the cloud console for the affected account and locate the referenced resource.")
        steps.append("Validate the configuration (public access / network exposure / IAM policy) matches the finding.")
        steps.append("Apply the recommended control change, then re-run the scan.")

    else:
        steps.append("Re-run the scan to confirm the condition.")

    return steps[:4]


def _compliance_table_rows(findings_sorted: list[dict]) -> list[tuple[str, int, str]]:
    """
    Produce a compact compliance mapping table.
    We only map what is explicitly tagged on findings to avoid misleading "inferred compliance".
    """
    frameworks = [
        ("ISO 27001", ("iso 27001", "iso/iec 27001", "iso27001", "iso")),
        ("PCI DSS", ("pci dss", "pcidss", "pci-dss", "pci")),
        ("SOC 2", ("soc 2", "soc2", "soc-2", "aicpa soc")),
        ("HIPAA", ("hipaa",)),
    ]

    tags: dict[str, set[str]] = {name: set() for name, _ in frameworks}
    counts: dict[str, set[int]] = {name: set() for name, _ in frameworks}  # unique finding indices

    annex_re = re.compile(r"\\bA\\.\\d+(?:\\.\\d+)?\\b", re.IGNORECASE)

    for idx, item in enumerate(findings_sorted, start=1):
        mappings = item.get("standard_mapping") or []
        if not isinstance(mappings, list):
            continue
        for raw in mappings:
            if not isinstance(raw, str):
                continue
            s = raw.strip()
            if not s:
                continue
            s_l = s.lower()
            for fw_name, needles in frameworks:
                if any(n in s_l for n in needles):
                    counts[fw_name].add(idx)
                    annexes = annex_re.findall(s)
                    if annexes:
                        for a in annexes:
                            tags[fw_name].add(a.upper())
                    else:
                        tags[fw_name].add(s[:48])

    rows: list[tuple[str, int, str]] = []
    for fw_name, _ in frameworks:
        tag_list = sorted(tags[fw_name])
        if not tag_list:
            tag_text = "-"
        else:
            tag_text = ", ".join(tag_list[:6])
            extra = len(tag_list) - min(len(tag_list), 6)
            if extra > 0:
                tag_text = f"{tag_text} (+{extra})"
        rows.append((fw_name, len(counts[fw_name]), tag_text))
    return rows


def _posture_for_report(report: Report, severity_counts: dict, metadata: dict) -> dict:
    posture = metadata.get("posture")
    if isinstance(posture, dict) and posture.get("score") is not None:
        return posture
    score = compute_posture_score(severity_counts=severity_counts, metadata=metadata)
    return {
        "score": score.score,
        "grade": score.grade,
        "penalty": score.penalty,
        "attack_surface_units": score.attack_surface_units,
        "breakdown": score.breakdown,
    }


def _insights_for_report(report: Report, findings_sorted: list[dict], metadata: dict) -> dict:
    """
    Fetch insights from stored metadata when present; otherwise compute from collected findings.
    """
    service_request = report.service_request
    service_type = service_request.service_type if service_request else None

    threat_model = metadata.get("threat_model")
    exploit_chains = metadata.get("exploit_chains")
    maturity = metadata.get("maturity")

    if not isinstance(threat_model, dict) or not threat_model:
        threat_model = compute_threat_model_snapshot(findings=findings_sorted, metadata=metadata, service_type=service_type)
    if not isinstance(exploit_chains, list) or exploit_chains is None:
        exploit_chains = compute_exploit_chains(findings=findings_sorted)
    if not isinstance(maturity, dict) or not maturity:
        maturity = compute_security_maturity(findings=findings_sorted, metadata=metadata)

    return {"threat_model": threat_model, "exploit_chains": exploit_chains, "maturity": maturity}


def _posture_trend_for_report(report: Report, limit: int = 6) -> list[dict]:
    """
    Return last N posture points for same org + same scope, oldest->newest.
    Uses stored metadata posture when available; falls back to computing from metadata/severity summary.
    """
    qs = (
        Report.objects.filter(organization_id=report.organization_id, scope=report.scope)
        .order_by("-generated_at", "-created_at")
    )
    points: list[dict] = []
    for r in qs[: max(1, limit)]:
        md = r.metadata or {}
        sev = (md.get("severity_summary") or {}) if isinstance(md, dict) else {}
        if not isinstance(sev, dict):
            sev = {}
        posture = md.get("posture") if isinstance(md, dict) else None
        if not (isinstance(posture, dict) and posture.get("score") is not None):
            p = compute_posture_score(severity_counts=sev, metadata=md if isinstance(md, dict) else {})
            posture = {"score": p.score, "grade": p.grade}
        points.append(
            {
                "generated_at": r.generated_at,
                "score": int(posture.get("score") or 0),
                "grade": str(posture.get("grade") or ""),
                "critical": int(sev.get("critical") or 0),
                "high": int(sev.get("high") or 0),
            }
        )
    return list(reversed(points))


def _severity_impact_lines() -> list[str]:
    return [
        "Critical: Immediate risk of unauthorized access or data compromise.",
        "High: Significant exposure that increases attack surface and lateral movement risk.",
        "Medium: Weaknesses that may be chained with other issues.",
        "Low: Hardening and defense-in-depth improvements.",
    ]


def _why_it_matters(finding: dict) -> str:
    if finding["type"] == "network":
        if finding.get("evidence", {}).get("validation_type"):
            return (
                "Active security validation highlighted a potential control gap that could be abused by attackers "
                "if left unaddressed."
            )
        return "Exposed services can be targeted for unauthorized access or used as pivot points."
    if finding["type"] == "cloud":
        return "Cloud misconfigurations can expose data or administrative access and should be remediated promptly."
    if finding.get("evidence", {}).get("category") == CodeFinding.CATEGORY_SECRETS:
        return "Leaked secrets can provide direct access to infrastructure or sensitive data."
    if finding.get("evidence", {}).get("category") == CodeFinding.CATEGORY_DEPENDENCY:
        return "Known vulnerable dependencies can introduce exploit paths into production systems."
    return "Security weaknesses increase the likelihood of exploitation and compliance risk."


def _default_remediation(finding: dict) -> str:
    if finding["type"] == "network":
        if finding.get("evidence", {}).get("validation_type"):
            return "Harden access controls, enforce secure defaults, and document safe validation coverage."
        return "Restrict exposed services, enforce secure configurations, and apply latest patches."
    if finding["type"] == "cloud":
        return "Restrict public access, harden IAM policies, and enable continuous cloud posture monitoring."
    if finding.get("evidence", {}).get("category") == CodeFinding.CATEGORY_SECRETS:
        return "Rotate exposed credentials, remove secrets from code, and enforce secret scanning in CI."
    if finding.get("evidence", {}).get("category") == CodeFinding.CATEGORY_DEPENDENCY:
        return "Upgrade dependencies to patched versions and validate through regression testing."
    return "Apply secure configuration and patching guidance for the affected component."


def _detection_summary(finding: dict) -> str:
    if finding["type"] == "network":
        if finding.get("evidence", {}).get("validation_type"):
            return "Safe, non-destructive validation checks observed response behavior without exploitation."
        return "TCP connectivity checks and protocol inspection confirmed exposure."
    if finding["type"] == "cloud":
        return "Read-only cloud control-plane checks identified a configuration control gap."
    if finding.get("evidence", {}).get("category") == CodeFinding.CATEGORY_SECRETS:
        return "Pattern and entropy analysis detected a likely secret in source code."
    if finding.get("evidence", {}).get("category") == CodeFinding.CATEGORY_DEPENDENCY:
        return "Dependency manifest analysis matched a known vulnerable version."
    return "Static analysis identified a security control or configuration weakness."


def _remediation_bullets(finding: dict) -> list[str]:
    if finding["type"] == "network":
        if finding.get("evidence", {}).get("validation_type"):
            return [
                "Confirm access control requirements for the affected endpoint",
                "Apply secure defaults (headers, cookies, authentication)",
                "Document the validation outcome and retest after changes",
                "Monitor and alert on anomalous access patterns",
            ]
        return [
            "Restrict access to trusted IP ranges",
            "Enforce secure configuration defaults",
            "Patch to the latest supported version",
            "Monitor access attempts and telemetry",
        ]
    if finding["type"] == "cloud":
        return [
            "Remove public exposure where not required",
            "Apply least-privilege IAM policies",
            "Enable logging and continuous monitoring",
            "Validate configuration against cloud benchmarks",
        ]
    if finding.get("evidence", {}).get("category") == CodeFinding.CATEGORY_SECRETS:
        return [
            "Rotate exposed credentials immediately",
            "Remove secrets from source code",
            "Implement secret scanning in CI/CD",
        ]
    if finding.get("evidence", {}).get("category") == CodeFinding.CATEGORY_DEPENDENCY:
        return [
            "Upgrade to a patched dependency version",
            "Lock versions and validate with tests",
            "Track vulnerability advisories continuously",
        ]
    return [
        "Apply secure configuration guidance",
        "Add validation and control checks",
        "Monitor for regression after fixes",
    ]


def _ai_recommendations(report: Report, findings: list[dict]) -> str:
    metadata = report.metadata or {}
    ai_text = metadata.get("ai_recommendations") or metadata.get("ai_summary")
    if ai_text:
        return ai_text
    severity_counts = _severity_counts_for_report(report)
    if not findings:
        return explain_report_summary(report.scope, severity_counts)
    top = findings[:3]
    actions = []
    for item in top:
        if item["type"] == "network":
            actions.append("Restrict exposed services and enforce secure defaults.")
        elif item["type"] == "cloud":
            actions.append("Harden cloud configurations and restrict public exposure.")
        elif item.get("evidence", {}).get("category") == CodeFinding.CATEGORY_SECRETS:
            actions.append("Rotate exposed credentials and remove secrets from source control.")
        elif item.get("evidence", {}).get("category") == CodeFinding.CATEGORY_DEPENDENCY:
            actions.append("Upgrade vulnerable dependencies and validate with regression tests.")
        else:
            actions.append("Apply secure configuration guidance and verify controls.")
    deduped = []
    for action in actions:
        if action not in deduped:
            deduped.append(action)
    base_summary = explain_report_summary(report.scope, severity_counts)
    return f"{base_summary} " + " ".join(deduped)


def _risk_scenarios(findings: list[dict]) -> list[str]:
    scenarios = []
    for finding in findings:
        scenarios.append(
            f"If '{finding['title']}' is exploited, an attacker could gain access to {finding['asset']} and expand access within the environment."
        )
    if not scenarios:
        scenarios.append("No critical attack paths were identified in this assessment.")
    return scenarios


def _remediation_roadmap(scope: str) -> list[str]:
    if scope == Report.SCOPE_CODE:
        return [
            "Immediate: Rotate exposed secrets and revoke compromised tokens.",
            "Short-term: Patch vulnerable dependencies and lock versions.",
            "Medium-term: Add automated secret and dependency scanning to CI/CD.",
        ]
    if scope == Report.SCOPE_NETWORK:
        return [
            "Immediate: Restrict exposed administrative ports to trusted IP ranges.",
            "Short-term: Enforce TLS 1.2+ and disable weak protocols.",
            "Medium-term: Implement segmentation and continuous monitoring.",
        ]
    if scope == Report.SCOPE_CLOUD:
        return [
            "Immediate: Restrict public access to storage and admin endpoints.",
            "Short-term: Harden IAM policies and rotate privileged credentials.",
            "Medium-term: Enable continuous CSPM monitoring and alerts.",
        ]
    return [
        "Immediate: Address critical exposure paths and rotate credentials.",
        "Short-term: Patch vulnerable dependencies and harden configurations.",
        "Medium-term: Establish continuous monitoring and segmentation controls.",
    ]


def _roadmap_cards(scope: str) -> list[tuple[str, str, str]]:
    if scope == Report.SCOPE_CODE:
        return [
            ("Immediate Actions", "Rotate exposed secrets and revoke compromised tokens.", "Engineering"),
            ("Short-term Goals", "Patch vulnerable dependencies and lock versions.", "Engineering"),
            ("Medium-term Strategy", "Add automated SAST and dependency scanning.", "Security Team"),
            ("Long-term Initiatives", "Adopt secure coding standards across repos.", "Security Team"),
        ]
    if scope == Report.SCOPE_WEB:
        return [
            ("Immediate Actions", "Harden exposed endpoints and headers.", "Application Team"),
            ("Short-term Goals", "Enforce TLS 1.2+ and remove weak ciphers.", "Infrastructure Team"),
            ("Medium-term Strategy", "Implement continuous validation checks.", "Security Team"),
            ("Long-term Initiatives", "Establish regular web security assessments.", "Security Team"),
        ]
    if scope == Report.SCOPE_NETWORK:
        return [
            ("Immediate Actions", "Restrict exposed administrative ports.", "Infrastructure Team"),
            ("Short-term Goals", "Harden TLS configurations across affected services.", "Infrastructure Team"),
            ("Medium-term Strategy", "Implement network segmentation for critical assets.", "Security Team"),
            ("Long-term Initiatives", "Establish continuous monitoring and threat detection.", "Security Team"),
        ]
    if scope == Report.SCOPE_CLOUD:
        return [
            ("Immediate Actions", "Restrict public storage and admin access.", "Cloud Operations"),
            ("Short-term Goals", "Harden IAM policies and rotate credentials.", "Cloud Operations"),
            ("Medium-term Strategy", "Enable CSPM guardrails and alerting.", "Security Team"),
            ("Long-term Initiatives", "Establish continuous cloud posture monitoring.", "Security Team"),
        ]
    return [
        ("Immediate Actions", "Address critical exposure paths and rotate credentials.", "Security Team"),
        ("Short-term Goals", "Patch vulnerable dependencies and harden configurations.", "Engineering"),
        ("Medium-term Strategy", "Implement continuous scanning and validation.", "Security Team"),
        ("Long-term Initiatives", "Formalize secure development and ops standards.", "Security Team"),
    ]


def _severity_counts_for_report(report: Report) -> dict:
    summary = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    scan_job = report.scan_job
    if not scan_job:
        return summary

    service_request = report.service_request
    if report.scope == Report.SCOPE_CODE:
        code_qs = CodeFinding.objects.filter(scan_job=scan_job)
        if not code_qs.exists():
            if service_request:
                code_qs = CodeFinding.objects.filter(service_request=service_request)
            elif getattr(scan_job, "repository_id", None):
                code_qs = CodeFinding.objects.filter(repository=scan_job.repository, scan_job__isnull=True)
        querysets = [code_qs]
    elif report.scope == Report.SCOPE_COMBINED:
        code_qs = CodeFinding.objects.filter(scan_job=scan_job)
        net_qs = NetworkFinding.objects.filter(scan_job=scan_job)
        if not code_qs.exists():
            if service_request:
                code_qs = CodeFinding.objects.filter(service_request=service_request)
            elif getattr(scan_job, "repository_id", None):
                code_qs = CodeFinding.objects.filter(repository=scan_job.repository, scan_job__isnull=True)
        if not net_qs.exists():
            if service_request:
                net_qs = NetworkFinding.objects.filter(service_request=service_request)
            elif getattr(scan_job, "asset_id", None):
                net_qs = NetworkFinding.objects.filter(
                    network_asset__organization=report.organization,
                    network_asset__asset=scan_job.asset,
                    scan_job__isnull=True,
                )
        querysets = [code_qs, net_qs]
    elif report.scope == Report.SCOPE_CLOUD:
        cloud_qs = CloudFinding.objects.filter(scan_job=scan_job)
        if not cloud_qs.exists() and service_request:
            cloud_qs = CloudFinding.objects.filter(service_request=service_request)
        querysets = [cloud_qs]
    else:
        net_qs = NetworkFinding.objects.filter(scan_job=scan_job)
        if not net_qs.exists():
            if service_request:
                net_qs = NetworkFinding.objects.filter(service_request=service_request)
            elif getattr(scan_job, "asset_id", None):
                net_qs = NetworkFinding.objects.filter(
                    network_asset__organization=report.organization,
                    network_asset__asset=scan_job.asset,
                    scan_job__isnull=True,
                )
        querysets = [net_qs]
    for queryset in querysets:
        for severity in queryset.values_list("severity", flat=True):
            summary[severity] = summary.get(severity, 0) + 1
    return summary


def _trend_lines(report: Report, current_counts: dict) -> list[str]:
    previous = (
        Report.objects.filter(organization=report.organization, scope=report.scope, generated_at__lt=report.generated_at)
        .exclude(id=report.id)
        .order_by("-generated_at")
        .first()
    )
    if not previous:
        return ["No prior report available for trend comparison."]

    previous_counts = _severity_counts_for_report(previous)
    return [
        f"Previous scan ({previous.generated_at:%Y-%m-%d}): critical {previous_counts['critical']}, high {previous_counts['high']}, medium {previous_counts['moderate']}, low {previous_counts['low']}.",
        f"Current scan ({report.generated_at:%Y-%m-%d}): critical {current_counts['critical']}, high {current_counts['high']}, medium {current_counts['moderate']}, low {current_counts['low']}.",
        "Overall exposure should trend downward as remediation is applied.",
    ]


