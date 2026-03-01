from rest_framework import viewsets, status, mixins
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from core.models import OrganizationQuerySetMixin
from core.permissions import OrganizationAccessPermission
from accounts.models import UserOrganization
from assets.models import Asset
from incidents.models import Incident
from code_security.models import CodeFinding
from network_security.models import NetworkFinding
from reports.models import Report
from core.posture import compute_posture_score
from .models import Scan, ScanJob, ScanRequest, ScanAlert
from django.utils import timezone
from datetime import timedelta
from .serializers import ScanSerializer, ScanJobSerializer, ScanRequestSerializer, ScanAlertSerializer
from .tasks import execute_scan_job


class ScanViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = ScanSerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    organization_field = "organization"
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD]

    def get_queryset(self):
        return self.filter_by_organization(Scan.objects.all(), self.request.user)


class ScanJobViewSet(OrganizationQuerySetMixin, viewsets.ModelViewSet):
    serializer_class = ScanJobSerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    organization_field = "organization"
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD]

    def get_queryset(self):
        queryset = ScanJob.objects.select_related(
            "organization",
            "asset",
            "repository",
            "service_request",
            "created_by",
        ).prefetch_related("reports")
        return self.filter_by_organization(queryset, self.request.user)

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        if request.user.organization:
            data["organization"] = str(request.user.organization.id)
        data["created_by"] = str(request.user.id)
        data["initiated_by"] = str(request.user.id)
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        execute_scan_job.delay(str(serializer.instance.id))
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class ScanRequestViewSet(
    OrganizationQuerySetMixin,
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = ScanRequestSerializer
    permission_classes = [IsAuthenticated]
    organization_field = "organization"

    def get_queryset(self):
        return self.filter_by_organization(ScanRequest.objects.all(), self.request.user).order_by("-created_at")

    def perform_create(self, serializer):
        org = self.request.user.organization
        if not org:
            raise ValidationError({"organization": "No organization assigned to this user."})
        serializer.save(organization=org, requested_by=self.request.user)


class SecurityStatusView(APIView):
    permission_classes = [IsAuthenticated]

    @staticmethod
    def _severity_weight(severity: str) -> int:
        weights = {
            CodeFinding.SEVERITY_CRITICAL: 20,
            CodeFinding.SEVERITY_HIGH: 12,
            CodeFinding.SEVERITY_MODERATE: 6,
            CodeFinding.SEVERITY_LOW: 2,
            NetworkFinding.SEVERITY_CRITICAL: 20,
            NetworkFinding.SEVERITY_HIGH: 12,
            NetworkFinding.SEVERITY_MODERATE: 6,
            NetworkFinding.SEVERITY_LOW: 2,
        }
        return weights.get(severity, 2)

    def _compliance_summary(self, code_findings, network_findings):
        standards = {
            "owasp_top_10": "OWASP",
            "iso_27001": "ISO",
            "nist_800_53": "NIST",
        }
        summary = {}
        for key, marker in standards.items():
            mapped = [
                f for f in code_findings
                if any(marker in mapping for mapping in (f.standard_mapping or []))
            ]
            if not mapped:
                summary[key] = "Not Assessed"
                continue
            has_high = any(f.severity in (CodeFinding.SEVERITY_CRITICAL, CodeFinding.SEVERITY_HIGH) for f in mapped)
            summary[key] = "Partial" if has_high else "Covered"
        return summary

    def get(self, request):
        user = request.user
        if user.is_superuser:
            assets_count = Asset.objects.count()
            scans_count = Scan.objects.count()
            incidents_open = Incident.objects.filter(status=Incident.STATUS_OPEN).count()
            code_findings = CodeFinding.objects.all()
            network_findings = NetworkFinding.objects.all()
            report_qs = Report.objects.all()
        else:
            org = user.organization
            assets_count = Asset.objects.filter(organization=org).count() if org else 0
            scans_count = Scan.objects.filter(organization=org).count() if org else 0
            incidents_open = Incident.objects.filter(organization=org, status=Incident.STATUS_OPEN).count() if org else 0
            code_findings = CodeFinding.objects.filter(repository__organization=org) if org else CodeFinding.objects.none()
            network_findings = NetworkFinding.objects.filter(network_asset__organization=org) if org else NetworkFinding.objects.none()
            report_qs = Report.objects.filter(organization=org) if org else Report.objects.none()

        open_code = code_findings.filter(status=CodeFinding.STATUS_OPEN)
        open_network = network_findings.filter(status=NetworkFinding.STATUS_OPEN)

        severity_counts = {
            "critical": open_code.filter(severity=CodeFinding.SEVERITY_CRITICAL).count()
            + open_network.filter(severity=NetworkFinding.SEVERITY_CRITICAL).count(),
            "high": open_code.filter(severity=CodeFinding.SEVERITY_HIGH).count()
            + open_network.filter(severity=NetworkFinding.SEVERITY_HIGH).count(),
            "moderate": open_code.filter(severity=CodeFinding.SEVERITY_MODERATE).count()
            + open_network.filter(severity=NetworkFinding.SEVERITY_MODERATE).count(),
            "low": open_code.filter(severity=CodeFinding.SEVERITY_LOW).count()
            + open_network.filter(severity=NetworkFinding.SEVERITY_LOW).count(),
        }

        # Prefer report-backed scoring (uses scan metadata); fall back to open finding counts.
        posture_trend = []
        for r in report_qs.order_by("-generated_at", "-created_at")[:6]:
            md = r.metadata or {}
            sev = (md.get("severity_summary") or {}) if isinstance(md, dict) else {}
            if not isinstance(sev, dict):
                sev = {}
            posture = md.get("posture") if isinstance(md, dict) else None
            if not (isinstance(posture, dict) and posture.get("score") is not None):
                p = compute_posture_score(severity_counts=sev, metadata=md if isinstance(md, dict) else {})
                posture = {"score": p.score, "grade": p.grade}
            posture_trend.append({"month": r.generated_at.strftime("%b %d"), "score": int(posture.get("score") or 0)})
        posture_trend = list(reversed(posture_trend))

        if posture_trend:
            security_score = posture_trend[-1]["score"]
        else:
            p = compute_posture_score(severity_counts=severity_counts, metadata={"assets": assets_count})
            security_score = p.score

        compliance_summary = self._compliance_summary(code_findings, network_findings)
        status = "Green"
        if security_score < 70:
            status = "Amber"
        if security_score < 50:
            status = "Red"

        summary = {
            "security_score": security_score,
            # Keep shape stable for the current frontend: include "high" inside critical bucket.
            "risk_summary": {
                "critical": int(severity_counts["critical"] + severity_counts["high"]),
                "moderate": int(severity_counts["moderate"]),
                "low": int(severity_counts["low"]),
            },
            "assets_monitored": assets_count,
            "scans_last_30_days": scans_count,
            "open_incidents": incidents_open,
            "compliance_summary": compliance_summary,
            "posture_trend": posture_trend,
            "status_banner": {
                "status": status,
                "headline": "Security posture is stable" if status == "Green" else "Elevated exposure detected",
                "detail": "Key controls are in place. Continue remediation work." if status == "Green" else "Prioritize remediation of high-severity findings and exposed services.",
            },
        }
        return Response(summary)


class AnalystMetricsView(OrganizationQuerySetMixin, APIView):
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    required_roles = [UserOrganization.ROLE_SECURITY_LEAD]
    organization_field = "organization"

    @staticmethod
    def _week_start(value):
        return (value - timedelta(days=value.weekday())).date()

    def get(self, request):
        user = request.user
        org = None
        if not (user.is_superuser or user.is_staff):
            org = getattr(user, "organization", None)
            if not org:
                return Response(
                    {
                        "summary": {
                            "open_findings": 0,
                            "critical": 0,
                            "high": 0,
                            "moderate": 0,
                            "low": 0,
                            "active_scans": 0,
                            "scan_jobs_running": 0,
                            "reports_ready": 0,
                            "mttr_days": None,
                            "assets_at_risk": 0,
                        },
                        "severity_trend": [],
                        "scan_volume": [],
                        "finding_breakdown": [],
                        "exposure_hotspots": [],
                        "report_trend": [],
                    }
                )

        code_qs = CodeFinding.objects.all()
        network_qs = NetworkFinding.objects.all()
        scan_job_qs = ScanJob.objects.all()
        report_qs = Report.objects.all()

        if org:
            code_qs = code_qs.filter(repository__organization=org)
            network_qs = network_qs.filter(network_asset__organization=org)
            scan_job_qs = scan_job_qs.filter(organization=org)
            report_qs = report_qs.filter(organization=org)

        open_code = code_qs.filter(status=CodeFinding.STATUS_OPEN)
        open_network = network_qs.filter(status=NetworkFinding.STATUS_OPEN)
        open_findings = open_code.count() + open_network.count()

        severity_counts = {
            "critical": open_code.filter(severity=CodeFinding.SEVERITY_CRITICAL).count()
            + open_network.filter(severity=NetworkFinding.SEVERITY_CRITICAL).count(),
            "high": open_code.filter(severity=CodeFinding.SEVERITY_HIGH).count()
            + open_network.filter(severity=NetworkFinding.SEVERITY_HIGH).count(),
            "moderate": open_code.filter(severity=CodeFinding.SEVERITY_MODERATE).count()
            + open_network.filter(severity=NetworkFinding.SEVERITY_MODERATE).count(),
            "low": open_code.filter(severity=CodeFinding.SEVERITY_LOW).count()
            + open_network.filter(severity=NetworkFinding.SEVERITY_LOW).count(),
        }

        active_scans = scan_job_qs.filter(status__in=[ScanJob.STATUS_QUEUED, ScanJob.STATUS_RUNNING]).count()
        scan_jobs_running = scan_job_qs.filter(status=ScanJob.STATUS_RUNNING).count()
        reports_ready = report_qs.count()

        resolved_code = code_qs.filter(status=CodeFinding.STATUS_RESOLVED, resolved_at__isnull=False)
        resolved_network = network_qs.filter(status=NetworkFinding.STATUS_RESOLVED, resolved_at__isnull=False)
        mttr_samples = []
        for finding in resolved_code:
            mttr_samples.append((finding.resolved_at - finding.created_at).total_seconds())
        for finding in resolved_network:
            mttr_samples.append((finding.resolved_at - finding.created_at).total_seconds())
        mttr_days = round(sum(mttr_samples) / len(mttr_samples) / 86400, 2) if mttr_samples else None

        assets_at_risk = (
            open_code.values("repository_id").distinct().count()
            + open_network.values("network_asset_id").distinct().count()
        )

        now = timezone.now()
        start_date = now - timedelta(weeks=8)
        weeks = [self._week_start(now - timedelta(weeks=offset)) for offset in range(7, -1, -1)]
        severity_trend = {
            week.isoformat(): {"period": week.isoformat(), "critical": 0, "high": 0, "moderate": 0, "low": 0}
            for week in weeks
        }
        for finding in code_qs.filter(created_at__gte=start_date):
            key = self._week_start(finding.created_at).isoformat()
            if key in severity_trend:
                severity_trend[key][finding.severity] += 1
        for finding in network_qs.filter(created_at__gte=start_date):
            key = self._week_start(finding.created_at).isoformat()
            if key in severity_trend:
                severity_trend[key][finding.severity] += 1

        scan_volume = {
            week.isoformat(): {"period": week.isoformat(), "code": 0, "web": 0, "network": 0, "infrastructure": 0}
            for week in weeks
        }
        for job in scan_job_qs.filter(created_at__gte=start_date):
            key = self._week_start(job.created_at).isoformat()
            if key in scan_volume:
                if job.scan_type == ScanJob.TYPE_CODE:
                    scan_volume[key]["code"] += 1
                elif job.scan_type in [ScanJob.TYPE_WEB, ScanJob.TYPE_API]:
                    scan_volume[key]["web"] += 1
                elif job.scan_type == ScanJob.TYPE_NETWORK:
                    scan_volume[key]["network"] += 1
                elif job.scan_type == ScanJob.TYPE_INFRA:
                    scan_volume[key]["infrastructure"] += 1

        finding_breakdown = {
            "secrets": 0,
            "dependency": 0,
            "sast": 0,
            "exposed_service": 0,
            "misconfiguration": 0,
            "segmentation_risk": 0,
            "active_validation": 0,
        }
        for finding in code_qs:
            finding_breakdown[finding.category] = finding_breakdown.get(finding.category, 0) + 1
        for finding in network_qs:
            finding_breakdown[finding.finding_type] = finding_breakdown.get(finding.finding_type, 0) + 1

        exposure_counts = {}
        for finding in open_network:
            evidence = finding.evidence or {}
            host = evidence.get("host")
            if not host:
                continue
            port = evidence.get("port")
            label = f"{host}:{port}" if port else str(host)
            exposure_counts[label] = exposure_counts.get(label, 0) + 1
        exposure_hotspots = [
            {"label": label, "count": count}
            for label, count in sorted(exposure_counts.items(), key=lambda item: item[1], reverse=True)[:6]
        ]

        report_trend = {week.isoformat(): {"period": week.isoformat(), "count": 0} for week in weeks}
        for report in report_qs.filter(generated_at__gte=start_date):
            key = self._week_start(report.generated_at).isoformat()
            if key in report_trend:
                report_trend[key]["count"] += 1

        summary = {
            "open_findings": open_findings,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "moderate": severity_counts["moderate"],
            "low": severity_counts["low"],
            "active_scans": active_scans,
            "scan_jobs_running": scan_jobs_running,
            "reports_ready": reports_ready,
            "mttr_days": mttr_days,
            "assets_at_risk": assets_at_risk,
        }

        return Response(
            {
                "summary": summary,
                "severity_trend": list(severity_trend.values()),
                "scan_volume": list(scan_volume.values()),
                "finding_breakdown": [
                    {"name": "Secrets", "value": finding_breakdown["secrets"]},
                    {"name": "Dependencies", "value": finding_breakdown["dependency"]},
                    {"name": "Code Standards", "value": finding_breakdown["sast"]},
                    {"name": "Exposed Services", "value": finding_breakdown["exposed_service"]},
                    {"name": "Misconfigurations", "value": finding_breakdown["misconfiguration"]},
                    {"name": "Segmentation Risks", "value": finding_breakdown["segmentation_risk"]},
                    {"name": "Active Validation", "value": finding_breakdown["active_validation"]},
                ],
                "exposure_hotspots": exposure_hotspots,
                "report_trend": list(report_trend.values()),
            }
        )


class ScanAlertViewSet(OrganizationQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = ScanAlertSerializer
    permission_classes = [IsAuthenticated, OrganizationAccessPermission]
    organization_field = "organization"

    def get_queryset(self):
        return self.filter_by_organization(ScanAlert.objects.all(), self.request.user).order_by("-created_at")
