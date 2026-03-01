from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import HttpResponse
from django.db import models
from django.utils import timezone
from datetime import timedelta
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from accounts.models import Organization, User, UserOrganization, OrganizationScanPolicy
from assets.models import Asset
from assets.serializers import AssetSerializer
from code_security.models import CodeRepository
from scans.models import Scan, ScanJob, ScanRequest, ScanSchedule, ScanAlert
from scans.tasks import execute_scan_job
from service_requests.models import ServiceRequest
from service_requests.tasks import execute_service_request_job
from incidents.models import Incident
from activity_log.models import ActivityLog
from reports.models import Report
from reports.views import build_report_pdf, build_report_appendix_bundle
from core.posture import compute_posture_score
from .permissions import IsInternalAdmin
from .serializers import (
    OrganizationAdminSerializer,
    OrganizationScanPolicySerializer,
    UserAdminSerializer,
    ScanJobAdminSerializer,
    ScanRequestAdminSerializer,
    ScanScheduleAdminSerializer,
    ScanAlertAdminSerializer,
    IncidentAdminSerializer,
    ActivityLogAdminSerializer,
    ReportAdminSerializer,
)

import ipaddress
import os


class AuditMixin:
    def log_action(self, request, action: str, metadata: dict | None = None, organization: Organization | None = None):
        if not request.user.is_authenticated:
            return
        org = organization or getattr(request.user, "organization", None) or Organization.objects.first()
        if not org:
            return
        ActivityLog.objects.create(
            organization=org,
            user=request.user,
            action=action,
            timestamp=self._now(),
            metadata=metadata or {},
        )

    @staticmethod
    def _now():
        from django.utils import timezone
        return timezone.now()

    def perform_create(self, serializer):
        instance = serializer.save()
        self.log_action(
            self.request,
            f"{self.__class__.__name__} created",
            {"id": str(instance.id)},
            organization=getattr(instance, "organization", None),
        )

    def perform_update(self, serializer):
        instance = serializer.save()
        self.log_action(
            self.request,
            f"{self.__class__.__name__} updated",
            {"id": str(instance.id)},
            organization=getattr(instance, "organization", None),
        )

    def perform_destroy(self, instance):
        instance_id = str(instance.id)
        organization = getattr(instance, "organization", None)
        instance.delete()
        self.log_action(
            self.request,
            f"{self.__class__.__name__} deleted",
            {"id": instance_id},
            organization=organization,
        )


class OrganizationInternalViewSet(AuditMixin, viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    @action(detail=True, methods=["get", "post"], url_path="scan-policy")
    def scan_policy(self, request, pk=None):
        """
        Internal admin endpoint to manage organization-level scan guardrails.

        POST accepts partial updates for:
        - ssrf_high_risk_enabled: bool
        - ssrf_allow_metadata: bool
        - ssrf_allowlist: dict with keys domains/cidrs/urls
        - inventory_expectations: dict with expected inventory counts (optional)
        """
        org = self.get_object()
        policy, _ = OrganizationScanPolicy.objects.get_or_create(organization=org)

        def _normalize_policy(p: OrganizationScanPolicy) -> dict:
            allowlist = p.ssrf_allowlist if isinstance(p.ssrf_allowlist, dict) else {}
            inv = p.inventory_expectations if isinstance(p.inventory_expectations, dict) else {}
            return {
                "ssrf_high_risk_enabled": bool(p.ssrf_high_risk_enabled),
                "ssrf_allow_metadata": bool(p.ssrf_allow_metadata),
                "ssrf_allowlist": {
                    "domains": [str(x) for x in (allowlist.get("domains") or []) if str(x).strip()][:200],
                    "cidrs": [str(x) for x in (allowlist.get("cidrs") or []) if str(x).strip()][:200],
                    "urls": [str(x) for x in (allowlist.get("urls") or []) if str(x).strip()][:200],
                },
                "inventory_expectations": {str(k): int(v) for k, v in inv.items() if str(k).strip()},
            }

        def _diff_policy(before: dict, after: dict) -> dict:
            diff: dict = {"changed_fields": []}
            for key in ("ssrf_high_risk_enabled", "ssrf_allow_metadata"):
                if before.get(key) != after.get(key):
                    diff["changed_fields"].append(key)
                    diff.setdefault("field_changes", {})[key] = {"before": before.get(key), "after": after.get(key)}

            # Allowlist diffs (added/removed) per bucket.
            b_al = before.get("ssrf_allowlist") or {}
            a_al = after.get("ssrf_allowlist") or {}
            allowlist_changes: dict = {}
            for key in ("domains", "cidrs", "urls"):
                b = [str(x).strip() for x in (b_al.get(key) or []) if str(x).strip()]
                a = [str(x).strip() for x in (a_al.get(key) or []) if str(x).strip()]
                b_set = set(b)
                a_set = set(a)
                added = sorted(a_set - b_set)[:50]
                removed = sorted(b_set - a_set)[:50]
                if added or removed:
                    diff["changed_fields"].append(f"ssrf_allowlist.{key}")
                    allowlist_changes[key] = {
                        "added": added,
                        "removed": removed,
                        "truncated": (len(a_set - b_set) > 50) or (len(b_set - a_set) > 50),
                    }
            if allowlist_changes:
                diff["allowlist_changes"] = allowlist_changes

            # Inventory expectation diffs.
            b_inv = before.get("inventory_expectations") or {}
            a_inv = after.get("inventory_expectations") or {}
            inv_keys = sorted(set(list(b_inv.keys()) + list(a_inv.keys())))
            inv_changes: list[dict] = []
            for k in inv_keys:
                if int(b_inv.get(k, 0) or 0) != int(a_inv.get(k, 0) or 0):
                    inv_changes.append({"key": k, "before": int(b_inv.get(k, 0) or 0), "after": int(a_inv.get(k, 0) or 0)})
            if inv_changes:
                diff["changed_fields"].append("inventory_expectations")
                diff["inventory_changes"] = inv_changes[:50]
                diff["inventory_truncated"] = len(inv_changes) > 50
            return diff

        if request.method.lower() == "post":
            before_state = _normalize_policy(policy)
            payload = request.data or {}
            if "ssrf_high_risk_enabled" in payload:
                policy.ssrf_high_risk_enabled = bool(payload.get("ssrf_high_risk_enabled"))
            if "ssrf_allow_metadata" in payload:
                policy.ssrf_allow_metadata = bool(payload.get("ssrf_allow_metadata"))
            if "ssrf_allowlist" in payload:
                allowlist = payload.get("ssrf_allowlist")
                if not isinstance(allowlist, dict):
                    raise ValidationError({"ssrf_allowlist": "ssrf_allowlist must be an object/dict."})
                for key in ("domains", "cidrs", "urls"):
                    if key in allowlist and not isinstance(allowlist.get(key), list):
                        raise ValidationError({f"ssrf_allowlist.{key}": "Must be a list."})
                policy.ssrf_allowlist = allowlist
            if "inventory_expectations" in payload:
                expectations = payload.get("inventory_expectations") or {}
                if expectations is None:
                    expectations = {}
                if not isinstance(expectations, dict):
                    raise ValidationError({"inventory_expectations": "Must be an object (e.g., {\"domains\": 1, \"apis\": 1})."})
                cleaned: dict = {}
                for key, value in expectations.items():
                    k = str(key).strip()
                    if not k:
                        continue
                    try:
                        cleaned[k] = max(0, int(value))
                    except Exception:
                        continue
                policy.inventory_expectations = cleaned
            policy.save()
            after_state = _normalize_policy(policy)
            policy_diff = _diff_policy(before_state, after_state)
            self.log_action(
                request,
                "Organization scan policy updated",
                {
                    "organization_id": str(org.id),
                    "policy_id": str(policy.id),
                    "diff": policy_diff,
                },
                organization=org,
            )

        serializer = OrganizationScanPolicySerializer(policy)
        return Response(serializer.data)


class AssetInternalViewSet(AuditMixin, viewsets.ModelViewSet):
    queryset = Asset.objects.all().select_related("organization")
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset().order_by("-created_at")
        org_id = self.request.query_params.get("organization")
        if org_id:
            queryset = queryset.filter(organization_id=org_id)
        return queryset


class UserInternalViewSet(AuditMixin, viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset()
        org_id = self.request.query_params.get("organization")
        if org_id:
            return queryset.filter(memberships__organization_id=org_id).distinct()
        return queryset

    def perform_create(self, serializer):
        instance = serializer.save()
        if not instance.memberships.exists():
            raise ValidationError({"organization": "User must be linked to an organization."})
        self.log_action(
            self.request,
            f"{self.__class__.__name__} created",
            {"id": str(instance.id)},
            organization=instance.organization,
        )


class ScanJobInternalViewSet(AuditMixin, viewsets.ModelViewSet):
    queryset = ScanJob.objects.all()
    serializer_class = ScanJobAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset().order_by("-started_at", "-created_at")
        org_id = self.request.query_params.get("organization")
        if org_id:
            return queryset.filter(organization_id=org_id)
        return queryset

    def _requeue_failed_job(self, request, job: ScanJob):
        if job.status != ScanJob.STATUS_FAILED:
            raise ValidationError({"status": "Only failed scan jobs can be rescanned."})

        job.status = ScanJob.STATUS_QUEUED
        job.started_at = None
        job.completed_at = None
        job.failure_reason = ""
        job.save(update_fields=["status", "started_at", "completed_at", "failure_reason"])

        if job.service_request_id:
            ServiceRequest.objects.filter(id=job.service_request_id).update(status=ServiceRequest.STATUS_APPROVED)
            execute_service_request_job.apply_async(args=[str(job.id)], queue="scanner")
            self.log_action(
                request,
                "Service request scan rescanned",
                {"scan_job_id": str(job.id)},
                organization=job.organization,
            )
        else:
            execute_scan_job.delay(str(job.id))
            self.log_action(
                request,
                "Scan job rescanned",
                {"scan_job_id": str(job.id)},
                organization=job.organization,
            )

        serializer = self.get_serializer(job)
        return Response(serializer.data)

    @action(detail=True, methods=["post"])
    def retry(self, request, pk=None):
        # Backward-compatible alias for older UI clients.
        job = self.get_object()
        return self._requeue_failed_job(request, job)

    @action(detail=True, methods=["post"])
    def rescan(self, request, pk=None):
        job = self.get_object()
        return self._requeue_failed_job(request, job)


class ScanScheduleInternalViewSet(AuditMixin, viewsets.ModelViewSet):
    queryset = ScanSchedule.objects.all()
    serializer_class = ScanScheduleAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset().order_by("-created_at")
        org_id = self.request.query_params.get("organization")
        if org_id:
            return queryset.filter(organization_id=org_id)
        return queryset


class ScanAlertInternalViewSet(AuditMixin, viewsets.ModelViewSet):
    queryset = ScanAlert.objects.all()
    serializer_class = ScanAlertAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset().order_by("-created_at")
        org_id = self.request.query_params.get("organization")
        if org_id:
            return queryset.filter(organization_id=org_id)
        return queryset


class ScanRequestInternalViewSet(AuditMixin, viewsets.ModelViewSet):
    queryset = ScanRequest.objects.all().select_related("organization", "requested_by", "asset", "repository")
    serializer_class = ScanRequestAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset()
        org_id = self.request.query_params.get("organization")
        if org_id:
            return queryset.filter(organization_id=org_id)
        return queryset

    def _resolve_target(self, request_obj: ScanRequest):
        def _resolve_or_create_asset(identifier: str, defaults: dict):
            qs = Asset.objects.filter(organization=request_obj.organization, identifier=identifier).order_by("-updated_at", "-created_at")
            asset = qs.first()
            if asset:
                return asset
            return Asset.objects.create(organization=request_obj.organization, identifier=identifier, **defaults)

        if request_obj.scan_type == ScanRequest.TYPE_CODE:
            if request_obj.repository:
                return request_obj.asset, request_obj.repository
            repo_url = request_obj.target
            asset = _resolve_or_create_asset(
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
            updates = []
            if request_obj.asset_id != asset.id:
                request_obj.asset = asset
                updates.append("asset")
            if request_obj.repository_id != repository.id:
                request_obj.repository = repository
                updates.append("repository")
            if updates:
                request_obj.save(update_fields=updates)
            return asset, repository

        if request_obj.asset:
            return request_obj.asset, None

        asset_type_map = {
            ScanRequest.TYPE_WEB: Asset.TYPE_WEB_APP,
            ScanRequest.TYPE_API: Asset.TYPE_API,
            ScanRequest.TYPE_NETWORK: Asset.TYPE_NETWORK_SEGMENT,
            ScanRequest.TYPE_INFRA: Asset.TYPE_CLOUD_RESOURCE,
        }
        asset = _resolve_or_create_asset(
            request_obj.target,
            {
                "name": request_obj.target,
                "asset_type": asset_type_map.get(request_obj.scan_type, Asset.TYPE_WEB_APP),
                "risk_level": Asset.RISK_LOW,
            },
        )
        if request_obj.asset_id != asset.id:
            request_obj.asset = asset
            request_obj.save(update_fields=["asset"])
        return asset, None

    def perform_update(self, serializer):
        previous = self.get_object()
        instance = serializer.save()
        status_changed = previous.status != instance.status

        if status_changed and instance.status in {
            ScanRequest.STATUS_QUEUED,
            ScanRequest.STATUS_IN_PROGRESS,
            ScanRequest.STATUS_COMPLETED,
        }:
            asset, repository = self._resolve_target(instance)
            if not instance.scan_jobs.exists():
                job = ScanJob.objects.create(
                    organization=instance.organization,
                    scan_type=instance.scan_type,
                    asset=asset,
                    repository=repository,
                    created_by=self.request.user,
                    scan_request=instance,
                )
                execute_scan_job.delay(str(job.id))

        self.log_action(
            self.request,
            f"{self.__class__.__name__} updated",
            {"id": str(instance.id), "status": instance.status},
            organization=instance.organization,
        )


class IncidentInternalViewSet(AuditMixin, viewsets.ModelViewSet):
    queryset = Incident.objects.all()
    serializer_class = IncidentAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset()
        org_id = self.request.query_params.get("organization")
        if org_id:
            return queryset.filter(organization_id=org_id)
        return queryset


class ActivityLogInternalViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ActivityLog.objects.all()
    serializer_class = ActivityLogAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset()
        org_id = self.request.query_params.get("organization")
        if org_id:
            return queryset.filter(organization_id=org_id)
        return queryset


class ReportInternalViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Report.objects.all()
    serializer_class = ReportAdminSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset()
        org_id = self.request.query_params.get("organization")
        if org_id:
            return queryset.filter(organization_id=org_id)
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

    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        report = self.get_object()
        if not report.client_visible:
            report.client_visible = True
            report.sent_at = timezone.now()
            report.save(update_fields=["client_visible", "sent_at"])
            ActivityLog.objects.create(
                organization=report.organization,
                user=request.user,
                action="Report published to client",
                timestamp=timezone.now(),
                metadata={"report_id": str(report.id)},
            )
        serializer = self.get_serializer(report)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], url_path="posture-trend")
    def posture_trend(self, request):
        org_id = request.query_params.get("organization")
        if not org_id:
            raise ValidationError({"organization": "organization query parameter is required"})
        scope = request.query_params.get("scope")
        limit = int(request.query_params.get("limit") or 10)
        if limit < 1:
            limit = 1
        if limit > 30:
            limit = 30

        qs = Report.objects.filter(organization_id=org_id).order_by("-generated_at", "-created_at")
        if scope:
            qs = qs.filter(scope=scope)

        points = []
        for r in qs[:limit]:
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
                    "report_id": str(r.id),
                    "generated_at": r.generated_at,
                    "scope": r.scope,
                    "score": int(posture.get("score") or 0),
                    "grade": str(posture.get("grade") or ""),
                    "critical": int(sev.get("critical") or 0),
                    "high": int(sev.get("high") or 0),
                    "moderate": int(sev.get("moderate") or 0),
                    "low": int(sev.get("low") or 0),
                }
            )

        return Response({"count": len(points), "results": list(reversed(points))})


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _cidr_is_too_broad(value: str) -> tuple[bool, str]:
    """
    Mirrors the scanner guardrails (prefix + absolute size).
    Returns (too_broad, reason).
    """
    if not value:
        return False, ""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except Exception:
        return False, ""

    max_addrs = _env_int("NETWORK_SCAN_MAX_CIDR_ADDRESSES", 65536)
    min_v4 = _env_int("NETWORK_SCAN_MIN_IPV4_PREFIX", 16)
    min_v6 = _env_int("NETWORK_SCAN_MIN_IPV6_PREFIX", 48)
    if getattr(network, "num_addresses", 0) > max_addrs:
        return True, f"exceeds_max_addresses({max_addrs})"
    if isinstance(network, ipaddress.IPv4Network) and network.prefixlen < min_v4:
        return True, f"prefix_too_broad(/<{min_v4})"
    if isinstance(network, ipaddress.IPv6Network) and network.prefixlen < min_v6:
        return True, f"prefix_too_broad(/<{min_v6})"
    return False, ""


class HygieneInternalViewSet(AuditMixin, viewsets.ViewSet):
    """
    Internal admin "coverage & hygiene" endpoints.

    - /internal/hygiene/overview/
    - /internal/hygiene/schedule-asset/ (POST)
    """

    permission_classes = [IsAuthenticated, IsInternalAdmin]

    @action(detail=False, methods=["get"], url_path="overview")
    def overview(self, request):
        stale_days = _env_int("HYGIENE_STALE_ASSET_DAYS", 14)
        try:
            stale_days = int(request.query_params.get("stale_days") or stale_days)
        except Exception:
            stale_days = 14
        stale_days = max(1, min(365, stale_days))

        now = timezone.now()
        stale_cutoff = now - timedelta(days=stale_days)

        org_rows = []
        for org in Organization.objects.all().order_by("name"):
            assets_qs = Asset.objects.filter(organization=org)
            repos_qs = CodeRepository.objects.filter(organization=org)
            cloud_count = getattr(org, "cloud_accounts", None).count() if hasattr(org, "cloud_accounts") else 0

            present = {
                "domains": assets_qs.filter(asset_type__in=[Asset.TYPE_DOMAIN, Asset.TYPE_WEB_APP]).count(),
                "ip_ranges": assets_qs.filter(asset_type__in=[Asset.TYPE_IP_RANGE, Asset.TYPE_NETWORK_SEGMENT]).count(),
                "apis": assets_qs.filter(asset_type=Asset.TYPE_API).count(),
                "apps": assets_qs.exclude(asset_type__in=[Asset.TYPE_IP_RANGE, Asset.TYPE_NETWORK_SEGMENT, Asset.TYPE_CLOUD_RESOURCE, Asset.TYPE_CODE_REPOSITORY]).count(),
                "repos": repos_qs.count(),
                "cloud_accounts": int(cloud_count),
            }

            policy = OrganizationScanPolicy.objects.filter(organization=org).first()
            expectations = (policy.inventory_expectations or {}) if policy else {}
            defaults = {"domains": 1, "ip_ranges": 1, "apis": 1, "cloud_accounts": 0, "repos": 1, "apps": 1}
            expected = {**defaults, **{k: int(v) for k, v in expectations.items() if str(k) in defaults}}
            configured = bool(expectations)

            categories = []
            ratios = []
            for key, label in [
                ("domains", "Domains / Web Apps"),
                ("ip_ranges", "IP Ranges / Segments"),
                ("apis", "APIs"),
                ("cloud_accounts", "Cloud Accounts"),
                ("repos", "Repositories"),
                ("apps", "Apps / Services"),
            ]:
                e = int(expected.get(key, 0) or 0)
                p = int(present.get(key, 0) or 0)
                if e <= 0:
                    ratio = None
                else:
                    ratio = min(1.0, p / float(e))
                    ratios.append(ratio)
                status = "ignored" if e <= 0 else ("ok" if p >= e else ("warn" if p > 0 else "miss"))
                categories.append({"key": key, "label": label, "present": p, "expected": e, "status": status})

            score = int(round((sum(ratios) / len(ratios)) * 100)) if ratios else 100
            org_rows.append(
                {
                    "organization_id": str(org.id),
                    "organization_name": org.name,
                    "score": score,
                    "configured": configured,
                    "categories": categories,
                }
            )

        stale_assets = (
            Asset.objects.filter(models.Q(last_scanned_at__isnull=True) | models.Q(last_scanned_at__lt=stale_cutoff))
            .select_related("organization")
            .order_by("last_scanned_at", "created_at")[:50]
        )
        stale_rows = []
        for a in stale_assets:
            active_schedule = ScanSchedule.objects.filter(organization=a.organization, asset=a, is_active=True).exists()
            last = a.last_scanned_at
            age_days = None
            if last:
                age_days = max(0, int((now - last).total_seconds() // 86400))
            stale_rows.append(
                {
                    "asset_id": str(a.id),
                    "organization_id": str(a.organization_id),
                    "organization_name": a.organization.name,
                    "name": a.name,
                    "asset_type": a.asset_type,
                    "identifier": a.identifier,
                    "risk_level": a.risk_level,
                    "last_scanned_at": last,
                    "age_days": age_days,
                    "has_active_schedule": bool(active_schedule),
                }
            )

        issues: list[dict] = []
        for org in Organization.objects.all().order_by("name"):
            policy = OrganizationScanPolicy.objects.filter(organization=org).first()
            if not policy:
                issues.append(
                    {
                        "severity": "moderate",
                        "organization_id": str(org.id),
                        "organization_name": org.name,
                        "code": "policy_missing",
                        "title": "Scan policy not configured",
                        "detail": "No OrganizationScanPolicy record exists. Defaults will apply.",
                    }
                )
                continue

            allowlist = policy.ssrf_allowlist or {}
            urls = allowlist.get("urls") if isinstance(allowlist, dict) else None
            domains = allowlist.get("domains") if isinstance(allowlist, dict) else None
            cidrs = allowlist.get("cidrs") if isinstance(allowlist, dict) else None

            if policy.ssrf_high_risk_enabled:
                missing_allowlist = not isinstance(allowlist, dict) or not any(
                    [
                        isinstance(urls, list) and len([u for u in urls if str(u).strip()]) > 0,
                        isinstance(domains, list) and len([d for d in domains if str(d).strip()]) > 0,
                        isinstance(cidrs, list) and len([c for c in cidrs if str(c).strip()]) > 0,
                    ]
                )
                if missing_allowlist:
                    issues.append(
                        {
                            "severity": "critical",
                            "organization_id": str(org.id),
                            "organization_name": org.name,
                            "code": "ssrf_allowlist_missing",
                            "title": "High-risk SSRF enabled without allowlist",
                            "detail": "Enablement requires explicit allowlisted domains/CIDRs and URLs.",
                        }
                    )

                authorized_assets = Asset.objects.filter(organization=org, high_risk_ssrf_authorized=True)
                if not authorized_assets.exists():
                    issues.append(
                        {
                            "severity": "warning",
                            "organization_id": str(org.id),
                            "organization_name": org.name,
                            "code": "ssrf_no_assets_authorized",
                            "title": "High-risk SSRF enabled but no assets authorized",
                            "detail": "At least one asset must be marked high_risk_ssrf_authorized to run high-risk validation.",
                        }
                    )
                if authorized_assets.filter(high_risk_ssrf_authorization_reference="").exists():
                    issues.append(
                        {
                            "severity": "moderate",
                            "organization_id": str(org.id),
                            "organization_name": org.name,
                            "code": "ssrf_asset_missing_reference",
                            "title": "Authorized asset missing authorization reference",
                            "detail": "Fill in high_risk_ssrf_authorization_reference for auditability.",
                        }
                    )

            if policy.ssrf_allow_metadata and not policy.ssrf_high_risk_enabled:
                issues.append(
                    {
                        "severity": "warning",
                        "organization_id": str(org.id),
                        "organization_name": org.name,
                        "code": "ssrf_metadata_without_highrisk",
                        "title": "Metadata SSRF toggle enabled while high-risk mode is disabled",
                        "detail": "ssrf_allow_metadata has no effect unless high-risk SSRF is enabled.",
                    }
                )

            for sched in ScanSchedule.objects.filter(organization=org, is_active=True).exclude(ip_cidr=""):
                too_broad, reason = _cidr_is_too_broad((sched.ip_cidr or "").strip())
                if too_broad:
                    issues.append(
                        {
                            "severity": "warning",
                            "organization_id": str(org.id),
                            "organization_name": org.name,
                            "code": "cidr_too_broad",
                            "title": "Scheduled CIDR likely to be blocked by safe scan limits",
                            "detail": f"Schedule {sched.id} target {sched.ip_cidr} ({reason}).",
                        }
                    )

        return Response(
            {
                "generated_at": now,
                "inventory": {"organizations": org_rows},
                "stale_assets": {"threshold_days": stale_days, "count": len(stale_rows), "results": stale_rows},
                "policy_issues": {"count": len(issues), "results": issues[:100]},
            }
        )

    @action(detail=False, methods=["post"], url_path="schedule-asset")
    def schedule_asset(self, request):
        payload = request.data or {}
        asset_id = str(payload.get("asset_id") or "").strip()
        if not asset_id:
            raise ValidationError({"asset_id": "asset_id is required."})
        asset = Asset.objects.filter(id=asset_id).select_related("organization").first()
        if not asset:
            raise ValidationError({"asset_id": "Asset not found."})

        default_service_type = ServiceRequest.SERVICE_NETWORK
        scope = ScanSchedule.SCOPE_ASSET
        repository_url = ""
        ip_cidr = ""
        domain_url = ""

        if asset.asset_type in {Asset.TYPE_DOMAIN, Asset.TYPE_WEB_APP}:
            default_service_type = ServiceRequest.SERVICE_WEB
            scope = ScanSchedule.SCOPE_DOMAIN
            domain_url = asset.identifier
        elif asset.asset_type == Asset.TYPE_API:
            default_service_type = ServiceRequest.SERVICE_API
            scope = ScanSchedule.SCOPE_DOMAIN
            domain_url = asset.identifier
        elif asset.asset_type in {Asset.TYPE_IP_RANGE, Asset.TYPE_NETWORK_SEGMENT}:
            default_service_type = ServiceRequest.SERVICE_NETWORK
            scope = ScanSchedule.SCOPE_IP_CIDR
            ip_cidr = asset.identifier
        elif asset.asset_type == Asset.TYPE_CODE_REPOSITORY:
            default_service_type = ServiceRequest.SERVICE_CODE_SECRETS
            scope = ScanSchedule.SCOPE_REPOSITORY
            repo = CodeRepository.objects.filter(asset=asset, organization=asset.organization).first()
            repository_url = (repo.repo_url if repo else "") or asset.identifier
        elif asset.asset_type == Asset.TYPE_CLOUD_RESOURCE:
            default_service_type = ServiceRequest.SERVICE_CLOUD
            scope = ScanSchedule.SCOPE_ASSET

        service_type = str(payload.get("service_type") or default_service_type).strip()
        try:
            interval_minutes = int(payload.get("interval_minutes") or 1440)
        except Exception:
            interval_minutes = 1440
        interval_minutes = max(15, min(60 * 24 * 30, interval_minutes))

        existing = (
            ScanSchedule.objects.filter(
                organization=asset.organization,
                asset=asset,
                service_type=service_type,
                is_active=True,
            )
            .order_by("-created_at")
            .first()
        )
        if existing:
            return Response(ScanScheduleAdminSerializer(existing).data, status=200)

        schedule = ScanSchedule.objects.create(
            organization=asset.organization,
            created_by=request.user,
            service_type=service_type,
            requested_role=UserOrganization.ROLE_SECURITY_LEAD,
            scope=scope,
            repository_url=repository_url,
            asset=asset,
            ip_cidr=ip_cidr,
            domain_url=domain_url,
            interval_minutes=interval_minutes,
            next_run_at=timezone.now(),
            is_active=True,
        )
        self.log_action(
            request,
            "Hygiene schedule created",
            {"asset_id": str(asset.id), "schedule_id": str(schedule.id), "service_type": service_type},
            organization=asset.organization,
        )
        return Response(ScanScheduleAdminSerializer(schedule).data, status=201)


def _p_quantile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    values_sorted = sorted(values)
    if p <= 0:
        return float(values_sorted[0])
    if p >= 1:
        return float(values_sorted[-1])
    # Nearest-rank with linear interpolation.
    k = (len(values_sorted) - 1) * p
    f = int(k)
    c = min(f + 1, len(values_sorted) - 1)
    if f == c:
        return float(values_sorted[f])
    return float(values_sorted[f] + (values_sorted[c] - values_sorted[f]) * (k - f))


def _classify_failure(reason: str) -> str:
    r = (reason or "").strip().lower()
    if not r:
        return "unknown"
    if "cidr range exceeds safe scan limits" in r or "cidr range too broad" in r or "broad cidr ranges are not permitted" in r:
        return "blocked_cidr"
    if "could not resolve" in r or "name or service not known" in r or "dns" in r:
        return "dns"
    if "timed out" in r or "timeout" in r:
        return "timeout"
    if "proxy" in r or "proxies" in r:
        return "proxy"
    if "connection refused" in r:
        return "conn_refused"
    if "ssl" in r or "certificate" in r:
        return "tls"
    if "permission denied" in r or "forbidden" in r:
        return "permission"
    if "unauthorized" in r or "401" in r:
        return "unauthorized"
    return "other"


class OpsInternalViewSet(AuditMixin, viewsets.ViewSet):
    """
    Internal admin operations control plane.

    - /internal/ops/overview/
    """

    permission_classes = [IsAuthenticated, IsInternalAdmin]

    @action(detail=False, methods=["get"], url_path="overview")
    def overview(self, request):
        now = timezone.now()
        window_hours = _env_int("OPS_METRICS_WINDOW_HOURS", 24)
        window_hours = max(1, min(168, int(window_hours)))
        since = now - timedelta(hours=window_hours)

        queued = ScanJob.objects.filter(status=ScanJob.STATUS_QUEUED).count()
        running = ScanJob.objects.filter(status=ScanJob.STATUS_RUNNING).count()
        failed_recent = ScanJob.objects.filter(status=ScanJob.STATUS_FAILED, completed_at__gte=since).count()
        completed_recent = ScanJob.objects.filter(status=ScanJob.STATUS_COMPLETED, completed_at__gte=since).count()

        oldest_queued = ScanJob.objects.filter(status=ScanJob.STATUS_QUEUED).order_by("created_at").first()
        oldest_queued_minutes = None
        if oldest_queued:
            oldest_queued_minutes = int((now - oldest_queued.created_at).total_seconds() // 60)

        # Worker health (best-effort Celery ping).
        workers = {"ok": False, "online": 0, "details": {}, "error": ""}
        try:
            from aegis_backend.celery import app as celery_app

            insp = celery_app.control.inspect(timeout=1.0)
            pong = insp.ping() or {}
            workers["details"] = {k: {"ok": True} for k in pong.keys()}
            workers["online"] = len(pong.keys())
            workers["ok"] = workers["online"] > 0
        except Exception as exc:
            workers["ok"] = False
            workers["online"] = 0
            workers["error"] = str(exc)

        # p95 duration (ms) over recent completed jobs.
        durations_ms: list[float] = []
        durations_by_type: dict[str, list[float]] = {}
        for job in ScanJob.objects.filter(status=ScanJob.STATUS_COMPLETED, completed_at__gte=since).exclude(started_at__isnull=True).exclude(completed_at__isnull=True):
            dur = (job.completed_at - job.started_at).total_seconds() * 1000.0
            durations_ms.append(dur)
            durations_by_type.setdefault(job.scan_type, []).append(dur)

        p95_overall = _p_quantile(durations_ms, 0.95)
        p95_by_type = {k: _p_quantile(v, 0.95) for k, v in durations_by_type.items()}

        # Failure analytics (top reasons + examples).
        failure_qs = ScanJob.objects.filter(status=ScanJob.STATUS_FAILED, completed_at__gte=since).order_by("-completed_at")
        buckets: dict[str, dict] = {}
        recent_failed = []
        for job in failure_qs[:50]:
            code = _classify_failure(job.failure_reason or "")
            b = buckets.setdefault(code, {"code": code, "count": 0, "examples": []})
            b["count"] += 1
            if len(b["examples"]) < 3 and (job.failure_reason or "").strip():
                b["examples"].append((job.failure_reason or "").strip()[:220])
            recent_failed.append(
                {
                    "scan_job_id": str(job.id),
                    "organization_id": str(job.organization_id),
                    "scan_type": job.scan_type,
                    "failure_reason": (job.failure_reason or "").strip()[:260],
                    "created_at": job.created_at,
                    "completed_at": job.completed_at,
                }
            )

        top_reasons = sorted(buckets.values(), key=lambda x: int(x["count"]), reverse=True)[:8]

        # Retry counts (derived from ActivityLog entries).
        retry_actions = {"Scan job retried", "Service request scan retried"}
        retry_counts: dict[str, int] = {}
        for log in ActivityLog.objects.filter(timestamp__gte=since, action__in=retry_actions).order_by("-timestamp")[:500]:
            md = log.metadata or {}
            sj = str(md.get("scan_job_id") or "").strip()
            if sj:
                retry_counts[sj] = retry_counts.get(sj, 0) + 1

        queue_jobs = []
        for job in ScanJob.objects.filter(status__in=[ScanJob.STATUS_QUEUED, ScanJob.STATUS_RUNNING, ScanJob.STATUS_FAILED]).order_by("-created_at")[:40]:
            queue_jobs.append(
                {
                    "scan_job_id": str(job.id),
                    "organization_id": str(job.organization_id),
                    "scan_type": job.scan_type,
                    "status": job.status,
                    "created_at": job.created_at,
                    "started_at": job.started_at,
                    "completed_at": job.completed_at,
                    "retries": int(retry_counts.get(str(job.id), 0)),
                    "failure_reason": (job.failure_reason or "").strip()[:220],
                }
            )

        # Safety budget telemetry from Scan.metadata (best-effort; depends on scan type).
        scan_rows = []
        scans = Scan.objects.filter(completed_at__gte=since).order_by("-completed_at")[:500]
        by_type: dict[str, list[dict]] = {}
        for s in scans:
            md = s.metadata or {}
            by_type.setdefault(s.scan_type, []).append(md if isinstance(md, dict) else {})

        for scan_type, rows in by_type.items():
            ports_checked_vals = [int(r.get("ports_checked") or 0) for r in rows if isinstance(r, dict)]
            validation_used_vals = [int(r.get("validation_requests_used") or 0) for r in rows if isinstance(r, dict)]
            scan_rows.append(
                {
                    "scan_type": scan_type,
                    "sample_size": len(rows),
                    "avg_ports_checked": int(round(sum(ports_checked_vals) / len(ports_checked_vals))) if ports_checked_vals else 0,
                    "avg_validation_requests_used": int(round(sum(validation_used_vals) / len(validation_used_vals))) if validation_used_vals else 0,
                    "p95_validation_requests_used": int(round(_p_quantile([float(v) for v in validation_used_vals], 0.95) or 0)) if validation_used_vals else 0,
                }
            )

        return Response(
            {
                "generated_at": now,
                "window_hours": window_hours,
                "workers": workers,
                "scan_queue": {
                    "queued": queued,
                    "running": running,
                    "failed_recent": failed_recent,
                    "completed_recent": completed_recent,
                    "oldest_queued_minutes": oldest_queued_minutes,
                    "jobs": queue_jobs,
                },
                "durations": {
                    "sample_size": len(durations_ms),
                    "p95_ms_overall": int(round(p95_overall)) if p95_overall is not None else None,
                    "p95_ms_by_type": {k: (int(round(v)) if v is not None else None) for k, v in p95_by_type.items()},
                },
                "failures": {"top_reasons": top_reasons, "recent_failed": recent_failed},
                "budget": {"by_scan_type": sorted(scan_rows, key=lambda r: r["scan_type"])},
            }
        )


def _human_bytes(value: int | None) -> str:
    try:
        v = int(value or 0)
    except Exception:
        v = 0
    if v <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    size = float(v)
    idx = 0
    while size >= 1024.0 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.1f} {units[idx]}"


class GovernanceInternalViewSet(AuditMixin, viewsets.ViewSet):
    """
    Internal admin governance & audit endpoints.

    - /internal/governance/ssrf-audit/
    - /internal/governance/policy-changes/
    - /internal/governance/evidence-retention/
    """

    permission_classes = [IsAuthenticated, IsInternalAdmin]

    @action(detail=False, methods=["get"], url_path="ssrf-audit")
    def ssrf_audit(self, request):
        limit = _env_int("GOVERNANCE_AUDIT_LIMIT", 100)
        try:
            limit = int(request.query_params.get("limit") or limit)
        except Exception:
            limit = 100
        limit = max(1, min(500, limit))
        org_id = (request.query_params.get("organization") or "").strip()

        qs = ActivityLog.objects.filter(action="High-risk SSRF validation attempted").order_by("-timestamp")
        if org_id:
            qs = qs.filter(organization_id=org_id)

        results: list[dict] = []
        for log in qs.select_related("organization", "user")[:limit]:
            md = log.metadata or {}
            sr_id = str(md.get("service_request_id") or "").strip()
            scan_job_id = str(md.get("scan_job_id") or "").strip()
            auth_ref = str(md.get("authorization_reference") or "").strip()
            attempts = md.get("attempts") if isinstance(md, dict) else []
            truncated = bool(md.get("truncated")) if isinstance(md, dict) else False

            sr = None
            if sr_id:
                sr = (
                    ServiceRequest.objects.filter(id=sr_id)
                    .select_related("requested_by", "approved_by", "organization")
                    .first()
                )

            requester_email = getattr(getattr(sr, "requested_by", None), "email", None)
            approver_email = getattr(getattr(sr, "approved_by", None), "email", None) or getattr(getattr(log, "user", None), "email", None)
            results.append(
                {
                    "id": str(log.id),
                    "timestamp": log.timestamp,
                    "organization_id": str(log.organization_id),
                    "organization_name": getattr(log.organization, "name", ""),
                    "service_request_id": sr_id or (str(sr.id) if sr else ""),
                    "scan_job_id": scan_job_id,
                    "requester_email": requester_email or "",
                    "approver_email": approver_email or "",
                    "authorization_reference": auth_ref,
                    "attempts_count": len(attempts) if isinstance(attempts, list) else 0,
                    "attempts": attempts if isinstance(attempts, list) else [],
                    "truncated": truncated,
                }
            )

        return Response({"generated_at": timezone.now(), "count": len(results), "results": results})

    @action(detail=False, methods=["get"], url_path="policy-changes")
    def policy_changes(self, request):
        limit = _env_int("GOVERNANCE_POLICY_CHANGE_LIMIT", 100)
        try:
            limit = int(request.query_params.get("limit") or limit)
        except Exception:
            limit = 100
        limit = max(1, min(500, limit))
        org_id = (request.query_params.get("organization") or "").strip()

        qs = ActivityLog.objects.filter(action="Organization scan policy updated").order_by("-timestamp")
        if org_id:
            qs = qs.filter(organization_id=org_id)

        results: list[dict] = []
        for log in qs.select_related("organization", "user")[:limit]:
            md = log.metadata or {}
            diff = md.get("diff") if isinstance(md, dict) else {}
            results.append(
                {
                    "id": str(log.id),
                    "timestamp": log.timestamp,
                    "organization_id": str(log.organization_id),
                    "organization_name": getattr(log.organization, "name", ""),
                    "changed_by_email": getattr(getattr(log, "user", None), "email", "") or "",
                    "diff": diff if isinstance(diff, dict) else {},
                }
            )
        return Response({"generated_at": timezone.now(), "count": len(results), "results": results})

    @action(detail=False, methods=["get"], url_path="evidence-retention")
    def evidence_retention(self, request):
        retention_days = _env_int("AEGIS_EVIDENCE_RETENTION_DAYS", 90)
        expiring_soon_days = _env_int("AEGIS_EVIDENCE_EXPIRING_SOON_DAYS", 7)
        try:
            retention_days = int(request.query_params.get("retention_days") or retention_days)
        except Exception:
            retention_days = 90
        try:
            expiring_soon_days = int(request.query_params.get("expiring_soon_days") or expiring_soon_days)
        except Exception:
            expiring_soon_days = 7
        retention_days = max(1, min(3650, retention_days))
        expiring_soon_days = max(1, min(90, expiring_soon_days))

        limit = _env_int("GOVERNANCE_EVIDENCE_LIMIT", 30)
        try:
            limit = int(request.query_params.get("limit") or limit)
        except Exception:
            limit = 30
        limit = max(1, min(200, limit))
        refresh = str(request.query_params.get("refresh") or "").strip() in {"1", "true", "yes"}
        cache = str(request.query_params.get("cache") or "1").strip() in {"1", "true", "yes"}

        now = timezone.now()
        results: list[dict] = []
        counts = {"ok": 0, "expiring": 0, "expired": 0, "missing": 0}

        qs = Report.objects.all().select_related("organization", "service_request", "scan_job").order_by("-generated_at", "-created_at")
        for report in qs[:limit]:
            expires_at = report.generated_at + timedelta(days=retention_days)
            days_left = int((expires_at - now).total_seconds() // 86400)
            status = "ok"
            if days_left < 0:
                status = "expired"
            elif days_left <= expiring_soon_days:
                status = "expiring"

            md = report.metadata or {}
            bundle_md = md.get("appendix_bundle") if isinstance(md, dict) else None
            cached_size = None
            cached_ok = None
            cached_at = None
            if isinstance(bundle_md, dict):
                cached_size = bundle_md.get("size_bytes")
                cached_ok = bundle_md.get("present")
                cached_at = bundle_md.get("calculated_at")

            appendix_present = bool(cached_ok) if cached_ok is not None else True
            size_bytes = int(cached_size) if isinstance(cached_size, int) else None
            error = ""

            if refresh or size_bytes is None or cached_ok is None:
                try:
                    bundle = build_report_appendix_bundle(report)
                    size_bytes = len(bundle)
                    appendix_present = True
                    if cache:
                        md = md if isinstance(md, dict) else {}
                        md["appendix_bundle"] = {
                            "present": True,
                            "size_bytes": int(size_bytes),
                            "calculated_at": now.isoformat(),
                            "expires_at": expires_at.isoformat(),
                        }
                        report.metadata = md
                        report.save(update_fields=["metadata", "updated_at"])
                except Exception as exc:
                    appendix_present = False
                    error = str(exc)[:240]
                    if cache:
                        md = md if isinstance(md, dict) else {}
                        md["appendix_bundle"] = {
                            "present": False,
                            "size_bytes": 0,
                            "calculated_at": now.isoformat(),
                            "expires_at": expires_at.isoformat(),
                            "error": error,
                        }
                        report.metadata = md
                        report.save(update_fields=["metadata", "updated_at"])

            if not appendix_present:
                counts["missing"] += 1
            elif status == "expired":
                counts["expired"] += 1
            elif status == "expiring":
                counts["expiring"] += 1
            else:
                counts["ok"] += 1

            results.append(
                {
                    "report_id": str(report.id),
                    "organization_id": str(report.organization_id),
                    "organization_name": getattr(report.organization, "name", ""),
                    "service_request_id": str(report.service_request_id) if report.service_request_id else "",
                    "scan_job_id": str(report.scan_job_id) if report.scan_job_id else "",
                    "generated_at": report.generated_at,
                    "expires_at": expires_at,
                    "status": status,
                    "days_left": days_left,
                    "appendix_present": bool(appendix_present),
                    "appendix_size_bytes": int(size_bytes or 0),
                    "appendix_size_human": _human_bytes(size_bytes),
                    "appendix_calculated_at": cached_at or now.isoformat(),
                    "error": error,
                }
            )

        return Response(
            {
                "generated_at": now,
                "retention_days": retention_days,
                "expiring_soon_days": expiring_soon_days,
                "counts": counts,
                "results": results,
            }
        )
