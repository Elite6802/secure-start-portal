from datetime import datetime, timedelta

from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from django.utils import timezone
from core.models import OrganizationQuerySetMixin
from core.permissions import get_user_role, RolePermissionMixin
from activity_log.models import ActivityLog
from accounts.models import UserOrganization, OrganizationScanPolicy
from assets.models import Asset
from scans.models import ScanAlert, ScanJob
from .models import ServiceRequest
from .serializers import ServiceRequestSerializer
from internal.permissions import IsInternalAdmin
from .tasks import execute_service_request_job


def _log_activity(request_obj: ServiceRequest, action: str, user=None, metadata: dict | None = None):
    ActivityLog.objects.create(
        organization=request_obj.organization,
        user=user,
        action=action,
        timestamp=timezone.now(),
        metadata=metadata or {},
    )


class ServiceRequestViewSet(
    RolePermissionMixin,
    OrganizationQuerySetMixin,
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = ServiceRequestSerializer
    permission_classes = [IsAuthenticated]
    organization_field = "organization"
    role_action_map = {
        "list": [
            UserOrganization.ROLE_SECURITY_LEAD,
            UserOrganization.ROLE_DEVELOPER,
            UserOrganization.ROLE_EXECUTIVE,
        ],
        "create": [
            UserOrganization.ROLE_SECURITY_LEAD,
            UserOrganization.ROLE_DEVELOPER,
        ],
    }

    def get_queryset(self):
        base = ServiceRequest.objects.all().prefetch_related("reports").order_by("-created_at")
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return base
        org = getattr(user, "organization", None)
        if not org:
            return base.none()
        role = get_user_role(user)
        if role == UserOrganization.ROLE_SECURITY_LEAD:
            return base.filter(organization=org)
        return base.filter(organization=org, requested_by=user)

    def _validate_role_access(self, role: str, service_type: str):
        if role == UserOrganization.ROLE_EXECUTIVE:
            raise PermissionDenied("Executives cannot submit service requests.")

        compliance_types = {
            ServiceRequest.SERVICE_CODE_COMPLIANCE,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_PYTHON,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_HTML,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_CSS,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_JAVASCRIPT,
            ServiceRequest.SERVICE_CODE_COMPLIANCE_REACT,
        }
        security_lead_services = {
            ServiceRequest.SERVICE_CODE_SECRETS,
            ServiceRequest.SERVICE_DEPENDENCY,
            *compliance_types,
            ServiceRequest.SERVICE_NETWORK,
            ServiceRequest.SERVICE_WEB,
            ServiceRequest.SERVICE_API,
            ServiceRequest.SERVICE_INFRA,
            ServiceRequest.SERVICE_CLOUD,
        }
        allowed = {
            UserOrganization.ROLE_DEVELOPER: {
                ServiceRequest.SERVICE_CODE_SECRETS,
                ServiceRequest.SERVICE_DEPENDENCY,
                *compliance_types,
            },
            UserOrganization.ROLE_SECURITY_LEAD: security_lead_services,
            # SOC admins have the same request privileges as security leads.
            UserOrganization.ROLE_SOC_ADMIN: security_lead_services,
        }
        if role not in allowed or service_type not in allowed[role]:
            raise PermissionDenied("Your role does not allow this service request type.")

    def perform_create(self, serializer):
        user = self.request.user
        org = getattr(user, "organization", None)
        if not org:
            raise ValidationError({"organization": "No organization assigned to this user."})

        role = get_user_role(user)
        if not role:
            raise PermissionDenied("No role assigned to this user.")

        service_type = serializer.validated_data.get("service_type")
        if not (user.is_staff or user.is_superuser):
            self._validate_role_access(role, service_type)

        # High-risk SSRF validation guardrails (authorized targets only).
        high_risk_ssrf = bool(serializer.validated_data.get("high_risk_ssrf"))
        ownership_confirmed = bool(serializer.validated_data.get("ownership_confirmed"))
        authorization_reference = (serializer.validated_data.get("authorization_reference") or "").strip()
        if high_risk_ssrf:
            if service_type not in {ServiceRequest.SERVICE_WEB, ServiceRequest.SERVICE_API}:
                raise ValidationError({"high_risk_ssrf": "High-risk SSRF validation is only available for Web/API scans."})
            if role not in {UserOrganization.ROLE_SECURITY_LEAD, UserOrganization.ROLE_SOC_ADMIN} and not (user.is_staff or user.is_superuser):
                raise PermissionDenied("Only Security Leads or SOC Admins can enable high-risk SSRF validation.")
            if not ownership_confirmed:
                raise ValidationError({"ownership_confirmed": "You must confirm you own/are authorized to test this target to enable high-risk SSRF validation."})
            if not authorization_reference:
                raise ValidationError({"authorization_reference": "Provide an authorization reference (e.g., internal ticket/change request ID) to enable high-risk SSRF validation."})
            policy = OrganizationScanPolicy.objects.filter(organization=org).first()
            if not (policy and policy.ssrf_high_risk_enabled):
                raise ValidationError({"high_risk_ssrf": "High-risk SSRF validation is not enabled for this organization. Ask a platform admin to configure scan policy allowlists."})

            # Per-asset authorization guardrail: require the target to be a registered asset
            # marked as authorized for high-risk SSRF mode.
            asset_obj = serializer.validated_data.get("asset")
            domain_url_for_lookup = (serializer.validated_data.get("domain_url") or "").strip()
            if not asset_obj and domain_url_for_lookup:
                asset_obj = Asset.objects.filter(organization=org, identifier=domain_url_for_lookup).first()

            if not asset_obj:
                raise ValidationError({"asset": "To enable high-risk SSRF validation, select a registered asset authorized for high-risk SSRF (or register the domain URL as an asset first)."})
            if not bool(getattr(asset_obj, "high_risk_ssrf_authorized", False)):
                raise ValidationError({"asset": "This asset is not authorized for high-risk SSRF validation. Ask a platform admin to authorize it in the asset registry."})

        repository_url = (serializer.validated_data.get("repository_url") or "").strip()
        ip_cidr = (serializer.validated_data.get("ip_cidr") or "").strip()
        domain_url = (serializer.validated_data.get("domain_url") or "").strip()
        asset = serializer.validated_data.get("asset")
        cloud_account = serializer.validated_data.get("cloud_account")

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
        if service_type in code_services:
            if not repository_url:
                raise ValidationError({"repository_url": "Repository URL is required for code scan requests."})
        if service_type in {ServiceRequest.SERVICE_NETWORK, ServiceRequest.SERVICE_INFRA}:
            if not (asset or ip_cidr or domain_url):
                raise ValidationError({"scope": "Provide an asset, domain/URL, or IP/CIDR for network requests."})
        if service_type in {ServiceRequest.SERVICE_WEB, ServiceRequest.SERVICE_API}:
            if not (asset or domain_url):
                raise ValidationError({"scope": "Provide a domain/URL or asset for web/API requests."})
        if service_type == ServiceRequest.SERVICE_CLOUD:
            if not cloud_account:
                raise ValidationError({"cloud_account": "Cloud account is required for cloud posture scans."})

        scope = serializer.validated_data.get("scope")
        if not scope:
            if repository_url:
                scope = ServiceRequest.SCOPE_REPOSITORY
            elif ip_cidr:
                scope = ServiceRequest.SCOPE_IP_CIDR
            elif domain_url:
                scope = ServiceRequest.SCOPE_DOMAIN
            elif asset:
                scope = ServiceRequest.SCOPE_ASSET
            elif cloud_account:
                scope = ServiceRequest.SCOPE_CLOUD

        instance = serializer.save(
            organization=org,
            requested_by=user,
            requested_role=role,
            scope=scope or "",
        )
        _log_activity(instance, "Service request created", user=user, metadata={"service_type": instance.service_type})


class ServiceRequestInternalViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ServiceRequest.objects.all().select_related("organization", "requested_by", "approved_by", "linked_scan_job").prefetch_related("reports")
    serializer_class = ServiceRequestSerializer
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    def get_queryset(self):
        queryset = super().get_queryset().order_by("-created_at")
        org_id = self.request.query_params.get("organization")
        if org_id:
            queryset = queryset.filter(organization_id=org_id)
        status = self.request.query_params.get("status")
        if status:
            queryset = queryset.filter(status=status)
        return queryset

    @action(detail=True, methods=["get"], url_path="terminal-stream")
    def terminal_stream(self, request, pk=None):
        request_obj = self.get_object()
        request_id = str(request_obj.id)
        linked_job_id = str(request_obj.linked_scan_job_id) if request_obj.linked_scan_job_id else ""

        since = timezone.now() - timedelta(minutes=3)
        since_raw = (request.query_params.get("since") or "").strip()
        if since_raw:
            try:
                since = datetime.fromisoformat(since_raw.replace("Z", "+00:00"))
                if timezone.is_naive(since):
                    since = timezone.make_aware(since, timezone.get_current_timezone())
            except Exception:
                pass

        def _level_for_text(text: str) -> str:
            lowered = text.lower()
            if "fail" in lowered or "error" in lowered:
                return "err"
            if "complete" in lowered or "approved" in lowered or "published" in lowered:
                return "ok"
            if "warn" in lowered or "reject" in lowered:
                return "warn"
            return "info"

        def _is_related(log: ActivityLog, req_id: str, job_id: str) -> bool:
            metadata = log.metadata if isinstance(log.metadata, dict) else {}
            req_ref = str(metadata.get("service_request") or metadata.get("service_request_id") or "")
            scan_ref = str(metadata.get("scan_job") or metadata.get("scan_job_id") or "")
            return req_ref == req_id or (job_id and scan_ref == job_id)

        current = (
            ServiceRequest.objects.filter(id=request_obj.id)
            .select_related("linked_scan_job", "asset")
            .first()
        )
        if not current:
            return Response({"lines": [], "cursor": since.isoformat(), "status": "MISSING"})

        lines = []

        def _push(ts, level: str, text: str):
            if not ts:
                ts = timezone.now()
            lines.append(
                {
                    "ts": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                    "level": level,
                    "text": text,
                }
            )

        include_snapshot = not bool(since_raw)
        if include_snapshot:
            target = current.domain_url or current.ip_cidr or current.repository_url or (current.asset.name if current.asset else "-")
            _push(current.created_at, "info", f"REQUEST_INIT  service={current.service_type}  target={target}")
            state_level = "err" if current.status == ServiceRequest.STATUS_FAILED else "ok" if current.status == ServiceRequest.STATUS_COMPLETED else "info"
            _push(current.updated_at, state_level, f"REQUEST_STATUS  {current.status}")

        job = current.linked_scan_job
        current_job_id = ""
        if job:
            current_job_id = str(job.id)
        if job and include_snapshot:
            job_level = "err" if job.status == ScanJob.STATUS_FAILED else "ok" if job.status == ScanJob.STATUS_COMPLETED else "info"
            _push(timezone.now(), job_level, f"JOB_STATUS  id={job.id}  state={job.status}")
            if job.started_at:
                _push(job.started_at, "info", "JOB_START  scanner worker picked up task")
            if job.status == ScanJob.STATUS_COMPLETED and job.completed_at:
                _push(job.completed_at, "ok", "JOB_COMPLETE  scan finished successfully")
            if job.status == ScanJob.STATUS_FAILED:
                _push(job.completed_at or timezone.now(), "err", f"JOB_FAIL  {job.failure_reason or 'Unknown failure reason'}")

        new_logs = (
            ActivityLog.objects.filter(organization=current.organization, created_at__gt=since)
            .order_by("created_at")[:150]
        )
        matched_logs = [log for log in new_logs if _is_related(log, request_id, current_job_id or linked_job_id)]
        for log in matched_logs:
            metadata_detail = ""
            if isinstance(log.metadata, dict):
                d = log.metadata.get("detail")
                if isinstance(d, str):
                    metadata_detail = f" :: {d}"
            detail = f"{log.action}{metadata_detail}"
            _push(log.timestamp, _level_for_text(detail), detail)

        lines.sort(key=lambda item: item["ts"])
        cursor = matched_logs[-1].created_at.isoformat() if matched_logs else timezone.now().isoformat()
        return Response(
            {
                "lines": lines[-100:],
                "cursor": cursor,
                "status": current.status,
                "linked_scan_job_id": str(current.linked_scan_job_id) if current.linked_scan_job_id else None,
            }
        )

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        request_obj = self.get_object()
        if request_obj.status == ServiceRequest.STATUS_APPROVED:
            return self.retrieve(request, pk=pk)
        if request_obj.status != ServiceRequest.STATUS_PENDING:
            raise ValidationError({"status": "Only pending requests can be approved."})

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
            ServiceRequest.SERVICE_CLOUD: ScanJob.TYPE_CLOUD,
        }

        job = request_obj.linked_scan_job
        if not job:
            job = ScanJob.objects.create(
                organization=request_obj.organization,
                scan_type=scan_type_map.get(request_obj.service_type, ScanJob.TYPE_CODE),
                asset=request_obj.asset,
                cloud_account=request_obj.cloud_account,
                created_by=request.user,
                initiated_by=request.user,
                service_request=request_obj,
            )
        request_obj.status = ServiceRequest.STATUS_APPROVED
        request_obj.approved_by = request.user
        request_obj.linked_scan_job = job
        request_obj.save(update_fields=["status", "approved_by", "linked_scan_job"])
        _log_activity(request_obj, "Service request approved", user=request.user, metadata={"scan_job_id": str(job.id)})

        return self.retrieve(request, pk=pk)

    @action(detail=True, methods=["post"])
    def start(self, request, pk=None):
        request_obj = self.get_object()
        if request_obj.status == ServiceRequest.STATUS_RUNNING:
            return self.retrieve(request, pk=pk)
        if request_obj.status != ServiceRequest.STATUS_APPROVED:
            raise ValidationError({"status": "Only approved requests can be started."})

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
            ServiceRequest.SERVICE_CLOUD: ScanJob.TYPE_CLOUD,
        }

        job = request_obj.linked_scan_job
        if not job:
            job = ScanJob.objects.create(
                organization=request_obj.organization,
                scan_type=scan_type_map.get(request_obj.service_type, ScanJob.TYPE_CODE),
                asset=request_obj.asset,
                cloud_account=request_obj.cloud_account,
                created_by=request.user,
                initiated_by=request.user,
                service_request=request_obj,
            )
            request_obj.linked_scan_job = job

        request_obj.status = ServiceRequest.STATUS_RUNNING
        request_obj.save(update_fields=["status", "linked_scan_job"])
        _log_activity(request_obj, "Service request started", user=request.user, metadata={"scan_job_id": str(job.id)})

        execute_service_request_job.apply_async(args=[str(job.id)], queue="scanner")
        return self.retrieve(request, pk=pk)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        request_obj = self.get_object()
        if request_obj.status != ServiceRequest.STATUS_PENDING:
            raise ValidationError({"status": "Only pending requests can be rejected."})
        request_obj.status = ServiceRequest.STATUS_REJECTED
        request_obj.approved_by = request.user
        request_obj.save(update_fields=["status", "approved_by"])
        _log_activity(request_obj, "Service request rejected", user=request.user)
        return self.retrieve(request, pk=pk)

    @action(detail=True, methods=["post"], url_path="send-feedback")
    def send_feedback(self, request, pk=None):
        request_obj = self.get_object()
        recipient = request_obj.requested_by
        if not recipient:
            raise ValidationError({"requested_by": "This request has no associated requester."})

        message = (request.data.get("message") or "").strip()
        if not message:
            fallback_error = (request_obj.linked_scan_job.failure_reason if request_obj.linked_scan_job else "").strip()
            if fallback_error:
                message = f"Scan failed: {fallback_error}"
            else:
                raise ValidationError({"message": "Feedback message is required."})

        title = (request.data.get("title") or "Update on your security scan").strip() or "Update on your security scan"
        severity = (request.data.get("severity") or ScanAlert.SEVERITY_WARNING).strip().lower()
        allowed_severities = {choice[0] for choice in ScanAlert.SEVERITY_CHOICES}
        if severity not in allowed_severities:
            raise ValidationError({"severity": f"Invalid severity. Allowed values: {', '.join(sorted(allowed_severities))}."})

        metadata = {
            "service_request_id": str(request_obj.id),
            "service_status": request_obj.status,
            "sent_by_user_id": str(request.user.id),
        }
        if request_obj.linked_scan_job_id:
            metadata["scan_job_id"] = str(request_obj.linked_scan_job_id)
            metadata["failure_reason"] = request_obj.linked_scan_job.failure_reason

        ScanAlert.objects.create(
            organization=request_obj.organization,
            user=recipient,
            severity=severity,
            title=title[:255],
            message=message,
            link="/dashboard/requests",
            metadata=metadata,
        )
        _log_activity(
            request_obj,
            "Admin feedback sent",
            user=request.user,
            metadata={"service_request_id": str(request_obj.id), "recipient_user_id": str(recipient.id)},
        )
        return Response({"status": "sent"})
