from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
import uuid
import os

from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError

from internal.permissions import IsInternalAdmin
from activity_log.models import ActivityLog
from accounts.models import UserOrganization
from accounts.models import Organization
from assets.models import Asset
from code_security.models import CodeFinding
from network_security.models import NetworkFinding
from cloud_security.models import CloudFinding
from scans.models import ScanJob
from service_requests.models import ServiceRequest
from service_requests.tasks import execute_service_request_job

from .models import FindingDisposition
from .utils import disposition_effective_status, age_days


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _sla_days(sev: str) -> int:
    s = (sev or "").lower().strip()
    return {
        "critical": _env_int("SLA_DAYS_CRITICAL", 7),
        "high": _env_int("SLA_DAYS_HIGH", 14),
        "moderate": _env_int("SLA_DAYS_MODERATE", 30),
        "low": _env_int("SLA_DAYS_LOW", 90),
    }.get(s, 30)


def _overdue(sev: str, created_at) -> bool:
    return age_days(created_at) > _sla_days(sev)


def _finding_ref(kind: str, obj_id) -> dict:
    return {"kind": kind, "id": str(obj_id)}


def _asset_for(kind: str, f):
    if kind == "code":
        return getattr(getattr(f, "repository", None), "asset", None)
    if kind == "network":
        return getattr(getattr(f, "network_asset", None), "asset", None)
    return getattr(f, "asset", None)


def _title_for(kind: str, f) -> str:
    if kind == "network":
        return f.summary
    return f.title


def _org_id_for(kind: str, f) -> str:
    if kind == "cloud":
        return str(getattr(f, "organization_id", "") or "")
    if kind == "code":
        return str(getattr(getattr(f, "repository", None), "organization_id", "") or "")
    return str(getattr(getattr(f, "network_asset", None), "organization_id", "") or "")


def _group_keys(asset: Asset | None, group_by: str) -> list[str]:
    if group_by == "tag":
        tags = getattr(asset, "tags", None) if asset else None
        if isinstance(tags, list) and tags:
            cleaned = [str(t).strip() for t in tags if str(t).strip()]
            return cleaned[:5] or ["untagged"]
        return ["untagged"]
    if group_by == "owner":
        contact = (getattr(asset, "owner_contact", "") or "").strip() if asset else ""
        return [contact or "unassigned"]
    team = (getattr(asset, "owner_team", "") or "").strip() if asset else ""
    return [team or "unassigned"]


def _load_dispositions(ct: ContentType, ids: list[uuid.UUID]) -> dict:
    if not ids:
        return {}
    rows = FindingDisposition.objects.filter(content_type=ct, object_id__in=ids)
    return {d.object_id: d for d in rows}


def _row(kind: str, f, disp: FindingDisposition | None) -> dict:
    asset = _asset_for(kind, f)
    effective = disposition_effective_status(disp)

    model_status = getattr(f, "status", "open")
    if model_status == "resolved":
        status = "resolved"
    else:
        status = effective

    sev = (getattr(f, "severity", "") or "low").lower()
    created = getattr(f, "created_at", None)
    return {
        **_finding_ref(kind, f.id),
        "title": _title_for(kind, f),
        "severity": sev,
        "status": status,
        "created_at": created,
        "age_days": age_days(created),
        "sla_days": _sla_days(sev),
        "overdue": _overdue(sev, created) if status == "open" else False,
        "organization_id": _org_id_for(kind, f),
        "asset_id": str(asset.id) if asset else "",
        "asset_name": asset.name if asset else (getattr(getattr(f, "cloud_account", None), "name", "") or "Cloud Account"),
        "owner_team": (getattr(asset, "owner_team", "") or "").strip() if asset else "",
        "owner_contact": (getattr(asset, "owner_contact", "") or "").strip() if asset else "",
        "tags": getattr(asset, "tags", []) if asset else [],
        "disposition": (
            {
                "status": disp.status,
                "expires_at": disp.expires_at,
                "justification": disp.justification,
                "updated_by": getattr(disp.updated_by, "email", "") if getattr(disp, "updated_by", None) else "",
                "updated_at": disp.updated_at,
            }
            if disp
            else None
        ),
    }


class TriageInternalViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, IsInternalAdmin]

    @action(detail=False, methods=["get"], url_path="fix-by-owner")
    def fix_by_owner(self, request):
        group_by = (request.query_params.get("group_by") or "team").strip().lower()
        if group_by not in {"team", "owner", "tag"}:
            raise ValidationError({"group_by": "group_by must be one of: team, owner, tag."})

        max_items = max(50, min(5000, _env_int("TRIAGE_BOARD_MAX_FINDINGS", 800)))
        code_qs = (
            CodeFinding.objects.filter(status=CodeFinding.STATUS_OPEN)
            .select_related("repository", "repository__asset")
            .order_by("-created_at")[: max_items // 3]
        )
        net_qs = (
            NetworkFinding.objects.filter(status=NetworkFinding.STATUS_OPEN)
            .select_related("network_asset", "network_asset__asset")
            .order_by("-created_at")[: max_items // 3]
        )
        cloud_qs = (
            CloudFinding.objects.filter(status=getattr(CloudFinding, "STATUS_OPEN", "open"))
            .select_related("asset", "cloud_account")
            .order_by("-created_at")[: max_items // 3]
        )

        ct_code = ContentType.objects.get_for_model(CodeFinding)
        ct_net = ContentType.objects.get_for_model(NetworkFinding)
        ct_cloud = ContentType.objects.get_for_model(CloudFinding)
        disp_code = _load_dispositions(ct_code, [f.id for f in code_qs])
        disp_net = _load_dispositions(ct_net, [f.id for f in net_qs])
        disp_cloud = _load_dispositions(ct_cloud, [f.id for f in cloud_qs])

        groups: dict[str, dict] = {}

        def bump(key: str, r: dict):
            g = groups.setdefault(
                key,
                {
                    "group_key": key,
                    "open_total": 0,
                    "overdue_total": 0,
                    "by_severity": {"critical": 0, "high": 0, "moderate": 0, "low": 0},
                    "sample": [],
                },
            )
            if r["status"] != "open":
                return
            g["open_total"] += 1
            g["by_severity"][r["severity"]] = int(g["by_severity"].get(r["severity"], 0)) + 1
            if r.get("overdue"):
                g["overdue_total"] += 1
            if len(g["sample"]) < 4:
                g["sample"].append({k: r[k] for k in ("kind", "id", "title", "severity", "asset_name", "age_days", "overdue")})

        for f in code_qs:
            r = _row("code", f, disp_code.get(f.id))
            for k in _group_keys(_asset_for("code", f), group_by):
                bump(k, r)
        for f in net_qs:
            r = _row("network", f, disp_net.get(f.id))
            for k in _group_keys(_asset_for("network", f), group_by):
                bump(k, r)
        for f in cloud_qs:
            r = _row("cloud", f, disp_cloud.get(f.id))
            for k in _group_keys(_asset_for("cloud", f), group_by):
                bump(k, r)

        rows = list(groups.values())
        rows.sort(key=lambda r: (r["by_severity"].get("critical", 0), r["by_severity"].get("high", 0), r["open_total"]), reverse=True)
        return Response({"generated_at": timezone.now(), "group_by": group_by, "count": len(rows), "results": rows[:200]})

    @action(detail=False, methods=["get"], url_path="findings")
    def findings(self, request):
        group_by = (request.query_params.get("group_by") or "team").strip().lower()
        if group_by not in {"team", "owner", "tag"}:
            raise ValidationError({"group_by": "group_by must be one of: team, owner, tag."})
        group_key = (request.query_params.get("group_key") or "").strip()
        if not group_key:
            raise ValidationError({"group_key": "group_key is required."})
        status = (request.query_params.get("status") or "open").strip().lower()
        if status not in {"open", "suppressed", "accepted_risk", "resolved", "all"}:
            raise ValidationError({"status": "status must be one of: open, suppressed, accepted_risk, resolved, all."})

        max_items = max(50, min(2000, _env_int("TRIAGE_FINDINGS_MAX", 400)))
        asset_q = Asset.objects.all()
        if group_by == "tag":
            asset_q = asset_q.filter(tags__contains=[group_key])
        elif group_by == "owner":
            asset_q = asset_q.filter(owner_contact=group_key)
        else:
            asset_q = asset_q.filter(owner_team=group_key)
        asset_ids = list(asset_q.values_list("id", flat=True)[:2000])

        code_qs = (
            CodeFinding.objects.filter(status=CodeFinding.STATUS_OPEN, repository__asset_id__in=asset_ids)
            .select_related("repository", "repository__asset")
            .order_by("-created_at")[: max_items // 2]
        )
        net_qs = (
            NetworkFinding.objects.filter(status=NetworkFinding.STATUS_OPEN, network_asset__asset_id__in=asset_ids)
            .select_related("network_asset", "network_asset__asset")
            .order_by("-created_at")[: max_items // 2]
        )
        cloud_qs = (
            CloudFinding.objects.filter(status=getattr(CloudFinding, "STATUS_OPEN", "open"), asset_id__in=asset_ids)
            .select_related("asset", "cloud_account")
            .order_by("-created_at")[: max_items // 2]
        )

        ct_code = ContentType.objects.get_for_model(CodeFinding)
        ct_net = ContentType.objects.get_for_model(NetworkFinding)
        ct_cloud = ContentType.objects.get_for_model(CloudFinding)
        disp_code = _load_dispositions(ct_code, [f.id for f in code_qs])
        disp_net = _load_dispositions(ct_net, [f.id for f in net_qs])
        disp_cloud = _load_dispositions(ct_cloud, [f.id for f in cloud_qs])

        rows = []
        rows.extend([_row("code", f, disp_code.get(f.id)) for f in code_qs])
        rows.extend([_row("network", f, disp_net.get(f.id)) for f in net_qs])
        rows.extend([_row("cloud", f, disp_cloud.get(f.id)) for f in cloud_qs])

        if status != "all":
            rows = [r for r in rows if r.get("status") == status]
        rows.sort(key=lambda r: (r.get("overdue", False), r.get("age_days", 0)), reverse=True)
        return Response({"generated_at": timezone.now(), "count": len(rows), "results": rows[:max_items]})

    @action(detail=False, methods=["get"], url_path="sla/overview")
    def sla_overview(self, request):
        now = timezone.now()
        window_days = max(7, min(365, _env_int("TRIAGE_MTTR_WINDOW_DAYS", 90)))
        since = now - timedelta(days=window_days)
        thresholds = {s: _sla_days(s) for s in ("critical", "high", "moderate", "low")}

        # Bounded open set for dashboard-level metrics.
        code_qs = CodeFinding.objects.filter(status=CodeFinding.STATUS_OPEN).order_by("-created_at")[:600]
        net_qs = NetworkFinding.objects.filter(status=NetworkFinding.STATUS_OPEN).order_by("-created_at")[:600]
        cloud_qs = CloudFinding.objects.filter(status=getattr(CloudFinding, "STATUS_OPEN", "open")).order_by("-created_at")[:600]

        ct_code = ContentType.objects.get_for_model(CodeFinding)
        ct_net = ContentType.objects.get_for_model(NetworkFinding)
        ct_cloud = ContentType.objects.get_for_model(CloudFinding)
        disp_code = _load_dispositions(ct_code, [f.id for f in code_qs])
        disp_net = _load_dispositions(ct_net, [f.id for f in net_qs])
        disp_cloud = _load_dispositions(ct_cloud, [f.id for f in cloud_qs])

        open_rows = []
        open_rows.extend([_row("code", f, disp_code.get(f.id)) for f in code_qs])
        open_rows.extend([_row("network", f, disp_net.get(f.id)) for f in net_qs])
        open_rows.extend([_row("cloud", f, disp_cloud.get(f.id)) for f in cloud_qs])
        open_rows = [r for r in open_rows if r.get("status") == "open"]

        buckets = [0, 3, 7, 14, 30, 60, 90, 9999]

        def label(lo: int, hi: int) -> str:
            return f">{lo}d" if hi >= 9999 else f"{lo}-{hi}d"

        by_sev = {s: {"total_open": 0, "overdue": 0, "age_buckets": defaultdict(int)} for s in thresholds.keys()}
        for r in open_rows:
            sev = r.get("severity") or "low"
            if sev not in by_sev:
                sev = "low"
            by_sev[sev]["total_open"] += 1
            if r.get("overdue"):
                by_sev[sev]["overdue"] += 1
            d = int(r.get("age_days") or 0)
            for i in range(len(buckets) - 1):
                lo = buckets[i]
                hi = buckets[i + 1]
                if d >= lo and (d <= hi or hi == 9999):
                    by_sev[sev]["age_buckets"][label(lo, hi)] += 1
                    break

        def mttr_days(qs):
            vals = []
            for f in qs:
                if not f.created_at or not getattr(f, "resolved_at", None):
                    continue
                if f.resolved_at < since:
                    continue
                vals.append((f.resolved_at - f.created_at).total_seconds() / 86400.0)
            if not vals:
                return None
            return round(sum(vals) / len(vals), 1)

        mttr = {
            "code": mttr_days(CodeFinding.objects.filter(status=CodeFinding.STATUS_RESOLVED).only("created_at", "resolved_at").order_by("-resolved_at")[:800]),
            "network": mttr_days(NetworkFinding.objects.filter(status=NetworkFinding.STATUS_RESOLVED).only("created_at", "resolved_at").order_by("-resolved_at")[:800]),
            "cloud": mttr_days(CloudFinding.objects.filter(status=getattr(CloudFinding, "STATUS_RESOLVED", "resolved")).only("created_at", "resolved_at").order_by("-resolved_at")[:800]),
        }
        mttr_vals = [v for v in mttr.values() if isinstance(v, (int, float))]
        mttr_overall = round(sum(mttr_vals) / len(mttr_vals), 1) if mttr_vals else None

        return Response(
            {
                "generated_at": now,
                "window_days": window_days,
                "thresholds_days": thresholds,
                "open_total": len(open_rows),
                "overdue_total": sum(int(by_sev[s]["overdue"]) for s in by_sev.keys()),
                "by_severity": {s: {**by_sev[s], "age_buckets": dict(by_sev[s]["age_buckets"])} for s in ("critical", "high", "moderate", "low")},
                "mttr_days": {"overall": mttr_overall, **mttr},
            }
        )

    @action(detail=False, methods=["post"], url_path="bulk-action")
    def bulk_action(self, request):
        payload = request.data or {}
        action_name = (payload.get("action") or "").strip().lower()
        items = payload.get("items") or []
        justification = (payload.get("justification") or "").strip()
        expires_at = payload.get("expires_at")

        if action_name not in {"accept_risk", "suppress", "resolve", "retest"}:
            raise ValidationError({"action": "action must be one of: accept_risk, suppress, resolve, retest."})
        if not isinstance(items, list) or not items:
            raise ValidationError({"items": "items must be a non-empty list of {kind, id}."})
        if len(items) > 50:
            raise ValidationError({"items": "Bulk actions are limited to 50 findings per request."})
        if action_name in {"accept_risk", "suppress"} and not justification:
            raise ValidationError({"justification": "justification is required for accept_risk and suppress."})

        exp_dt = None
        if expires_at:
            try:
                exp_dt = timezone.datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                if timezone.is_naive(exp_dt):
                    exp_dt = timezone.make_aware(exp_dt, timezone=timezone.utc)
            except Exception:
                raise ValidationError({"expires_at": "expires_at must be an ISO datetime string."})
        if action_name == "suppress":
            if not exp_dt:
                raise ValidationError({"expires_at": "expires_at is required for suppress."})
            if exp_dt <= timezone.now():
                raise ValidationError({"expires_at": "expires_at must be in the future."})

        resolved: list[tuple[str, object]] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            kind = (it.get("kind") or "").strip().lower()
            obj_id = (it.get("id") or "").strip()
            if kind not in {"code", "network", "cloud"}:
                continue
            try:
                uid = uuid.UUID(obj_id)
            except Exception:
                continue
            model = {"code": CodeFinding, "network": NetworkFinding, "cloud": CloudFinding}[kind]
            obj = model.objects.filter(id=uid).first()
            if obj:
                resolved.append((kind, obj))
        if not resolved:
            raise ValidationError({"items": "No valid findings found for bulk action."})

        def _log_org_id() -> str:
            kind0, obj0 = resolved[0]
            if kind0 == "cloud":
                return str(getattr(obj0, "organization_id", "") or "")
            if kind0 == "code":
                return str(getattr(getattr(obj0, "repository", None), "organization_id", "") or "")
            return str(getattr(getattr(obj0, "network_asset", None), "organization_id", "") or "")

        org_id = _log_org_id()
        org = Organization.objects.filter(id=org_id).first()
        if not org:
            raise ValidationError({"organization": "Unable to resolve organization for triage action."})

        def upsert_disp(kind: str, obj, status: str):
            ct = ContentType.objects.get_for_model(obj.__class__)
            org_id = _org_id_for(kind, obj)
            if not org_id:
                return
            disp, _ = FindingDisposition.objects.get_or_create(content_type=ct, object_id=obj.id, defaults={"organization_id": org_id})
            disp.organization_id = org_id
            disp.status = status
            disp.justification = justification
            disp.expires_at = exp_dt
            disp.updated_by = request.user
            disp.save()

        if action_name == "resolve":
            now = timezone.now()
            for kind, obj in resolved:
                if hasattr(obj, "status") and hasattr(obj, "resolved_at"):
                    obj.status = "resolved"
                    obj.resolved_at = now
                    obj.save(update_fields=["status", "resolved_at", "updated_at"])
                upsert_disp(kind, obj, FindingDisposition.STATUS_RESOLVED)
            ActivityLog.objects.create(
                organization=org,
                user=request.user,
                action="Triage bulk resolve",
                timestamp=timezone.now(),
                metadata={"count": len(resolved), "items": [_finding_ref(k, o.id) for k, o in resolved]},
            )
            return Response({"ok": True, "updated": len(resolved)})

        if action_name == "accept_risk":
            for kind, obj in resolved:
                upsert_disp(kind, obj, FindingDisposition.STATUS_ACCEPTED_RISK)
            ActivityLog.objects.create(
                organization=org,
                user=request.user,
                action="Triage bulk accept risk",
                timestamp=timezone.now(),
                metadata={"count": len(resolved), "items": [_finding_ref(k, o.id) for k, o in resolved], "expires_at": str(expires_at or "")},
            )
            return Response({"ok": True, "updated": len(resolved)})

        if action_name == "suppress":
            for kind, obj in resolved:
                upsert_disp(kind, obj, FindingDisposition.STATUS_SUPPRESSED)
            ActivityLog.objects.create(
                organization=org,
                user=request.user,
                action="Triage bulk suppress",
                timestamp=timezone.now(),
                metadata={"count": len(resolved), "items": [_finding_ref(k, o.id) for k, o in resolved], "expires_at": str(expires_at or "")},
            )
            return Response({"ok": True, "updated": len(resolved)})

        # retest
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

        def service_type_for(kind: str, obj) -> str:
            sr = getattr(obj, "service_request", None)
            if sr and getattr(sr, "service_type", ""):
                return sr.service_type
            if kind == "code":
                cat = getattr(obj, "category", "") or ""
                if cat == CodeFinding.CATEGORY_SECRETS:
                    return ServiceRequest.SERVICE_CODE_SECRETS
                if cat == CodeFinding.CATEGORY_DEPENDENCY:
                    return ServiceRequest.SERVICE_DEPENDENCY
                return ServiceRequest.SERVICE_CODE_COMPLIANCE
            if kind == "cloud":
                return ServiceRequest.SERVICE_CLOUD
            return ServiceRequest.SERVICE_NETWORK

        targets: dict[tuple, dict] = {}
        for kind, obj in resolved:
            sr = getattr(obj, "service_request", None)
            service_type = service_type_for(kind, obj)
            scope = getattr(sr, "scope", None) or ServiceRequest.SCOPE_ASSET
            asset = _asset_for(kind, obj)
            repository_url = getattr(sr, "repository_url", "") if sr else ""
            ip_cidr = getattr(sr, "ip_cidr", "") if sr else ""
            domain_url = getattr(sr, "domain_url", "") if sr else ""
            cloud_account = getattr(sr, "cloud_account", None) if sr else getattr(obj, "cloud_account", None)

            org = getattr(sr, "organization", None)
            if not org:
                if kind == "cloud":
                    org = getattr(obj, "organization", None)
                elif kind == "code":
                    org = getattr(getattr(obj, "repository", None), "organization", None)
                else:
                    org = getattr(getattr(obj, "network_asset", None), "organization", None)
            if not org:
                continue

            key = (str(org.id), service_type, scope, str(getattr(asset, "id", "")), repository_url, ip_cidr, domain_url, str(getattr(cloud_account, "id", "")))
            targets.setdefault(
                key,
                {
                    "org": org,
                    "service_type": service_type,
                    "scope": scope,
                    "asset": asset,
                    "repository_url": repository_url,
                    "ip_cidr": ip_cidr,
                    "domain_url": domain_url,
                    "cloud_account": cloud_account,
                },
            )

        if len(targets) > 20:
            raise ValidationError({"items": "Retest is limited to 20 unique targets per request."})

        created_requests: list[str] = []
        created_jobs: list[str] = []
        for t in targets.values():
            sr = ServiceRequest.objects.create(
                organization=t["org"],
                requested_by=request.user,
                requested_role=UserOrganization.ROLE_SECURITY_LEAD,
                service_type=t["service_type"],
                scope=t["scope"],
                repository_url=t.get("repository_url") or "",
                asset=t.get("asset"),
                cloud_account=t.get("cloud_account"),
                ip_cidr=t.get("ip_cidr") or "",
                domain_url=t.get("domain_url") or "",
                justification=f"Triage re-test requested. {justification}".strip(),
                status=ServiceRequest.STATUS_APPROVED,
                approved_by=request.user,
            )
            job = ScanJob.objects.create(
                organization=t["org"],
                scan_type=scan_type_map.get(t["service_type"], ScanJob.TYPE_NETWORK),
                asset=t.get("asset"),
                cloud_account=t.get("cloud_account"),
                created_by=request.user,
                service_request=sr,
            )
            sr.linked_scan_job = job
            sr.save(update_fields=["linked_scan_job"])
            execute_service_request_job.apply_async(args=[str(job.id)], queue="scanner")
            created_requests.append(str(sr.id))
            created_jobs.append(str(job.id))

        ActivityLog.objects.create(
            organization=org,
            user=request.user,
            action="Triage bulk retest initiated",
            timestamp=timezone.now(),
            metadata={"items": [_finding_ref(k, o.id) for k, o in resolved], "unique_targets": len(targets), "scan_job_ids": created_jobs},
        )
        return Response({"ok": True, "unique_targets": len(targets), "service_requests": created_requests, "scan_jobs": created_jobs})
