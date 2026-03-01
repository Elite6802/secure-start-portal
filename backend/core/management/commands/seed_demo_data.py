from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from accounts.models import Organization, User, UserOrganization
from assets.models import Asset
from scans.models import Scan, ScanRequest
from service_requests.models import ServiceRequest
from code_security.models import CodeRepository, CodeFinding
from network_security.models import NetworkAsset, NetworkFinding
from incidents.models import Incident
from activity_log.models import ActivityLog


class Command(BaseCommand):
    help = "Seed demo data for Aegis/Secure Start Portal. Idempotent."

    def handle(self, *args, **options):
        now = timezone.now()
        org, _ = Organization.objects.get_or_create(
            name="Acme Financial Group",
            defaults={"industry": "FinTech", "domain": "acme-finance.com"},
        )

        admin_user, created = User.objects.get_or_create(
            username="admin@acme-finance.com",
            defaults={"email": "admin@acme-finance.com", "is_staff": True, "is_superuser": True},
        )
        if created:
            admin_user.set_password("Admin1234!")
            admin_user.save()

        UserOrganization.objects.get_or_create(
            user=admin_user,
            organization=org,
            defaults={"role": "security_lead", "is_primary": True},
        )

        assets_data = [
            ("Customer API", Asset.TYPE_API, "https://api.acme-finance.com"),
            ("Web Portal", Asset.TYPE_WEB_APP, "https://portal.acme-finance.com"),
            ("Core Banking Cluster", Asset.TYPE_CLOUD_RESOURCE, "aws://prod-cluster-01"),
            ("Internal Network Segment", Asset.TYPE_NETWORK_SEGMENT, "10.10.0.0/16"),
            ("Legacy VPN Gateway", Asset.TYPE_IP_RANGE, "203.0.113.0/28"),
            ("Payments Repo", Asset.TYPE_CODE_REPOSITORY, "https://github.com/acme/payments"),
        ]

        assets = []
        for name, asset_type, identifier in assets_data:
            asset, _ = Asset.objects.get_or_create(
                organization=org,
                name=name,
                defaults={
                    "asset_type": asset_type,
                    "identifier": identifier,
                    "risk_level": Asset.RISK_MODERATE,
                    "last_scanned_at": now - timedelta(days=2),
                },
            )
            assets.append(asset)

        scans_payload = [
            (assets[0], Scan.TYPE_API, Scan.STATUS_COMPLETED, {"high": 1, "moderate": 2, "low": 6}, now - timedelta(days=4), now - timedelta(days=4, minutes=-25)),
            (assets[1], Scan.TYPE_WEB, Scan.STATUS_COMPLETED, {"high": 0, "moderate": 3, "low": 4}, now - timedelta(days=3), now - timedelta(days=3, minutes=-18)),
            (assets[2], Scan.TYPE_INFRA, Scan.STATUS_COMPLETED, {"high": 2, "moderate": 1, "low": 2}, now - timedelta(days=1), now - timedelta(days=1, minutes=-32)),
        ]

        for asset, scan_type, status, summary, started, completed in scans_payload:
            Scan.objects.get_or_create(
                organization=org,
                asset=asset,
                scan_type=scan_type,
                defaults={
                    "status": status,
                    "severity_summary": summary,
                    "started_at": started,
                    "completed_at": completed,
                },
            )

        repo_asset = assets[-1]
        repo, _ = CodeRepository.objects.get_or_create(
            organization=org,
            asset=repo_asset,
            defaults={"repo_url": repo_asset.identifier, "language": "Python"},
        )

        code_findings = [
            ("Secrets exposure in CI logs", "secrets", "high", "Detected plaintext API key in build logs.", "Rotate key and add secret scanning.", ["OWASP ASVS 2.1", "NIST 800-53 AC-6"]),
            ("Dependency vulnerability CVE-2024-27198", "dependency", "moderate", "Outdated library with known RCE risk.", "Upgrade dependency and pin versions.", ["OWASP Top 10 A06", "NIST 800-53 SI-2"]),
            ("Insecure configuration defaults", "sast", "low", "Default debug flags enabled in production config.", "Disable debug and enforce secure defaults.", ["ISO 27001 A.12", "OWASP Top 10 A05"]),
        ]

        for title, category, severity, description, remediation, mapping in code_findings:
            CodeFinding.objects.get_or_create(
                repository=repo,
                title=title,
                defaults={
                    "category": category,
                    "severity": severity,
                    "description": description,
                    "remediation": remediation,
                    "standard_mapping": mapping,
                },
            )

        network_asset, _ = NetworkAsset.objects.get_or_create(
            organization=org,
            asset=assets[3],
            defaults={"network_type": "internal"},
        )

        network_findings = [
            ("Open port 3389 detected on admin subnet", "exposed_service", "high", "Restrict RDP exposure to bastion hosts."),
            ("Weak TLS configuration detected", "misconfiguration", "moderate", "Enforce TLS 1.2+ and disable legacy ciphers."),
            ("Exposed admin service on perimeter", "exposed_service", "critical", "Remove public exposure and add MFA."),
        ]

        for summary, finding_type, severity, recommendation in network_findings:
            NetworkFinding.objects.get_or_create(
                network_asset=network_asset,
                summary=summary,
                defaults={
                    "finding_type": finding_type,
                    "severity": severity,
                    "recommendation": recommendation,
                },
            )

        Incident.objects.get_or_create(
            organization=org,
            description="Credential leakage detected in CI logs",
            defaults={
                "severity": "high",
                "status": "investigating",
                "detected_at": now - timedelta(days=2, hours=4),
                "resolved_at": None,
            },
        )

        Incident.objects.get_or_create(
            organization=org,
            description="Exposed admin service on perimeter network",
            defaults={
                "severity": "critical",
                "status": "open",
                "detected_at": now - timedelta(days=1, hours=2),
                "resolved_at": None,
            },
        )

        ActivityLog.objects.get_or_create(
            organization=org,
            action="Scan started",
            timestamp=now - timedelta(days=4, hours=1),
            defaults={"metadata": {"detail": "API scan initiated for Customer API."}, "user": admin_user},
        )
        ActivityLog.objects.get_or_create(
            organization=org,
            action="Scan completed",
            timestamp=now - timedelta(days=3, hours=21),
            defaults={"metadata": {"detail": "Web portal scan completed with moderate findings."}, "user": admin_user},
        )
        ActivityLog.objects.get_or_create(
            organization=org,
            action="Incident created",
            timestamp=now - timedelta(days=1, hours=3),
            defaults={"metadata": {"detail": "Exposed admin service flagged for investigation."}, "user": admin_user},
        )

        ScanRequest.objects.get_or_create(
            organization=org,
            requested_by=admin_user,
            scan_type=ScanRequest.TYPE_CODE,
            target=repo.repo_url,
            defaults={
                "status": ScanRequest.STATUS_REQUESTED,
                "client_notes": "Please scan the payments repository before the next release.",
                "repository": repo,
                "asset": repo_asset,
            },
        )
        ScanRequest.objects.get_or_create(
            organization=org,
            requested_by=admin_user,
            scan_type=ScanRequest.TYPE_WEB,
            target=assets[1].identifier,
            defaults={
                "status": ScanRequest.STATUS_COMPLETED,
                "client_notes": "Validate portal exposure ahead of the quarterly audit.",
                "admin_notes": "Baseline scan completed. Moderate findings shared with engineering.",
                "asset": assets[1],
                "completed_at": now - timedelta(days=1, hours=3),
            },
        )

        ServiceRequest.objects.get_or_create(
            organization=org,
            requested_by=admin_user,
            requested_role=UserOrganization.ROLE_SECURITY_LEAD,
            service_type=ServiceRequest.SERVICE_CODE_SECRETS,
            repository_url=repo.repo_url,
            justification="Request a secrets review prior to the upcoming release window.",
            defaults={
                "status": ServiceRequest.STATUS_PENDING,
                "scope": ServiceRequest.SCOPE_REPOSITORY,
            },
        )
        ServiceRequest.objects.get_or_create(
            organization=org,
            requested_by=admin_user,
            requested_role=UserOrganization.ROLE_SECURITY_LEAD,
            service_type=ServiceRequest.SERVICE_NETWORK,
            domain_url=assets[3].identifier,
            justification="Validate segmentation controls for the internal network segment.",
            defaults={
                "status": ServiceRequest.STATUS_APPROVED,
                "scope": ServiceRequest.SCOPE_DOMAIN,
                "approved_by": admin_user,
            },
        )

        self.stdout.write(self.style.SUCCESS("Demo data seeded successfully."))
