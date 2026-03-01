from __future__ import annotations

import json
from typing import List
from cloud_security.models import CloudAccount
from .types import CloudFindingResult


SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017}


def _gcp_clients(account: CloudAccount):
    try:
        from google.oauth2 import service_account  # type: ignore
        from google.cloud import storage  # type: ignore
        from google.cloud import compute_v1  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("GCP SDKs are required for GCP CSPM scanning.") from exc

    info = json.loads(account.gcp_service_account_json)
    creds = service_account.Credentials.from_service_account_info(info)
    return storage.Client(credentials=creds, project=account.gcp_project_id), compute_v1.FirewallsClient(credentials=creds)


def scan_gcp_account(account: CloudAccount) -> List[CloudFindingResult]:
    storage_client, fw_client = _gcp_clients(account)
    findings: List[CloudFindingResult] = []

    try:
        for bucket in storage_client.list_buckets(project=account.gcp_project_id):
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                    findings.append(
                        CloudFindingResult(
                            title="GCP bucket is public",
                            severity="high",
                            description=f"Bucket {bucket.name} is publicly accessible.",
                            remediation="Remove public IAM bindings and enforce uniform bucket-level access.",
                            evidence={"bucket": bucket.name},
                            compliance=["CIS GCP 5.1", "NIST 800-53 AC-3"],
                        )
                    )
                    break
    except Exception:
        pass

    try:
        for fw in fw_client.list(project=account.gcp_project_id):
            for allowed in fw.allowed or []:
                ports = allowed.ports or []
                for port in ports:
                    if port.isdigit() and int(port) in SENSITIVE_PORTS:
                        if "0.0.0.0/0" in (fw.source_ranges or []):
                            findings.append(
                                CloudFindingResult(
                                    title="GCP firewall allows sensitive port",
                                    severity="critical",
                                    description=f"Firewall rule {fw.name} allows port {port} from 0.0.0.0/0.",
                                    remediation="Restrict firewall source ranges to trusted IPs.",
                                    evidence={"firewall": fw.name, "port": port},
                                    compliance=["CIS GCP 3.2", "NIST 800-53 AC-17"],
                                )
                            )
    except Exception:
        pass

    return findings
