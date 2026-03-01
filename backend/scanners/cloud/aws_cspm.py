from __future__ import annotations

from typing import List
from cloud_security.models import CloudAccount
from .types import CloudFindingResult


SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017}


def _boto3():
    try:
        import boto3  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("boto3 is required for AWS CSPM scanning.") from exc
    return boto3


def scan_aws_account(account: CloudAccount) -> List[CloudFindingResult]:
    boto3 = _boto3()
    session = boto3.session.Session()
    sts = session.client("sts")
    assume_kwargs = {
        "RoleArn": account.aws_role_arn,
        "RoleSessionName": "aegis-cspm",
    }
    if account.aws_external_id:
        assume_kwargs["ExternalId"] = account.aws_external_id
    creds = sts.assume_role(**assume_kwargs)["Credentials"]
    creds_args = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }

    findings: List[CloudFindingResult] = []

    s3 = session.client("s3", **creds_args)
    try:
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab.get("PublicAccessBlockConfiguration", {})
                if not all(cfg.get(flag, False) for flag in ["BlockPublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets", "IgnorePublicAcls"]):
                    findings.append(
                        CloudFindingResult(
                            title="S3 bucket public access block disabled",
                            severity="high",
                            description=f"Bucket {name} does not enforce full public access block settings.",
                            remediation="Enable S3 Public Access Block settings and audit bucket policies.",
                            evidence={"bucket": name, "public_access_block": cfg},
                            compliance=["CIS AWS 3.1", "NIST 800-53 AC-3"],
                        )
                    )
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:  # type: ignore[attr-defined]
                findings.append(
                    CloudFindingResult(
                        title="S3 bucket missing public access block",
                        severity="high",
                        description=f"Bucket {name} does not have public access block configuration.",
                        remediation="Configure S3 Public Access Block and review bucket policy.",
                        evidence={"bucket": name},
                        compliance=["CIS AWS 3.1", "NIST 800-53 AC-3"],
                    )
                )
    except Exception:
        pass

    ec2 = session.client("ec2", **creds_args)
    try:
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                ip_ranges = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
                if "0.0.0.0/0" in ip_ranges and from_port is not None and to_port is not None:
                    for port in range(int(from_port), int(to_port) + 1):
                        if port in SENSITIVE_PORTS:
                            findings.append(
                                CloudFindingResult(
                                    title="Security group exposes sensitive port",
                                    severity="critical",
                                    description=f"Security group {sg.get('GroupId')} exposes port {port} to 0.0.0.0/0.",
                                    remediation="Restrict inbound rules to trusted IP ranges or remove exposure.",
                                    evidence={"security_group": sg.get("GroupId"), "port": port},
                                    compliance=["CIS AWS 4.1", "NIST 800-53 AC-17"],
                                )
                            )
    except Exception:
        pass

    iam = session.client("iam", **creds_args)
    try:
        for user in iam.list_users().get("Users", []):
            keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
            for key in keys:
                if key.get("Status") == "Active" and key.get("CreateDate"):
                    findings.append(
                        CloudFindingResult(
                            title="Active IAM access key present",
                            severity="moderate",
                            description=f"IAM user {user['UserName']} has active access keys.",
                            remediation="Rotate access keys regularly and enforce least privilege.",
                            evidence={"user": user["UserName"], "key_id": key.get("AccessKeyId")},
                            compliance=["CIS AWS 1.4", "NIST 800-53 IA-5"],
                        )
                    )
    except Exception:
        pass

    return findings
