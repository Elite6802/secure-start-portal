from __future__ import annotations

from typing import List

from cloud_security.models import CloudAccount
from .types import CloudFindingResult
from .aws_cspm import scan_aws_account
from .azure_cspm import scan_azure_account
from .gcp_cspm import scan_gcp_account


def scan_cloud_account(account: CloudAccount) -> List[CloudFindingResult]:
    if account.provider == CloudAccount.PROVIDER_AWS:
        return scan_aws_account(account)
    if account.provider == CloudAccount.PROVIDER_AZURE:
        return scan_azure_account(account)
    if account.provider == CloudAccount.PROVIDER_GCP:
        return scan_gcp_account(account)
    return []
