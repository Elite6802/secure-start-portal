from __future__ import annotations

from typing import List
from cloud_security.models import CloudAccount
from .types import CloudFindingResult


SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017}


def _azure_clients(account: CloudAccount):
    try:
        from azure.identity import ClientSecretCredential  # type: ignore
        from azure.mgmt.network import NetworkManagementClient  # type: ignore
        from azure.mgmt.storage import StorageManagementClient  # type: ignore
        from azure.mgmt.keyvault import KeyVaultManagementClient  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Azure SDKs are required for Azure CSPM scanning.") from exc

    credential = ClientSecretCredential(
        tenant_id=account.azure_tenant_id,
        client_id=account.azure_client_id,
        client_secret=account.azure_client_secret,
    )
    subscription_id = account.azure_subscription_id
    return (
        NetworkManagementClient(credential, subscription_id),
        StorageManagementClient(credential, subscription_id),
        KeyVaultManagementClient(credential, subscription_id),
    )


def scan_azure_account(account: CloudAccount) -> List[CloudFindingResult]:
    network_client, storage_client, keyvault_client = _azure_clients(account)
    findings: List[CloudFindingResult] = []

    try:
        for nsg in network_client.network_security_groups.list_all():
            for rule in nsg.security_rules or []:
                if rule.direction != "Inbound":
                    continue
                if rule.source_address_prefix in ("*", "0.0.0.0/0"):
                    ports = set()
                    if rule.destination_port_range and rule.destination_port_range.isdigit():
                        ports.add(int(rule.destination_port_range))
                    for port in ports:
                        if port in SENSITIVE_PORTS:
                            findings.append(
                                CloudFindingResult(
                                    title="Azure NSG exposes sensitive port",
                                    severity="critical",
                                    description=f"NSG {nsg.name} exposes port {port} to the public internet.",
                                    remediation="Restrict NSG inbound rules to trusted IP ranges.",
                                    evidence={"nsg": nsg.name, "port": port, "rule": rule.name},
                                    compliance=["CIS Azure 4.1", "NIST 800-53 AC-17"],
                                )
                            )
    except Exception:
        pass

    try:
        for account_obj in storage_client.storage_accounts.list():
            props = storage_client.storage_accounts.get_properties(account_obj.id.split("/")[4], account_obj.name)
            if getattr(props, "allow_blob_public_access", False):
                findings.append(
                    CloudFindingResult(
                        title="Azure Storage allows public blob access",
                        severity="high",
                        description=f"Storage account {account_obj.name} allows public blob access.",
                        remediation="Disable public blob access and review container permissions.",
                        evidence={"storage_account": account_obj.name},
                        compliance=["CIS Azure 3.2", "NIST 800-53 AC-3"],
                    )
                )
    except Exception:
        pass

    try:
        for vault in keyvault_client.vaults.list():
            props = vault.properties
            if props and props.public_network_access == "Enabled":
                findings.append(
                    CloudFindingResult(
                        title="Key Vault public network access enabled",
                        severity="high",
                        description=f"Key Vault {vault.name} allows public network access.",
                        remediation="Restrict Key Vault access to private endpoints or trusted networks.",
                        evidence={"key_vault": vault.name},
                        compliance=["CIS Azure 5.1", "NIST 800-53 AC-3"],
                    )
                )
    except Exception:
        pass

    return findings
