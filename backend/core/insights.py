from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


def _sev_rank(sev: str | None) -> int:
    s = (sev or "").lower()
    return {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}.get(s, 0)


def _pick_top(items: Iterable[str], limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for it in items:
        it = (it or "").strip()
        if not it or it in seen:
            continue
        seen.add(it)
        out.append(it)
        if len(out) >= limit:
            break
    return out


def compute_threat_model_snapshot(
    *,
    findings: list[dict],
    metadata: dict[str, Any] | None,
    service_type: str | None,
) -> dict[str, Any]:
    """
    Threat model snapshot is an explainable, heuristic summary.
    It does not claim full coverage; it highlights likely attacker goals given observed signals.
    """
    metadata = metadata or {}

    # Assets (what we think is in-scope).
    assets: list[str] = []
    if service_type:
        assets.append(service_type.replace("_", " ").title())
    if metadata.get("cloud_account_name"):
        assets.append(f"Cloud: {metadata.get('cloud_account_name')}")
    if metadata.get("endpoints_scanned"):
        assets.append(f"Endpoints: {metadata.get('endpoints_scanned')}")
    if metadata.get("hosts_alive") or metadata.get("hosts_scanned"):
        assets.append(f"Hosts: {metadata.get('hosts_alive') or metadata.get('hosts_scanned')}")
    if metadata.get("repositories_scanned") or metadata.get("repos_scanned"):
        assets.append(f"Repos: {metadata.get('repositories_scanned') or metadata.get('repos_scanned')}")

    # Threat actors.
    actors: list[str] = ["External attacker (internet)", "Automated bot/scanner"]
    if any((f.get("type") == "code" for f in findings)):
        actors.append("Insider / compromised developer workstation")
    if any((f.get("type") == "cloud" for f in findings)):
        actors.append("Cloud account compromise (stolen keys / misconfig abuse)")
    actors = _pick_top(actors, 4)

    # Top threats driven by observed finding categories.
    threats: list[str] = []
    mitigations: list[str] = []
    for f in findings:
        t = f.get("type")
        title = (f.get("title") or "").lower()
        evidence = f.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}

        if t == "network":
            port = str(evidence.get("port") or "")
            service = (evidence.get("service") or "").lower()
            if port in {"22", "3389"} or service in {"ssh", "rdp"}:
                threats.append("Credential-based access attempts against remote administration services")
                mitigations.append("Restrict admin ports to VPN/bastion, enforce MFA, monitor auth failures.")
            if "open redirect" in title or (evidence.get("validation_type") or "").lower().find("redirect") >= 0:
                threats.append("Phishing redirection / token leakage via open redirect behavior")
                mitigations.append("Allowlist redirect destinations and avoid absolute user-controlled redirect URLs.")
            if (evidence.get("validation_type") or "").lower().find("graphql") >= 0:
                threats.append("API surface enumeration via GraphQL introspection")
                mitigations.append("Disable introspection in prod or require authz; add query cost limits.")
            if (evidence.get("validation_type") or "").lower().find("authorization") >= 0:
                threats.append("Broken object level authorization (BOLA/IDOR) leading to data exposure")
                mitigations.append("Enforce object-level authz checks on every ID-based endpoint.")

        if t == "code":
            category = (evidence.get("category") or "").lower()
            if category == "secrets" or "secret" in title or "token" in title:
                threats.append("Unauthorized access via leaked secrets (tokens/keys) in repositories")
                mitigations.append("Rotate exposed secrets, remove from history, adopt secret manager and pre-commit scanning.")
            if "raw sql" in title or "unsanitized" in title:
                threats.append("Injection risks (SQL/command) from unsanitized input flows")
                mitigations.append("Use parameterized queries and validate input; add SAST checks in CI.")

        if t == "cloud":
            if "public" in title or "exposes" in title:
                threats.append("Data exposure from public cloud resources / permissive network rules")
                mitigations.append("Block public access by default; tighten security groups/NSGs; audit IAM policies.")

    threats = _pick_top(threats, 4)
    mitigations = _pick_top(mitigations, 4)

    return {
        "assets": assets[:4],
        "actors": actors,
        "top_threats": threats,
        "priority_mitigations": mitigations,
        "notes": "Heuristic snapshot based on observed scan signals; not a full threat model.",
    }


def compute_exploit_chains(
    *,
    findings: list[dict],
) -> list[dict[str, Any]]:
    """
    Create 1-2 plausible exploit chains (attack-path narratives) from findings.
    Chains are hypotheses, not proof of exploitation.
    """
    chains: list[dict[str, Any]] = []

    def add_chain(title: str, steps: list[str], confidence: str) -> None:
        if not steps:
            return
        chains.append({"title": title, "confidence": confidence, "steps": steps[:5]})

    has_secrets = any((f.get("type") == "code" and (f.get("evidence") or {}).get("category") == "secrets") for f in findings)
    has_bola = any(((f.get("validation_type") or "").lower().find("authorization") >= 0) for f in findings)
    has_open_redirect = any(((f.get("validation_type") or "").lower().find("redirect") >= 0) for f in findings)
    has_public_cloud = any((f.get("type") == "cloud" and "public" in (f.get("title") or "").lower()) for f in findings)
    has_remote_admin = False
    for f in findings:
        if f.get("type") != "network":
            continue
        ev = f.get("evidence") or {}
        if not isinstance(ev, dict):
            continue
        port = str(ev.get("port") or "")
        svc = (ev.get("service") or "").lower()
        if port in {"22", "3389"} or svc in {"ssh", "rdp"}:
            has_remote_admin = True
            break

    if has_bola:
        add_chain(
            "BOLA/IDOR → Data Exposure",
            [
                "Attacker enumerates ID-based API endpoints (often via OpenAPI/Swagger exposure).",
                "Unauthenticated or weakly authorized requests return other users' objects (BOLA/IDOR).",
                "Sensitive fields are harvested at scale (PII, tokens, account metadata).",
                "Business impact: regulatory exposure + account compromise risk.",
            ],
            "medium",
        )

    if has_secrets:
        add_chain(
            "Leaked Secret → Privileged Access",
            [
                "Attacker obtains exposed key/token from repository history or artifacts.",
                "Token is replayed against API/cloud control plane.",
                "Privilege is escalated via over-permissive roles or lateral movement.",
                "Business impact: data access, environment control, service disruption.",
            ],
            "medium",
        )

    if has_remote_admin:
        add_chain(
            "Exposed Remote Admin → Foothold → Lateral Movement",
            [
                "Internet-exposed SSH/RDP is discovered via routine scanning.",
                "Attacker attempts credential stuffing / brute-force against the service.",
                "Foothold enables internal recon and movement to higher-value services.",
            ],
            "low",
        )

    if has_public_cloud:
        add_chain(
            "Public Cloud Resource → Data Exfiltration",
            [
                "Public bucket/storage endpoint is discovered via enumeration or direct URL access.",
                "Sensitive objects are downloaded without authentication.",
                "Business impact: disclosure of customer/business data and compliance penalties.",
            ],
            "medium",
        )

    if has_open_redirect and not any(c["title"].startswith("Open Redirect") for c in chains):
        add_chain(
            "Open Redirect → Phishing → Session Theft (Scenario)",
            [
                "Attacker crafts a trusted-domain URL that redirects to a phishing page.",
                "Victim enters credentials; attacker reuses them to access the platform.",
                "Business impact: account takeover and downstream fraud risk.",
            ],
            "low",
        )

    # De-duplicate by title and keep at most 2 for compact reports.
    unique: dict[str, dict[str, Any]] = {}
    for c in chains:
        unique.setdefault(c["title"], c)
    ordered = list(unique.values())
    return ordered[:2]


def compute_security_maturity(
    *,
    findings: list[dict],
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Security maturity is a light-weight rubric (1..5) derived from scan signals.
    This is not a formal audit; it's a practical indicator to drive improvement planning.
    """
    metadata = metadata or {}

    # Bucket counts by area.
    by_area = {
        "Network Hardening": 0,
        "Application Security": 0,
        "Identity & Secrets": 0,
        "Cloud Governance": 0,
        "Vulnerability Management": 0,
    }
    max_sev = 0

    for f in findings:
        sev = _sev_rank(f.get("severity"))
        if sev > max_sev:
            max_sev = sev
        t = f.get("type")
        ev = f.get("evidence") or {}
        if not isinstance(ev, dict):
            ev = {}
        if t == "network":
            by_area["Network Hardening"] += 1
            if ev.get("validation_type"):
                by_area["Application Security"] += 1
        elif t == "code":
            by_area["Application Security"] += 1
            if (ev.get("category") or "").lower() == "secrets":
                by_area["Identity & Secrets"] += 2
        elif t == "cloud":
            by_area["Cloud Governance"] += 1
        # All findings contribute to vuln mgmt demand.
        by_area["Vulnerability Management"] += 1

    def score_for(area_findings: int) -> int:
        # Base on finding volume + max severity; bounded, explainable.
        penalty = (min(10, area_findings) * 0.25) + (max_sev * 0.6)
        raw = 5.0 - penalty
        if raw < 1.0:
            raw = 1.0
        if raw > 5.0:
            raw = 5.0
        return int(round(raw))

    domains = []
    for domain, count in by_area.items():
        domains.append({"domain": domain, "score": score_for(count), "signals": count})

    overall = round(sum(d["score"] for d in domains) / max(1, len(domains)), 2)
    if overall >= 4.5:
        level = "Optimized"
    elif overall >= 3.5:
        level = "Managed"
    elif overall >= 2.5:
        level = "Defined"
    elif overall >= 1.5:
        level = "Basic"
    else:
        level = "Ad-hoc"

    return {
        "overall": overall,
        "level": level,
        "domains": domains,
        "notes": "Rubric-based estimate derived from scan findings volume/severity; not a formal audit.",
    }

