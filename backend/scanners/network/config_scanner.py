import ipaddress
import http.client
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Dict, Iterator, List
from urllib.parse import urlparse


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


CONNECT_TIMEOUT = 1.5
REQUEST_TIMEOUT = 2.0
SLEEP_BETWEEN_CONNECTIONS = 0.1
MAX_CONNECTIONS = _env_int("NETWORK_SCAN_MAX_CONNECTIONS", 120)
MAX_HOSTS = _env_int("NETWORK_SCAN_MAX_HOSTS", 256)
MAX_CIDR_ADDRESSES = _env_int("NETWORK_SCAN_MAX_CIDR_ADDRESSES", 65536)
MIN_IPV4_PREFIX = _env_int("NETWORK_SCAN_MIN_IPV4_PREFIX", 16)
MIN_IPV6_PREFIX = _env_int("NETWORK_SCAN_MIN_IPV6_PREFIX", 48)
ENABLE_DEFAULT_CREDENTIAL_CHECKS = os.getenv("NETWORK_SCAN_ENABLE_DEFAULT_CREDS", "0").strip() in {"1", "true", "TRUE", "yes", "YES"}

DISCOVERY_PORTS = [22, 53, 80, 443, 3389]
PORTS_TO_CHECK = [22, 53, 80, 139, 443, 445, 500, 1194, 1701, 1723, 3306, 4500, 5432, 6379, 8080, 8443, 9200]
WEB_PORTS = [80, 443, 8080, 8443]
API_PORTS = [80, 443, 8080, 8443]
INFRA_PORTS = [22, 53, 139, 445, 500, 1194, 1701, 1723, 3306, 4500, 5432, 6379, 9200]

ADMIN_PORTS = {8443, 8080, 8000, 9000, 15672}
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 9200}
HTTP_PORTS = {80, 8080, 443, 8443}
TLS_PORTS = {443, 8443}
DNS_PORT = 53
SMB_PORTS = {139, 445}
VPN_PORTS = {500, 4500, 1194, 1701, 1723}

SERVICE_PORT_MAP = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    139: "SMB",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    445: "SMB",
    500: "IPsec/IKE",
    4500: "IPsec/NAT-T",
    1194: "OpenVPN",
    1701: "L2TP",
    1723: "PPTP",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
]

API_DOC_PATHS = ["/swagger", "/swagger/index.html", "/openapi.json", "/api/docs"]

VULN_SIGNATURES = [
    {
        "service": "OpenSSH",
        "version_prefixes": ["7.2", "7.1"],
        "cve": "CVE-2016-10012",
        "severity": "high",
        "summary": "Potential vulnerable OpenSSH version detected",
        "recommendation": "Upgrade OpenSSH to the latest supported patch release.",
    },
    {
        "service": "Apache",
        # Applies to Apache HTTPD 2.4.0-2.4.29 (range check via prefix list).
        "version_prefixes": [f"2.4.{i}" for i in range(0, 30)],
        "cve": "CVE-2017-15715",
        "severity": "high",
        "summary": "Potential vulnerable Apache HTTPD version detected",
        "recommendation": "Upgrade Apache HTTPD to a supported 2.4.x release.",
        "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "service": "Apache",
        "version_prefixes": ["2.4.49"],
        "cve": "CVE-2021-41773",
        "severity": "critical",
        "summary": "Potential path traversal vulnerable Apache version detected",
        "recommendation": "Upgrade Apache HTTPD immediately to patched releases (2.4.51+).",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "service": "Apache",
        "version_prefixes": ["2.4.50"],
        "cve": "CVE-2021-42013",
        "severity": "critical",
        "summary": "Potential path traversal / RCE vulnerable Apache version detected",
        "recommendation": "Upgrade Apache HTTPD immediately to patched releases (2.4.51+).",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "service": "nginx",
        "version_prefixes": ["1.10", "1.12"],
        "cve": "CVE-2017-7529",
        "severity": "moderate",
        "summary": "Potential vulnerable nginx version detected",
        "recommendation": "Upgrade nginx to the latest stable version.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "service": "nginx",
        "version_prefixes": ["1.16", "1.18"],
        "cve": "CVE-2021-23017",
        "severity": "moderate",
        "summary": "Potential nginx resolver vulnerability exposure",
        "recommendation": "Patch nginx to a currently supported stable release.",
    },
    {
        "service": "OpenSSH",
        "version_prefixes": ["6.", "7.0", "7.1", "7.2"],
        "cve": "Multiple historical OpenSSH CVEs",
        "severity": "high",
        "summary": "Outdated OpenSSH version detected",
        "recommendation": "Upgrade OpenSSH to a supported release and rotate affected credentials.",
    },
]


@dataclass
class NetworkFindingResult:
    issue_type: str
    severity: str
    summary: str
    recommendation: str
    evidence: str
    host: str
    port: int | None
    protocol: str
    evidence_data: dict | None = None
    confidence_score: int | None = None
    rationale: str | None = None


@dataclass
class ScanMetrics:
    hosts_scanned: int
    hosts_alive: int
    open_ports: int
    ports_checked: int
    environment_summary: Dict[str, int]
    os_summary: Dict[str, int]


@dataclass
class ScanResult:
    findings: List[NetworkFindingResult]
    metrics: ScanMetrics


def scan_asset(target: str, scope: str) -> ScanResult:
    return _scan_with_profile(target, scope, PORTS_TO_CHECK, check_https_redirect=False, check_api_docs=False)


def scan_web_target(target: str, scope: str) -> ScanResult:
    return _scan_with_profile(target, scope, WEB_PORTS, check_https_redirect=True, check_api_docs=False)


def scan_api_target(target: str, scope: str) -> ScanResult:
    return _scan_with_profile(target, scope, API_PORTS, check_https_redirect=True, check_api_docs=True)


def scan_infra_target(target: str, scope: str) -> ScanResult:
    return _scan_with_profile(target, scope, INFRA_PORTS, check_https_redirect=False, check_api_docs=False)


def _scan_with_profile(
    target: str,
    scope: str,
    ports: list[int],
    check_https_redirect: bool,
    check_api_docs: bool,
) -> ScanResult:
    if not target:
        return ScanResult(findings=[], metrics=_empty_metrics())
    scope = scope or ""
    hosts = list(_resolve_targets(target, scope))
    if not hosts:
        return ScanResult(findings=[], metrics=_empty_metrics())

    findings: List[NetworkFindingResult] = []
    connection_budget = MAX_CONNECTIONS
    hosts_alive = 0
    open_ports_total = 0
    environment_summary: Dict[str, int] = {}
    os_summary: Dict[str, int] = {}
    ports_checked = 0
    host_ports: dict[str, list[int]] = {}
    host_env: dict[str, str] = {}
    zone_candidates = _zone_candidates_from_target(target)

    for host in hosts:
        environment = _infer_environment(host)
        environment_summary[environment] = environment_summary.get(environment, 0) + 1
        host_env[host] = environment
        open_ports: List[int] = []
        service_info: dict[int, dict] = {}
        for port in ports:
            if connection_budget <= 0:
                break
            connection_budget -= 1
            ports_checked += 1
            if _tcp_connect(host, port):
                open_ports.append(port)
                info = _identify_service(host, port)
                info["environment"] = environment
                info["os_guess"] = _infer_os_guess(info, port)
                service_info[port] = info
            time.sleep(SLEEP_BETWEEN_CONNECTIONS)

        if not open_ports:
            continue

        hosts_alive += 1
        open_ports_total += len(open_ports)
        host_ports[host] = list(open_ports)

        host_os = _summarize_os(service_info)
        if host_os:
            os_summary[host_os] = os_summary.get(host_os, 0) + 1

        findings.extend(_evaluate_open_ports(host, open_ports, service_info))

        for port in open_ports:
            if port in TLS_PORTS:
                findings.extend(_check_tls(host, port, service_info.get(port, {})))
            if port in HTTP_PORTS:
                findings.extend(_check_http_headers(host, port, service_info.get(port, {})))
                if check_https_redirect and port not in TLS_PORTS:
                    findings.extend(_check_https_redirect(host, port, service_info.get(port, {})))
                if check_api_docs:
                    findings.extend(_check_api_docs(host, port, service_info.get(port, {})))
                if ENABLE_DEFAULT_CREDENTIAL_CHECKS and port in ADMIN_PORTS:
                    findings.extend(_check_http_default_credentials(host, port, service_info.get(port, {})))

            # Deeper, safe checks (no brute-force): DNS AXFR, no-auth exposures, VPN/SMB exposure signals.
            if port == DNS_PORT:
                findings.extend(_check_dns_zone_transfer(host, service_info.get(port, {}), zone_candidates))
                findings.extend(_check_dns_open_resolver(host, service_info.get(port, {})))
            if port in SMB_PORTS:
                findings.extend(_check_smb_exposure(host, port, service_info.get(port, {})))
            if port in VPN_PORTS:
                findings.extend(_check_vpn_exposure(host, port, service_info.get(port, {})))
            if port == 6379:
                findings.extend(_check_redis_noauth(host, port, service_info.get(port, {})))
            if port == 9200:
                findings.extend(_check_elasticsearch_noauth(host, port, service_info.get(port, {})))

            vuln_findings = _correlate_vulnerabilities(host, port, service_info.get(port, {}))
            findings.extend(vuln_findings)

    # Pivot-path and segmentation heuristics across the scanned host set (deeper mapping).
    findings.extend(_pivot_path_findings(host_ports, host_env))

    metrics = ScanMetrics(
        hosts_scanned=len(hosts),
        hosts_alive=hosts_alive,
        open_ports=open_ports_total,
        ports_checked=ports_checked,
        environment_summary=environment_summary,
        os_summary=os_summary,
    )
    return ScanResult(findings=findings, metrics=metrics)


def _resolve_targets(target: str, scope: str) -> Iterator[str]:
    target = target.strip()
    if not target:
        return iter(())

    if "*" in target:
        raise ValueError("Wildcard targets are not permitted for network scans.")

    if scope == "ip_cidr":
        if not _looks_like_cidr(target):
            host = _extract_host(target)
            if host:
                return iter([host])
            raise ValueError("Scope ip_cidr requires a valid CIDR or IP target.")
        network = ipaddress.ip_network(target, strict=False)
        if network.prefixlen == 0:
            raise ValueError("Broad CIDR ranges are not permitted.")
        if isinstance(network, ipaddress.IPv4Network) and network.prefixlen < MIN_IPV4_PREFIX:
            raise ValueError(f"CIDR range too broad. Use /{MIN_IPV4_PREFIX} or narrower.")
        if isinstance(network, ipaddress.IPv6Network) and network.prefixlen < MIN_IPV6_PREFIX:
            raise ValueError(f"IPv6 CIDR range too broad. Use /{MIN_IPV6_PREFIX} or narrower.")
        if network.num_addresses > MAX_CIDR_ADDRESSES:
            raise ValueError(
                f"CIDR range exceeds safe scan limits (max {MAX_CIDR_ADDRESSES} addresses)."
            )
        hosts = list(network.hosts())[:MAX_HOSTS]
        return (str(host) for host in hosts)

    if _looks_like_cidr(target):
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > MAX_CIDR_ADDRESSES:
            raise ValueError(
                f"CIDR range exceeds safe scan limits (max {MAX_CIDR_ADDRESSES} addresses)."
            )
        hosts = list(network.hosts())[:MAX_HOSTS]
        return (str(host) for host in hosts)

    host = _extract_host(target)
    if not host:
        return iter(())
    return iter([host])


def _extract_host(target: str) -> str:
    # Docker note: within containers, "localhost" and 127.0.0.1 refer to the container,
    # not the host machine. For local dev on Docker Desktop, rewrite to host.docker.internal
    # unless explicitly disabled.
    def _docker_rewrite(hostname: str) -> str:
        if not hostname:
            return ""
        if hostname not in {"localhost", "127.0.0.1"}:
            return hostname
        if os.getenv("AEGIS_DOCKER_LOCALHOST_REWRITE", "1").strip() in {"0", "false", "FALSE", "no", "NO"}:
            return hostname
        try:
            if not os.path.exists("/.dockerenv"):
                return hostname
        except Exception:
            return hostname
        alias = (os.getenv("AEGIS_DOCKER_HOST_ALIAS", "host.docker.internal") or "").strip()
        return alias or hostname

    if "://" in target:
        parsed = urlparse(target)
        return _docker_rewrite(parsed.hostname or "")
    if "/" in target:
        target = target.split("/")[0]
    if ":" in target:
        base, suffix = target.rsplit(":", 1)
        if suffix.isdigit():
            return _docker_rewrite(base)
    return target


def _looks_like_cidr(target: str) -> bool:
    if "://" in target:
        return False
    target = target.strip()
    return bool(re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", target))


def _tcp_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def _evaluate_open_ports(host: str, open_ports: List[int], service_info: dict[int, dict]) -> List[NetworkFindingResult]:
    findings: List[NetworkFindingResult] = []
    sensitive_open = [port for port in open_ports if port in SENSITIVE_PORTS]

    for port in open_ports:
        if port in ADMIN_PORTS or port in SENSITIVE_PORTS:
            info = service_info.get(port, {})
            service = info.get("service") or SERVICE_PORT_MAP.get(port, "Service")
            version = info.get("version")
            summary = f"Sensitive service exposed: {service} on port {port}"
            if version:
                summary = f"{summary} ({version})"
            evidence = f"TCP connect succeeded on {host}:{port}."
            base_evidence = _base_evidence(host, port, info)
            findings.append(
                NetworkFindingResult(
                    issue_type="exposed_service",
                    severity="high",
                    summary=summary,
                    recommendation="Restrict access, enforce MFA, and limit exposure to trusted networks.",
                    evidence=evidence,
                    host=host,
                    port=port,
                    protocol="tcp",
                    evidence_data={
                        **base_evidence,
                        "service": service,
                        "version": version,
                        "protocol": "tcp",
                    },
                    confidence_score=90,
                    rationale="TCP connect confirmed the service is reachable on the exposed interface.",
                )
            )

    if len(sensitive_open) >= 3:
        base_evidence = _base_evidence(host, None, {})
        findings.append(
            NetworkFindingResult(
                issue_type="segmentation_risk",
                severity="moderate",
                summary="Multiple sensitive services exposed on the same host",
                recommendation="Review segmentation policies and restrict management ports.",
                evidence=f"Sensitive ports open: {', '.join(str(p) for p in sensitive_open)}.",
                host=host,
                port=None,
                protocol="tcp",
                evidence_data={**base_evidence, "ports": sensitive_open, "protocol": "tcp"},
                confidence_score=70,
                rationale="Multiple sensitive ports were reachable on the same host.",
            )
        )

    return findings


def _identify_service(host: str, port: int) -> dict:
    info = {"host": host, "port": port, "service": SERVICE_PORT_MAP.get(port, "Service")}
    if port == 22:
        banner = _read_banner(host, port)
        if banner:
            info["banner"] = banner
            info["service"] = "OpenSSH" if "OpenSSH" in banner else info["service"]
            info["version"] = _extract_version(info["service"], banner)
        return info

    if port in HTTP_PORTS:
        metadata = _fetch_http_metadata(host, port)
        server = metadata.get("server")
        if server:
            info["server_header"] = server
            info["service"] = server.split("/")[0]
            info["version"] = _extract_version(info["service"], server)
        info["status"] = metadata.get("status")
        info["encryption"] = "TLS" if port in TLS_PORTS else "Plaintext"
        return info

    return info


def _read_banner(host: str, port: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(REQUEST_TIMEOUT)
            data = sock.recv(200)
            return data.decode("utf-8", errors="ignore").strip()
    except OSError:
        return ""


def _extract_version(service: str, banner: str) -> str | None:
    import re

    if not banner:
        return None
    patterns = [
        r"OpenSSH[_-]([0-9]+(?:\\.[0-9]+)?)",
        r"Apache/?([0-9]+(?:\\.[0-9]+)?)",
        r"nginx/?([0-9]+(?:\\.[0-9]+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)
    if "/" in banner:
        parts = banner.split("/")
        if len(parts) > 1:
            return parts[1].split(" ")[0]
    return None


def _check_tls(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    findings: List[NetworkFindingResult] = []
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                version = tls_sock.version() or ""
    except OSError:
        return findings

    if version in {"TLSv1", "TLSv1.1"}:
        base_evidence = _base_evidence(host, port, info)
        findings.append(
            NetworkFindingResult(
                issue_type="misconfiguration",
                severity="moderate",
                summary=f"Weak TLS version enabled ({version})",
                recommendation="Disable legacy TLS versions and enforce TLS 1.2+.",
                evidence=f"Negotiated {version} on {host}:{port}.",
                host=host,
                port=port,
                protocol="tls",
                evidence_data={**base_evidence, "tls_version": version, "protocol": "tls"},
                confidence_score=80,
                rationale="TLS handshake succeeded with a deprecated protocol version.",
            )
        )
    return findings


def _fetch_http_metadata(host: str, port: int) -> dict:
    scheme = "https" if port in TLS_PORTS else "http"
    context = None
    if scheme == "https":
        context = ssl._create_unverified_context()

    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port=port, timeout=REQUEST_TIMEOUT, context=context)
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=REQUEST_TIMEOUT)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        headers = {k: v for k, v in response.getheaders()}
        status = response.status
        conn.close()
    except Exception:
        return {}

    return {"headers": headers, "status": status, "server": headers.get("Server"), "scheme": scheme}


def _check_http_headers(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    findings: List[NetworkFindingResult] = []
    metadata = _fetch_http_metadata(host, port)
    headers = metadata.get("headers") or {}
    missing = [header for header in SECURITY_HEADERS if header not in headers]
    if missing:
        base_evidence = _base_evidence(host, port, info)
        findings.append(
            NetworkFindingResult(
                issue_type="misconfiguration",
                severity="low",
                summary="Missing recommended security headers",
                recommendation="Add security headers to reduce exposure to common web attacks.",
                evidence=f"Missing headers: {', '.join(missing)}.",
                host=host,
                port=port,
                protocol=metadata.get("scheme", "http"),
                evidence_data={
                    **base_evidence,
                    "missing_headers": missing,
                    "protocol": metadata.get("scheme", "http"),
                },
                confidence_score=60,
                rationale="HTTP response headers did not include common security hardening controls.",
            )
        )
    return findings


def _check_https_redirect(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    findings: List[NetworkFindingResult] = []
    try:
        conn = http.client.HTTPConnection(host, port=port, timeout=REQUEST_TIMEOUT)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        location = dict(response.getheaders()).get("Location", "")
        conn.close()
    except Exception:
        return findings

    if location and location.startswith("https://"):
        return findings

    base_evidence = _base_evidence(host, port, info)
    findings.append(
        NetworkFindingResult(
            issue_type="misconfiguration",
            severity="low",
            summary="HTTP service does not redirect to HTTPS",
            recommendation="Enforce HTTPS redirects to protect data in transit.",
            evidence=f"No HTTPS redirect detected on {host}:{port}.",
            host=host,
            port=port,
            protocol="http",
            evidence_data={**base_evidence, "protocol": "http"},
            confidence_score=55,
            rationale="HTTP response did not include an HTTPS redirect.",
        )
    )
    return findings


def _check_api_docs(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    findings: List[NetworkFindingResult] = []
    scheme = "https" if port in TLS_PORTS else "http"
    context = ssl._create_unverified_context() if scheme == "https" else None

    for path in API_DOC_PATHS:
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port=port, timeout=REQUEST_TIMEOUT, context=context)
            else:
                conn = http.client.HTTPConnection(host, port=port, timeout=REQUEST_TIMEOUT)
            conn.request("GET", path)
            response = conn.getresponse()
            status = response.status
            conn.close()
        except Exception:
            continue
        if status and 200 <= status < 300:
            base_evidence = _base_evidence(host, port, info)
            findings.append(
                NetworkFindingResult(
                    issue_type="misconfiguration",
                    severity="moderate",
                    summary="Public API documentation exposed",
                    recommendation="Restrict API documentation to trusted networks or require authentication.",
                    evidence=f"Accessible endpoint: {scheme}://{host}:{port}{path}",
                    host=host,
                    port=port,
                    protocol=scheme,
                    evidence_data={**base_evidence, "protocol": scheme, "path": path},
                    confidence_score=75,
                    rationale="Unauthenticated API documentation was accessible over HTTP.",
                )
            )
    return findings


def _zone_candidates_from_target(target: str) -> list[str]:
    """
    Best-effort candidates for DNS zone transfer checks.
    We avoid guessing TLD rules; we simply try:
    - full hostname (if any)
    - parent domain (drop first label)
    """
    host = _extract_host(target)
    if not host:
        return []
    # If it's an IP/CIDR, there's no zone name to test.
    try:
        ipaddress.ip_address(host)
        return []
    except ValueError:
        pass
    labels = [p for p in host.split(".") if p]
    if len(labels) < 2:
        return []
    candidates = [host]
    if len(labels) >= 3:
        candidates.append(".".join(labels[1:]))
    # Deduplicate while preserving order.
    out: list[str] = []
    seen: set[str] = set()
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out[:2]


def _check_dns_zone_transfer(host: str, info: dict, zone_candidates: list[str]) -> List[NetworkFindingResult]:
    """
    DNS zone transfer check (AXFR) against in-scope DNS servers.
    Safe/non-destructive: we stop after a small number of messages.
    """
    if not zone_candidates:
        return []
    try:
        import dns.query  # type: ignore
        import dns.zone  # noqa: F401
        import dns.exception  # noqa: F401
    except Exception:
        return []

    findings: List[NetworkFindingResult] = []
    environment = info.get("environment") or _infer_environment(host)
    base_evidence = _base_evidence(host, DNS_PORT, info)

    for zone in zone_candidates:
        try:
            xfr = dns.query.xfr(where=host, zone=zone, timeout=REQUEST_TIMEOUT, lifetime=REQUEST_TIMEOUT * 2)  # type: ignore
            msg_count = 0
            rr_count = 0
            for message in xfr:
                msg_count += 1
                for rrset in getattr(message, "answer", []) or []:
                    try:
                        rr_count += len(rrset)
                    except Exception:
                        rr_count += 1
                if msg_count >= 3 or rr_count >= 20:
                    break
            if rr_count <= 0:
                continue
        except Exception:
            continue

        severity = "critical" if environment == "external" else "high"
        findings.append(
            NetworkFindingResult(
                issue_type="misconfiguration",
                severity=severity,
                summary="DNS zone transfer appears permitted (AXFR)",
                recommendation="Disable AXFR to untrusted hosts; restrict transfers to authorized secondary DNS servers only.",
                evidence=f"AXFR returned records for zone candidate: {zone}",
                host=host,
                port=DNS_PORT,
                protocol="dns",
                evidence_data={**base_evidence, "protocol": "dns", "zone": zone, "axfr_records_sampled": rr_count},
                confidence_score=75,
                rationale="AXFR response indicates the server may allow zone transfers, enabling full DNS enumeration.",
            )
        )
        break

    return findings


def _check_dns_open_resolver(host: str, info: dict) -> List[NetworkFindingResult]:
    """
    Detect open DNS recursion ("open resolver") behavior.
    Safe/non-destructive: single query for a benign public domain.
    """
    try:
        import dns.message  # type: ignore
        import dns.query  # type: ignore
        import dns.rdatatype  # type: ignore
        import dns.flags  # type: ignore
    except Exception:
        return []

    findings: List[NetworkFindingResult] = []
    base_evidence = _base_evidence(host, DNS_PORT, info)
    environment = info.get("environment") or _infer_environment(host)

    try:
        # Query a benign, stable name. RD=1 tests recursion behavior.
        q = dns.message.make_query("example.com.", dns.rdatatype.A)  # type: ignore
        q.flags |= dns.flags.RD  # type: ignore
        resp = dns.query.udp(q, where=host, timeout=REQUEST_TIMEOUT)  # type: ignore
    except Exception:
        return []

    # RA + an answer strongly suggests the server performed recursion.
    has_ra = bool(resp.flags & dns.flags.RA)  # type: ignore
    answer_count = 0
    try:
        answer_count = sum(len(rrset) for rrset in (resp.answer or []))
    except Exception:
        answer_count = len(resp.answer or [])

    if not has_ra or answer_count <= 0:
        return []

    severity = "high" if environment == "external" else "moderate"
    findings.append(
        NetworkFindingResult(
            issue_type="misconfiguration",
            severity=severity,
            summary="DNS server appears to allow recursive queries (open resolver signal)",
            recommendation="Disable recursion for untrusted networks and restrict resolver access to internal clients only.",
            evidence=f"Recursive response observed (RA=1) with {answer_count} answer records.",
            host=host,
            port=DNS_PORT,
            protocol="dns",
            evidence_data={**base_evidence, "protocol": "dns", "recursion_available": True, "answer_records": answer_count},
            confidence_score=70,
            rationale="An open resolver can be abused for DNS amplification and can leak internal resolution behavior.",
        )
    )
    return findings


def _check_redis_noauth(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    """
    Redis default/no-auth exposure check.
    Safe: send PING and see if it responds without AUTH.
    """
    findings: List[NetworkFindingResult] = []
    base_evidence = _base_evidence(host, port, info)
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(REQUEST_TIMEOUT)
            sock.sendall(b"PING\r\n")
            data = sock.recv(64)
    except OSError:
        return findings
    if b"PONG" not in data:
        return findings
    environment = info.get("environment") or _infer_environment(host)
    severity = "critical" if environment == "external" else "high"
    findings.append(
        NetworkFindingResult(
            issue_type="exposed_service",
            severity=severity,
            summary="Redis service responds without authentication (no-auth exposure)",
            recommendation="Enable Redis AUTH, bind to private interfaces, and restrict access via firewall/VPC rules.",
            evidence=f"PING returned PONG from {host}:{port} without authentication.",
            host=host,
            port=port,
            protocol="tcp",
            evidence_data={**base_evidence, "service": "Redis", "no_auth": True, "protocol": "tcp"},
            confidence_score=85,
            rationale="Unauthenticated Redis access can lead to data exposure and remote command execution patterns depending on deployment.",
        )
    )
    return findings


def _check_elasticsearch_noauth(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    """
    Elasticsearch exposure check (unauthenticated cluster metadata).
    Safe: read-only HTTP GET.
    """
    findings: List[NetworkFindingResult] = []
    base_evidence = _base_evidence(host, port, info)
    try:
        conn = http.client.HTTPConnection(host, port=port, timeout=REQUEST_TIMEOUT)
        conn.request("GET", "/_cluster/health")
        response = conn.getresponse()
        status = response.status
        body = response.read(256).decode("utf-8", errors="ignore")
        conn.close()
    except Exception:
        return findings

    if status in {401, 403}:
        return findings
    if status and 200 <= status < 300 and ("cluster_name" in body or "status" in body):
        environment = info.get("environment") or _infer_environment(host)
        severity = "high" if environment == "external" else "moderate"
        findings.append(
            NetworkFindingResult(
                issue_type="exposed_service",
                severity=severity,
                summary="Elasticsearch endpoint appears accessible without authentication",
                recommendation="Require authentication, restrict network exposure, and enable TLS for Elasticsearch APIs.",
                evidence=f"GET /_cluster/health returned HTTP {status} without authentication challenge.",
                host=host,
                port=port,
                protocol="http",
                evidence_data={**base_evidence, "service": "Elasticsearch", "path": "/_cluster/health", "status": status, "protocol": "http"},
                confidence_score=70,
                rationale="Unauthenticated Elasticsearch endpoints can leak sensitive data and cluster metadata.",
            )
        )
    return findings


def _check_http_default_credentials(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    """
    Optional default-credential validation for HTTP Basic Auth prompts.
    Disabled by default. Enable via NETWORK_SCAN_ENABLE_DEFAULT_CREDS=1.
    """
    findings: List[NetworkFindingResult] = []
    scheme = "https" if port in TLS_PORTS else "http"
    context = ssl._create_unverified_context() if scheme == "https" else None
    base_evidence = _base_evidence(host, port, info)

    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port=port, timeout=REQUEST_TIMEOUT, context=context)
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=REQUEST_TIMEOUT)
        conn.request("GET", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        resp.read(128)
        conn.close()
    except Exception:
        return findings

    www_auth = headers.get("www-authenticate", "")
    if status not in {401, 403} or "basic" not in (www_auth or "").lower():
        return findings

    import base64

    candidates = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
    ]

    for username, password in candidates:
        try:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            hdrs = {"Authorization": f"Basic {token}", "User-Agent": "AegisScanner/1.0"}
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port=port, timeout=REQUEST_TIMEOUT, context=context)
            else:
                conn = http.client.HTTPConnection(host, port=port, timeout=REQUEST_TIMEOUT)
            conn.request("GET", "/", headers=hdrs)
            r = conn.getresponse()
            r_status = r.status
            r.read(128)
            conn.close()
        except Exception:
            continue
        if r_status and 200 <= r_status < 300:
            environment = info.get("environment") or _infer_environment(host)
            severity = "critical" if environment == "external" else "high"
            findings.append(
                NetworkFindingResult(
                    issue_type="misconfiguration",
                    severity=severity,
                    summary="Default credentials accepted on HTTP Basic Auth endpoint",
                    recommendation="Disable default credentials, enforce MFA, and restrict admin endpoints to trusted networks.",
                    evidence=f"HTTP Basic Auth accepted username '{username}' on {scheme}://{host}:{port}/",
                    host=host,
                    port=port,
                    protocol=scheme,
                    evidence_data={**base_evidence, "protocol": scheme, "default_creds": True, "username": username, "path": "/"},
                    confidence_score=80,
                    rationale="An admin endpoint accepted a common default credential pair; this typically enables immediate unauthorized access.",
                )
            )
            break

    return findings


def _smb1_negotiate_packet() -> bytes:
    """
    Minimal SMB1 negotiate request with NT LM 0.12 dialect.
    This is used only to detect whether SMBv1 is accepted (legacy risk signal).
    """
    smb = bytearray()
    # SMB Header (32 bytes)
    smb += b"\xFFSMB"          # Protocol
    smb += b"\x72"             # SMB_COM_NEGOTIATE
    smb += b"\x00\x00\x00\x00"  # NT Status
    smb += b"\x18"             # Flags
    smb += b"\x01\x28"         # Flags2
    smb += b"\x00\x00"         # PID high
    smb += b"\x00" * 8         # Signature
    smb += b"\x00\x00"         # Reserved
    smb += b"\x00\x00"         # TID
    smb += b"\x2F\x4B"         # PID (arbitrary)
    smb += b"\x00\x00"         # UID
    smb += b"\xC5\x5E"         # MID (arbitrary)
    # Body
    smb += b"\x00"             # WordCount
    dialect = b"NT LM 0.12"
    dialects = b"\x02" + dialect + b"\x00"
    smb += len(dialects).to_bytes(2, "little")  # ByteCount
    smb += dialects
    # NetBIOS Session Service header
    length = len(smb)
    nb = b"\x00" + length.to_bytes(3, "big")
    return nb + bytes(smb)


def _check_smb_v1(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    """
    Safe SMBv1 support signal: attempt SMB1 negotiate and look for SMB1 header in response.
    We do not authenticate or enumerate shares.
    """
    findings: List[NetworkFindingResult] = []
    base_evidence = _base_evidence(host, port, info)
    environment = info.get("environment") or _infer_environment(host)

    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(REQUEST_TIMEOUT)
            sock.sendall(_smb1_negotiate_packet())
            data = sock.recv(256)
    except OSError:
        return findings

    # SMB1 header: FF 'SMB' in the payload. SMB2/3 would typically contain FE 'SMB'.
    if b"\xFFSMB" not in data:
        return findings

    severity = "high" if environment == "external" else "moderate"
    findings.append(
        NetworkFindingResult(
            issue_type="misconfiguration",
            severity=severity,
            summary="SMBv1 appears to be supported (legacy protocol)",
            recommendation="Disable SMBv1 and enforce SMBv2/SMBv3 with signing where applicable.",
            evidence=f"SMB1 negotiate response observed on {host}:{port}.",
            host=host,
            port=port,
            protocol="tcp",
            evidence_data={**base_evidence, "service": "SMB", "smbv1_supported": True, "protocol": "tcp"},
            confidence_score=65,
            rationale="SMBv1 is a legacy protocol associated with high-risk exploitation paths and should be disabled.",
        )
    )
    return findings


def _check_smb_exposure(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    """
    SMB exposure signal. We do not attempt authentication or share enumeration here.
    """
    findings: List[NetworkFindingResult] = []
    environment = info.get("environment") or _infer_environment(host)
    severity = "critical" if environment == "external" else "high"
    base_evidence = _base_evidence(host, port, info)
    findings.append(
        NetworkFindingResult(
            issue_type="exposed_service",
            severity=severity,
            summary=f"SMB service reachable on port {port}",
            recommendation="Do not expose SMB to the internet; restrict to internal subnets and enforce SMB signing where applicable.",
            evidence=f"TCP connect succeeded on {host}:{port} (SMB).",
            host=host,
            port=port,
            protocol="tcp",
            evidence_data={**base_evidence, "service": "SMB", "protocol": "tcp"},
            confidence_score=80,
            rationale="SMB exposure increases risk of credential relay and remote exploitation depending on patch level and configuration.",
        )
    )
    # Additional legacy-protocol signal (safe negotiate probe).
    findings.extend(_check_smb_v1(host, port, info))
    return findings


def _check_vpn_exposure(host: str, port: int, info: dict) -> List[NetworkFindingResult]:
    """
    VPN exposure/misconfiguration signal. We do not attempt authentication.
    """
    findings: List[NetworkFindingResult] = []
    environment = info.get("environment") or _infer_environment(host)
    base_evidence = _base_evidence(host, port, info)
    service = SERVICE_PORT_MAP.get(port, "VPN")

    # PPTP is considered weak; elevate severity.
    if port == 1723:
        severity = "critical" if environment == "external" else "high"
        findings.append(
            NetworkFindingResult(
                issue_type="misconfiguration",
                severity=severity,
                summary="PPTP VPN service detected (legacy/weak protocol)",
                recommendation="Disable PPTP and migrate to modern VPN protocols (IPsec/IKEv2, WireGuard, OpenVPN) with MFA.",
                evidence=f"Port {port} reachable on {host} ({service}).",
                host=host,
                port=port,
                protocol="tcp",
                evidence_data={**base_evidence, "service": service, "protocol": "tcp"},
                confidence_score=65,
                rationale="PPTP is widely considered insecure and increases risk of credential compromise.",
            )
        )
        return findings

    severity = "high" if environment == "external" else "moderate"
    findings.append(
        NetworkFindingResult(
            issue_type="exposed_service",
            severity=severity,
            summary=f"VPN-related service exposed: {service} on port {port}",
            recommendation="Restrict VPN exposure, enforce MFA, disable legacy ciphers, and monitor authentication logs.",
            evidence=f"Port {port} reachable on {host} ({service}).",
            host=host,
            port=port,
            protocol="tcp",
            evidence_data={**base_evidence, "service": service, "protocol": "tcp"},
            confidence_score=60,
            rationale="VPN endpoints are high-value targets; exposure should be tightly controlled and monitored.",
        )
    )
    return findings


def _pivot_path_findings(host_ports: dict[str, list[int]], host_env: dict[str, str]) -> List[NetworkFindingResult]:
    """
    Heuristic pivot-path mapping:
    - Identify hosts that expose admin access + data services.
    - Identify widespread admin port exposure within internal ranges.
    """
    findings: List[NetworkFindingResult] = []
    if not host_ports:
        return findings

    admin_ports = {22, 3389}
    data_ports = {3306, 5432, 6379, 9200}
    web_ports = {80, 443, 8080, 8443}

    pivot_hosts: list[str] = []
    admin_hosts_internal: list[str] = []
    for host, ports in host_ports.items():
        env = host_env.get(host, _infer_environment(host))
        has_admin = any(p in admin_ports for p in ports)
        has_data = any(p in data_ports for p in ports)
        has_web = any(p in web_ports for p in ports)

        if env == "internal" and has_admin:
            admin_hosts_internal.append(host)
        if has_admin and (has_data or has_web):
            pivot_hosts.append(host)

    if pivot_hosts:
        sample = ", ".join(pivot_hosts[:4])
        findings.append(
            NetworkFindingResult(
                issue_type="segmentation_risk",
                severity="moderate",
                summary="Potential pivot hosts detected (admin access + application/data services)",
                recommendation="Segment admin interfaces from application/data tiers; restrict management access and enforce least-privilege network policies.",
                evidence=f"Hosts with mixed exposure: {sample}{' (+more)' if len(pivot_hosts) > 4 else ''}",
                host="scan_scope",
                port=None,
                protocol="tcp",
                evidence_data={"hosts": pivot_hosts[:10], "count": len(pivot_hosts), "protocol": "tcp"},
                confidence_score=55,
                rationale="Hosts exposing both admin access and application/data services can act as pivot points for lateral movement.",
            )
        )

    if len(admin_hosts_internal) >= 5:
        sample = ", ".join(admin_hosts_internal[:6])
        findings.append(
            NetworkFindingResult(
                issue_type="segmentation_risk",
                severity="moderate",
                summary="Administrative access broadly reachable within internal network",
                recommendation="Reduce admin port exposure, require bastion/VPN access, and apply host-based firewall policies.",
                evidence=f"Internal hosts with SSH/RDP reachable: {sample}{' (+more)' if len(admin_hosts_internal) > 6 else ''}",
                host="scan_scope",
                port=None,
                protocol="tcp",
                evidence_data={"hosts": admin_hosts_internal[:12], "count": len(admin_hosts_internal), "protocol": "tcp"},
                confidence_score=50,
                rationale="Widespread admin port reachability increases lateral movement and credential abuse risk.",
            )
        )

    return findings


def _correlate_vulnerabilities(host: str, port: int, service_info: dict) -> List[NetworkFindingResult]:
    service = service_info.get("service")
    version = service_info.get("version")
    if not service or not version:
        return []
    findings: List[NetworkFindingResult] = []
    base_evidence = _base_evidence(host, port, service_info)
    for signature in VULN_SIGNATURES:
        if signature["service"].lower() != service.lower():
            continue
        for prefix in signature["version_prefixes"]:
            if version.startswith(prefix):
                summary = f"{signature['summary']} ({service} {version})"
                findings.append(
                    NetworkFindingResult(
                        issue_type="misconfiguration",
                        severity=signature["severity"],
                        summary=summary,
                        recommendation=signature["recommendation"],
                        evidence=f"Service banner indicates {service} {version}.",
                        host=host,
                        port=port,
                        protocol=service_info.get("protocol", "tcp"),
                        evidence_data={
                            **base_evidence,
                            "service": service,
                            "version": version,
                            "cve": signature.get("cve"),
                            "cvss_vector": signature.get("cvss_vector") or "",
                        },
                        confidence_score=70,
                        rationale="Service banner matched a known vulnerable version signature.",
                    )
                )
                break
    return findings


def _infer_environment(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private:
            return "internal"
        return "external"
    except ValueError:
        cloud_markers = ("amazonaws.com", "cloudapp.azure.com", "azure.com", "googleusercontent.com", "digitaloceanspaces.com")
        if any(marker in host for marker in cloud_markers):
            return "cloud"
        return "external"


def _infer_os_guess(info: dict, port: int) -> str | None:
    banner = (info.get("banner") or "") + " " + (info.get("server_header") or "")
    banner_lower = banner.lower()
    if port == 3389:
        return "Windows"
    if "ubuntu" in banner_lower:
        return "Ubuntu"
    if "debian" in banner_lower:
        return "Debian"
    if "centos" in banner_lower:
        return "CentOS"
    if "red hat" in banner_lower or "rhel" in banner_lower:
        return "RHEL"
    if "windows" in banner_lower or "microsoft-iis" in banner_lower:
        return "Windows"
    if "openssh" in banner_lower:
        return "Linux/Unix"
    return None


def _summarize_os(service_info: dict[int, dict]) -> str | None:
    for info in service_info.values():
        os_guess = info.get("os_guess")
        if os_guess:
            return os_guess
    return None


def _base_evidence(host: str, port: int | None, info: dict) -> dict:
    return {
        "host": host,
        "port": port,
        "service": info.get("service"),
        "version": info.get("version"),
        "environment": info.get("environment"),
        "os_guess": info.get("os_guess"),
    }


def _empty_metrics() -> ScanMetrics:
    return ScanMetrics(
        hosts_scanned=0,
        hosts_alive=0,
        open_ports=0,
        ports_checked=0,
        environment_summary={},
        os_summary={},
    )
