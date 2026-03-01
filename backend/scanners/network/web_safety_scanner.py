import os
import socket
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen


REQUEST_TIMEOUT = 5
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]
SQL_ERROR_MARKERS = [
    "sql syntax",
    "you have an error in your sql syntax",
    "unterminated quoted string",
    "sqlite error",
    "psycopg2.errors",
    "mysql server version",
]


@dataclass
class WebFinding:
    issue_type: str
    severity: str
    summary: str
    recommendation: str
    host: str
    port: int | None
    protocol: str
    evidence_data: dict | None = None
    confidence_score: int | None = None
    rationale: str | None = None


@dataclass
class WebMetrics:
    hosts_scanned: int
    hosts_alive: int
    open_ports: int
    ports_checked: int
    environment_summary: dict
    os_summary: dict


@dataclass
class WebScanResult:
    findings: List[WebFinding]
    metrics: WebMetrics


def scan_web_security(target: str) -> WebScanResult:
    if not target:
        return WebScanResult(findings=[], metrics=_empty_metrics())

    parsed = _normalize_target(target)
    if not parsed:
        return WebScanResult(findings=[], metrics=_empty_metrics())

    host = parsed.hostname or target
    protocol = parsed.scheme or "http"
    port = parsed.port or (443 if protocol == "https" else 80)

    findings: List[WebFinding] = []

    response_headers, body = _fetch_headers(parsed.geturl())
    if response_headers is None:
        return WebScanResult(findings=[], metrics=_empty_metrics())

    missing_headers = [header for header in SECURITY_HEADERS if header.lower() not in response_headers]
    if missing_headers:
        findings.append(
            WebFinding(
                issue_type="misconfiguration",
                severity="low",
                summary="Missing recommended security headers",
                recommendation="Add baseline HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).",
                host=host,
                port=port,
                protocol=protocol,
                evidence_data={"missing_headers": missing_headers},
                confidence_score=60,
                rationale="HTTP response headers did not include common security hardening controls.",
            )
        )

    server_header = response_headers.get("server", "")
    if server_header and any(char.isdigit() for char in server_header):
        findings.append(
            WebFinding(
                issue_type="misconfiguration",
                severity="low",
                summary="Server version disclosure in response header",
                recommendation="Suppress detailed server version banners in HTTP responses.",
                host=host,
                port=port,
                protocol=protocol,
                evidence_data={"server": server_header},
                confidence_score=70,
                rationale="Version-bearing server header can improve attacker reconnaissance.",
            )
        )

    cors_origin = response_headers.get("access-control-allow-origin", "")
    cors_creds = response_headers.get("access-control-allow-credentials", "")
    if cors_origin.strip() == "*" and cors_creds.lower() == "true":
        findings.append(
            WebFinding(
                issue_type="misconfiguration",
                severity="high",
                summary="Overly permissive CORS policy detected",
                recommendation="Avoid wildcard origins when credentials are allowed; use a strict allowlist.",
                host=host,
                port=port,
                protocol=protocol,
                evidence_data={"access_control_allow_origin": cors_origin, "access_control_allow_credentials": cors_creds},
                confidence_score=80,
                rationale="Wildcard CORS with credentials may allow unauthorized cross-origin access patterns.",
            )
        )

    if protocol == "http":
        findings.append(
            WebFinding(
                issue_type="misconfiguration",
                severity="moderate",
                summary="HTTP endpoint is not enforcing TLS",
                recommendation="Redirect HTTP to HTTPS and enforce TLS 1.2+.",
                host=host,
                port=port,
                protocol=protocol,
                evidence_data={"scheme": "http"},
                confidence_score=55,
                rationale="Endpoint responded over cleartext HTTP.",
            )
        )

    probe_headers, probe_body = _fetch_headers(parsed.geturl() + ("&" if "?" in parsed.geturl() else "?") + "id=' OR 1=1--")
    if probe_headers is not None:
        body_l = (probe_body or "").lower()
        if any(marker in body_l for marker in SQL_ERROR_MARKERS):
            findings.append(
                WebFinding(
                    issue_type="misconfiguration",
                    severity="high",
                    summary="Potential SQL injection error leakage detected",
                    recommendation="Use parameterized queries and suppress detailed database error messages.",
                    host=host,
                    port=port,
                    protocol=protocol,
                    evidence_data={"probe": "id=' OR 1=1--"},
                    confidence_score=65,
                    rationale="The response body contained database error markers after an injection-style probe.",
                )
            )

    if body and "<form" in body.lower():
        if "csrf" not in body.lower():
            findings.append(
                WebFinding(
                    issue_type="misconfiguration",
                    severity="moderate",
                    summary="Form detected without CSRF indicators",
                    recommendation="Ensure CSRF tokens are present on all state-changing forms.",
                    host=host,
                    port=port,
                    protocol=protocol,
                    evidence_data={"form_detected": True},
                    confidence_score=45,
                    rationale="HTML form found without obvious CSRF token markers.",
                )
            )

    metrics = WebMetrics(
        hosts_scanned=1,
        hosts_alive=1,
        open_ports=1,
        ports_checked=1,
        environment_summary={_infer_environment(host): 1},
        os_summary={},
    )
    return WebScanResult(findings=findings, metrics=metrics)


def _normalize_target(target: str):
    if "://" not in target:
        target = f"https://{target}"
    try:
        parsed = urlparse(target)
        # Docker note: "localhost" inside a container refers to the container itself.
        # For local dev on Docker Desktop, rewrite to host.docker.internal unless disabled.
        if (parsed.hostname or "") in {"localhost", "127.0.0.1"}:
            if os.getenv("AEGIS_DOCKER_LOCALHOST_REWRITE", "1").strip() not in {"0", "false", "FALSE", "no", "NO"}:
                try:
                    if os.path.exists("/.dockerenv"):
                        alias = (os.getenv("AEGIS_DOCKER_HOST_ALIAS", "host.docker.internal") or "").strip()
                        if alias:
                            port = f":{parsed.port}" if parsed.port else ""
                            parsed = urlparse(parsed._replace(netloc=f"{alias}{port}").geturl())
                except Exception:
                    pass
        return parsed
    except ValueError:
        return None


def _fetch_headers(url: str):
    try:
        request = Request(url, headers={"User-Agent": "AegisScanner/1.0"})
        # Do not honor host machine proxy env vars inside the scanner container.
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.read(4096).decode("utf-8", errors="ignore")
            return headers, body
    except Exception:
        return None, ""


def _infer_environment(host: str) -> str:
    if host.startswith("10.") or host.startswith("192.168.") or host.startswith("172.16."):
        return "internal"
    return "external"


def _empty_metrics() -> WebMetrics:
    return WebMetrics(
        hosts_scanned=0,
        hosts_alive=0,
        open_ports=0,
        ports_checked=0,
        environment_summary={},
        os_summary={},
    )
