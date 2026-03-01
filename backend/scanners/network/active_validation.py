import json
import ipaddress
import os
import re
import socket
import time
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import urljoin, urlparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen

REQUEST_TIMEOUT = 5
VALIDATION_USER_AGENT = "AegisActiveValidation/1.0"
MAX_VALIDATION_REQUESTS = 40
SLEEP_BETWEEN_REQUESTS = 0.15
HIGH_RISK_SSRF_MAX_REQUESTS = 12  # Extra strict budget for explicit opt-in mode.


@dataclass
class ValidationFinding:
    validation_type: str
    severity: str
    summary: str
    recommendation: str
    tested_url: str
    status_code: int | None
    evidence: dict
    rationale: str


def validate_web_target(target: str, mode: str = "web") -> List[ValidationFinding]:
    findings, _meta = validate_web_target_detailed(target, mode=mode)
    return findings


def validate_web_target_detailed(
    target: str,
    mode: str = "web",
    high_risk_ssrf: bool = False,
    ssrf_allowlist: dict | None = None,
    allow_metadata: bool = False,
) -> Tuple[List[ValidationFinding], dict]:
    if not target:
        return [], {"high_risk_ssrf": False, "high_risk_ssrf_attempts": []}

    mode = (mode or "web").strip().lower()
    parsed = _normalize_target(target)
    if not parsed:
        return [], {"high_risk_ssrf": False, "high_risk_ssrf_attempts": []}

    base_url = parsed.geturl()
    findings: List[ValidationFinding] = []

    budget = {"remaining": MAX_VALIDATION_REQUESTS}
    meta: dict = {"high_risk_ssrf": False, "high_risk_ssrf_attempts": []}

    base_response = _safe_request(base_url, budget=budget)
    if base_response:
        findings.extend(_validate_cookie_security(base_url, base_response))
        findings.extend(_validate_directory_listing(base_url, base_response))
        candidates = _discover_candidate_urls(base_url, base_response.get("body") or "")
        findings.extend(_validate_reflected_input(base_url, budget=budget))
        findings.extend(_validate_auth_surface_exposure(base_url, budget=budget, candidates=candidates))
        findings.extend(_validate_xss_payload_reflection(base_url, budget=budget, candidates=candidates))
        findings.extend(_validate_sql_error_reflection(base_url, budget=budget, candidates=candidates))
        findings.extend(_validate_path_traversal_indicators(base_url, budget=budget, candidates=candidates))
        findings.extend(_validate_ssrf_indicators(base_url, budget=budget, candidates=candidates))

        # High-risk SSRF validation (explicit opt-in + allowlisted targets only).
        # This does not use any hardcoded internal/metadata endpoints.
        if high_risk_ssrf and isinstance(ssrf_allowlist, dict):
            allowlist = _canonicalize_allowlist(ssrf_allowlist)
            if _base_target_matches_allowlist(base_url, allowlist):
                attempts: list[dict] = []
                hr_start = min(int(budget.get("remaining", 0)), HIGH_RISK_SSRF_MAX_REQUESTS)
                hr_budget = {"remaining": hr_start}
                findings.extend(
                    _validate_ssrf_high_risk(
                        base_url,
                        budget=hr_budget,
                        candidates=candidates,
                        allowlist=allowlist,
                        allow_metadata=allow_metadata,
                        attempts=attempts,
                    )
                )
                meta["high_risk_ssrf"] = True
                meta["high_risk_ssrf_attempts"] = attempts
                # Consume high-risk requests from the shared budget.
                consumed = hr_start - int(hr_budget.get("remaining", 0))
                budget["remaining"] = int(budget.get("remaining", 0)) - consumed
            else:
                meta["high_risk_ssrf"] = False
                meta["high_risk_ssrf_blocked_reason"] = "target_not_in_allowlist"
        findings.extend(_validate_file_upload_surface(base_url, base_response, budget=budget))
        findings.extend(_validate_open_redirect(base_url, budget=budget))

    for path in ("/admin/", "/.git/", "/.env", "/debug"):
        test_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = _safe_request(test_url, budget=budget)
        if not response:
            continue
        if response["status"] in {200, 206}:
            findings.append(
                ValidationFinding(
                    validation_type="Access Control Validation",
                    severity="moderate",
                    summary="Potentially exposed sensitive endpoint",
                    recommendation="Restrict access to sensitive administrative or configuration paths.",
                    tested_url=test_url,
                    status_code=response["status"],
                    evidence={"status": response["status"], "path": path},
                    rationale="Endpoint responded without an authentication challenge. Validate access controls.",
                )
            )

    if mode == "api":
        findings.extend(_validate_graphql_introspection(base_url, budget=budget))
        findings.extend(_validate_graphql_complexity_controls(base_url, budget=budget))
        findings.extend(_validate_rate_limiting(base_url, budget=budget))
        findings.extend(_validate_openapi_auth_requirements(base_url, budget=budget))
        findings.extend(_validate_jwt_negative_token_handling(base_url, budget=budget))
        findings.extend(_validate_rate_limit_consistency_from_openapi(base_url, budget=budget))
        findings.extend(_validate_excessive_data_exposure_from_openapi(base_url, budget=budget))
        findings.extend(_validate_mass_assignment_from_openapi(base_url, budget=budget))
        findings.extend(_validate_bola_from_openapi(base_url, budget=budget))

    # Budget telemetry (safe; used for ops dashboards).
    try:
        remaining = int(budget.get("remaining", 0))
    except Exception:
        remaining = 0
    meta["validation_requests_budget"] = int(MAX_VALIDATION_REQUESTS)
    meta["validation_requests_used"] = int(MAX_VALIDATION_REQUESTS) - max(0, remaining)

    return findings, meta


def _normalize_target(target: str):
    if "/" in target and not target.startswith(("http://", "https://")):
        return None
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


def _safe_request(url: str, method: str = "GET", payload: dict | None = None, budget: dict | None = None):
    if budget is not None:
        remaining = int(budget.get("remaining", 0))
        if remaining <= 0:
            return None
        budget["remaining"] = remaining - 1
    try:
        headers = {"User-Agent": VALIDATION_USER_AGENT}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        request = Request(url, headers=headers, data=data, method=method)
        # Do not honor host machine proxy env vars inside the scanner container.
        # Proxies commonly break localhost/host.docker.internal validation.
        opener = build_opener(ProxyHandler({}))
        started = time.time()
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.read(2048).decode("utf-8", errors="ignore")
            duration_ms = int((time.time() - started) * 1000)
            return {"status": response.status, "headers": headers, "body": body, "duration_ms": duration_ms}
    except Exception:
        return None
    finally:
        time.sleep(SLEEP_BETWEEN_REQUESTS)


def _safe_request_with_headers(url: str, headers: dict, method: str = "GET", budget: dict | None = None):
    """
    Like _safe_request, but allows custom headers (used for safe negative auth tests).
    Payloads are intentionally not supported here.
    """
    if budget is not None:
        remaining = int(budget.get("remaining", 0))
        if remaining <= 0:
            return None
        budget["remaining"] = remaining - 1
    try:
        merged = {"User-Agent": VALIDATION_USER_AGENT}
        for k, v in (headers or {}).items():
            merged[str(k)] = str(v)
        request = Request(url, headers=merged, method=method)
        opener = build_opener(ProxyHandler({}))
        started = time.time()
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            headers_out = {k.lower(): v for k, v in response.headers.items()}
            body = response.read(2048).decode("utf-8", errors="ignore")
            duration_ms = int((time.time() - started) * 1000)
            return {"status": response.status, "headers": headers_out, "body": body, "duration_ms": duration_ms}
    except Exception:
        return None
    finally:
        time.sleep(SLEEP_BETWEEN_REQUESTS)


def _canonicalize_allowlist(allowlist: dict) -> dict:
    domains = allowlist.get("domains") if isinstance(allowlist.get("domains"), list) else []
    cidrs = allowlist.get("cidrs") if isinstance(allowlist.get("cidrs"), list) else []
    urls = allowlist.get("urls") if isinstance(allowlist.get("urls"), list) else []
    out = {
        "domains": [str(d).strip().lower().lstrip(".") for d in domains if str(d).strip()],
        "cidrs": [str(c).strip() for c in cidrs if str(c).strip()],
        "urls": [str(u).strip() for u in urls if str(u).strip()],
    }
    return out


def _host_matches_domain_allowlist(host: str, allow_domains: list[str]) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if not host or not allow_domains:
        return False
    for d in allow_domains:
        if host == d or host.endswith("." + d):
            return True
    return False


def _host_matches_cidr_allowlist(host: str, allow_cidrs: list[str]) -> bool:
    if not host or not allow_cidrs:
        return False
    try:
        ip = ipaddress.ip_address(host)
        for c in allow_cidrs:
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
            except Exception:
                continue
        return False
    except ValueError:
        # Hostname -> resolve to IPs best-effort.
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return False
        ips = []
        for info in infos[:6]:
            try:
                ips.append(ipaddress.ip_address(info[4][0]))
            except Exception:
                continue
        for ip in ips:
            for c in allow_cidrs:
                try:
                    if ip in ipaddress.ip_network(c, strict=False):
                        return True
                except Exception:
                    continue
        return False


def _base_target_matches_allowlist(base_url: str, allowlist: dict) -> bool:
    try:
        parsed = urlparse(base_url)
    except Exception:
        return False
    host = parsed.hostname or ""
    if not host:
        return False
    if _host_matches_domain_allowlist(host, allowlist.get("domains") or []):
        return True
    if _host_matches_cidr_allowlist(host, allowlist.get("cidrs") or []):
        return True
    # Explicit URL allowlist can also authorize the scanned base itself.
    urls = allowlist.get("urls") or []
    return base_url in urls


def _is_metadata_like_target(host: str) -> bool:
    # Link-local ranges + common metadata IPs. This is a safety guardrail; bypass requires explicit allow_metadata=True.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip in ipaddress.ip_network("169.254.0.0/16", strict=False):
        return True
    # IPv6 link-local
    if ip.version == 6 and ip.is_link_local:
        return True
    return False


def _validate_ssrf_high_risk(
    base_url: str,
    budget: dict,
    candidates: list[str],
    allowlist: dict,
    allow_metadata: bool,
    attempts: list[dict],
) -> list[ValidationFinding]:
    """
    High-risk SSRF probe (guarded):
    - Only runs when explicitly enabled by the caller.
    - Uses only allowlisted internal URLs (no hardcoded metadata/internal targets).
    - Logs every attempted probe (probe_url + ssrf_target) via the `attempts` collector.

    This is still heuristic validation: we do not attempt exploitation or data exfiltration.
    """
    urls = allowlist.get("urls") or []
    if not urls:
        return []

    # Keep the test bounded and auditable.
    internal_targets: list[str] = []
    for u in urls[:6]:
        if not isinstance(u, str):
            continue
        if len(u) > 512:
            continue
        if not u.startswith(("http://", "https://")):
            continue
        try:
            p = urlparse(u)
        except Exception:
            continue
        if p.scheme not in {"http", "https"} or not p.hostname:
            continue
        if not allow_metadata and _is_metadata_like_target(p.hostname):
            continue
        internal_targets.append(u)

    if not internal_targets:
        return []

    params = ("url", "uri", "dest", "destination", "callback", "image", "avatar", "resource")
    error_markers = (
        "connection refused",
        "timed out",
        "timeout",
        "could not resolve",
        "no route to host",
        "connection reset",
        "invalid url",
        "unsupported protocol",
        "econnrefused",
        "etimedout",
    )

    targets = candidates[:2] if candidates else [base_url]
    for target in targets:
        for internal_url in internal_targets:
            for param in params:
                probe_url = f"{target}{'&' if '?' in target else '?'}{param}={internal_url}"
                attempts.append({"probe_url": probe_url, "ssrf_target": internal_url, "parameter": param})
                resp = _safe_request(probe_url, budget=budget)
                if not resp:
                    continue
                body_l = (resp.get("body") or "").lower()
                if any(m in body_l for m in error_markers):
                    return [
                        ValidationFinding(
                            validation_type="SSRF High-Risk Validation",
                            severity="high",
                            summary="SSRF sink indicator during allowlisted internal URL probe (high-risk mode)",
                            recommendation="Implement strict URL allowlists, block internal/link-local ranges, and restrict outbound egress. Avoid server-side URL fetching where possible.",
                            tested_url=probe_url,
                            status_code=resp.get("status"),
                            evidence={
                                "high_risk_mode": True,
                                "parameter": param,
                                "ssrf_target": internal_url,
                                "attempted": attempts[-10:],
                                "duration_ms": resp.get("duration_ms"),
                            },
                            rationale="The application response contained network error markers consistent with server-side URL fetch processing to an internal target. This is a heuristic signal; confirm in a controlled environment.",
                        )
                    ]
    return []


def _discover_candidate_urls(base_url: str, body: str) -> list[str]:
    """
    Lightweight, safe endpoint discovery to improve coverage without broad crawling.

    Rules:
    - Only same-origin absolute URLs, and relative URLs under the same base.
    - Only HTTP(S) URLs.
    - Cap the number of candidates to keep scan bounded.
    """
    if not body:
        return []

    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # href/src/action attributes (very small heuristic parser).
    raw_urls: list[str] = []
    for match in re.finditer(r"""(?i)\b(?:href|src|action)\s*=\s*["']([^"'#]+)""", body):
        raw = (match.group(1) or "").strip()
        if not raw:
            continue
        raw_urls.append(raw)

    candidates: list[str] = []
    seen: set[str] = set()
    for raw in raw_urls:
        if raw.startswith(("mailto:", "javascript:", "data:")):
            continue
        if raw.startswith(("http://", "https://")):
            url = raw
        else:
            url = urljoin(base_url.rstrip("/") + "/", raw.lstrip("/"))
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        if parsed.scheme not in {"http", "https"}:
            continue
        if f"{parsed.scheme}://{parsed.netloc}" != base_origin:
            continue
        # Drop obvious static assets
        if parsed.path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf", ".map")):
            continue
        # Normalize: keep path + existing query (some apps route by query).
        norm = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            norm = f"{norm}?{parsed.query}"
        if norm in seen:
            continue
        seen.add(norm)
        candidates.append(norm)
        if len(candidates) >= 8:
            break

    # Always include base_url as the first candidate.
    out = [base_url]
    for c in candidates:
        if c != base_url:
            out.append(c)
    return out[:8]


def _validate_cookie_security(base_url: str, response: dict) -> list[ValidationFinding]:
    cookie_header = response["headers"].get("set-cookie")
    if not cookie_header:
        return []

    lowered = cookie_header.lower()
    missing = []
    if "secure" not in lowered:
        missing.append("Secure")
    if "httponly" not in lowered:
        missing.append("HttpOnly")
    if "samesite" not in lowered:
        missing.append("SameSite")
    if not missing:
        return []

    return [
        ValidationFinding(
            validation_type="Session & Cookie Security Validation",
            severity="high",
            summary="Session cookie missing recommended security attributes",
            recommendation="Apply Secure, HttpOnly, and SameSite attributes to session cookies.",
            tested_url=base_url,
            status_code=response["status"],
            evidence={"missing": missing},
            rationale="Cookies without these attributes are more susceptible to theft or cross-site leakage.",
        )
    ]


def _validate_directory_listing(base_url: str, response: dict) -> list[ValidationFinding]:
    body = response["body"].lower()
    if "index of /" not in body:
        return []
    return [
        ValidationFinding(
            validation_type="Directory Exposure Validation",
            severity="moderate",
            summary="Directory listing detected on web root",
            recommendation="Disable directory listing and expose only required assets.",
            tested_url=base_url,
            status_code=response["status"],
            evidence={"indicator": "index of /"},
            rationale="Directory listing can reveal sensitive files and structure.",
        )
    ]


def _validate_reflected_input(base_url: str, budget: dict) -> list[ValidationFinding]:
    probe_value = "aegis_validation_token"
    probe_url = f"{base_url}?probe={probe_value}"
    response = _safe_request(probe_url, budget=budget)
    if not response:
        return []
    if probe_value not in response["body"]:
        return []
    return [
        ValidationFinding(
            validation_type="Input Handling Validation",
            severity="low",
            summary="Reflected input detected in response",
            recommendation="Ensure output encoding and sanitization for user-supplied input.",
            tested_url=probe_url,
            status_code=response["status"],
            evidence={"reflected": True},
            rationale="Reflected input can be leveraged in XSS scenarios without proper encoding.",
        )
    ]


def _validate_xss_payload_reflection(base_url: str, budget: dict, candidates: list[str]) -> list[ValidationFinding]:
    """
    Reflected XSS checks (safe):
    - Send unique marker payloads that should not execute on their own without user interaction.
    - Flag only when the raw payload (or a risky subset) is reflected unencoded.
    """
    token = "aegis_xss_" + str(int(time.time()))
    payloads = [
        (f"<script>{token}</script>", "q"),
        (f"\\\"><svg/onload={token}>", "q"),
        (f"'><img src=x onerror={token}>", "q"),
    ]

    targets = candidates[:3] if candidates else [base_url]
    for target in targets:
        for payload, param in payloads:
            probe_url = f"{target}{'&' if '?' in target else '?'}{param}={payload}"
            response = _safe_request(probe_url, budget=budget)
            if not response:
                continue
            body = response.get("body", "") or ""
            # If the exact payload is reflected, that is a strong signal.
            if payload in body:
                return [
                    ValidationFinding(
                        validation_type="Input Validation",
                        severity="high",
                        summary="Reflected XSS indicator: unencoded HTML/JS payload reflected",
                        recommendation="Apply context-aware output encoding and input validation. Use templating auto-escaping and CSP where possible.",
                        tested_url=probe_url,
                        status_code=response["status"],
                        evidence={"payload_reflected": True, "parameter": param, "token": token, "probe": payload[:80]},
                        rationale="A script-like payload was reflected unencoded in the response body.",
                    )
                ]
            # Secondary signal: token reflected near dangerous HTML contexts.
            if token in body and any(ctx in body.lower() for ctx in ("<script", "onerror=", "onload=", "javascript:")):
                return [
                    ValidationFinding(
                        validation_type="Input Handling Validation",
                        severity="moderate",
                        summary="Reflected input appears in a potentially executable HTML context",
                        recommendation="Ensure user input is never placed into executable contexts; use strict escaping for attributes/scripts.",
                        tested_url=probe_url,
                        status_code=response["status"],
                        evidence={"token_reflected": True, "parameter": param, "token": token},
                        rationale="The marker value was observed in a context that may allow script execution depending on rendering.",
                    )
                ]
    return []


def _validate_sql_error_reflection(base_url: str, budget: dict, candidates: list[str]) -> list[ValidationFinding]:
    payload = "' OR 1=1--"
    targets = candidates[:2] if candidates else [base_url]
    markers = [
        "sql syntax",
        "mysql",
        "sqlite",
        "postgres",
        "unterminated quoted string",
        "odbc",
        "database error",
    ]
    for target in targets:
        probe_url = f"{target}{'&' if '?' in target else '?'}id={payload}"
        response = _safe_request(probe_url, budget=budget)
        if not response:
            continue
        body = (response.get("body") or "").lower()
        if not any(marker in body for marker in markers):
            continue
        return [
            ValidationFinding(
                validation_type="Input Validation",
                severity="moderate",
                summary="Database error markers observed after SQL-style probe",
                recommendation="Use parameterized queries and suppress detailed database error messages.",
                tested_url=probe_url,
                status_code=response["status"],
                evidence={"payload": payload, "db_error_marker": True},
                rationale="SQL-style probe produced response content that resembles database error leakage.",
            )
        ]
    return []


def _validate_path_traversal_indicators(base_url: str, budget: dict, candidates: list[str]) -> list[ValidationFinding]:
    """
    Path traversal signal (safe heuristic):
    - Use a traversal-like payload but flag only based on error markers that indicate path handling,
      not based on successful sensitive file disclosure.
    """
    payload = "../" * 6 + "etc/passwd"
    markers = ("no such file", "permission denied", "invalid path", "path traversal", "not allowed", "forbidden")
    targets = candidates[:2] if candidates else [base_url]
    for target in targets:
        probe_url = f"{target}{'&' if '?' in target else '?'}file={payload}"
        response = _safe_request(probe_url, budget=budget)
        if not response:
            continue
        body = (response.get("body") or "").lower()
        if any(m in body for m in markers) or payload.lower() in body:
            return [
                ValidationFinding(
                    validation_type="Input Handling Validation",
                    severity="moderate",
                    summary="Traversal-like input produced path-handling error indicators",
                    recommendation="Validate and canonicalize file/path parameters; block traversal sequences and restrict filesystem access.",
                    tested_url=probe_url,
                    status_code=response["status"],
                    evidence={"payload": payload, "indicator": "path_handling_error"},
                    rationale="The response suggests user-controlled path input may reach filesystem operations; confirm controls prevent traversal.",
                )
            ]
    return []


def _validate_ssrf_indicators(base_url: str, budget: dict, candidates: list[str]) -> list[ValidationFinding]:
    """
    SSRF indicator (safe heuristic):
    - Provide a public URL in likely URL-accepting parameters and look for evidence the server fetched remote content.
    - No internal IPs or metadata endpoints are used.
    """
    params = ("url", "uri", "dest", "destination", "callback", "image", "avatar", "resource")
    remote = "https://example.com/"
    signature = "Example Domain"

    targets = candidates[:2] if candidates else [base_url]
    for target in targets:
        for param in params:
            probe_url = f"{target}{'&' if '?' in target else '?'}{param}={remote}"
            response = _safe_request(probe_url, budget=budget)
            if not response:
                continue
            body = response.get("body") or ""
            if signature in body:
                return [
                    ValidationFinding(
                        validation_type="Input Validation",
                        severity="high",
                        summary="SSRF indicator: remote content appears to be fetched and reflected",
                        recommendation="Enforce URL allowlists, block link-local/internal ranges, and disable server-side URL fetching where not required.",
                        tested_url=probe_url,
                        status_code=response["status"],
                        evidence={"parameter": param, "remote": remote, "signature": signature},
                        rationale="Response contained content signature consistent with remote fetch behavior.",
                    )
                ]
            lowered = body.lower()
            if any(err in lowered for err in ("connection refused", "timed out", "invalid url", "unsupported protocol", "could not resolve")):
                return [
                    ValidationFinding(
                        validation_type="Input Handling Validation",
                        severity="moderate",
                        summary="SSRF sink indicator: server-side URL processing errors observed",
                        recommendation="Validate URL inputs, restrict outbound requests, and enforce egress controls.",
                        tested_url=probe_url,
                        status_code=response["status"],
                        evidence={"parameter": param, "remote": remote, "error_indicator": True},
                        rationale="Server response suggests it attempted to process a user-supplied URL value.",
                    )
                ]
    return []


def _validate_file_upload_surface(base_url: str, response: dict, budget: dict) -> list[ValidationFinding]:
    """
    File upload surface discovery:
    - Detect multipart forms and file inputs.
    - Perform safe OPTIONS/HEAD to identify risky methods like PUT.
    - No file content is uploaded.
    """
    body = (response.get("body") or "")
    if not body:
        return []

    lowered = body.lower()
    if "type=\"file\"" not in lowered and "multipart/form-data" not in lowered:
        return []

    actions = []
    for m in re.finditer(r"""(?i)<form[^>]+action\s*=\s*["']([^"']+)""", body):
        actions.append((m.group(1) or "").strip())
        if len(actions) >= 3:
            break

    tested = []
    risky = []
    for action in actions[:2]:
        if not action:
            continue
        upload_url = urljoin(base_url.rstrip("/") + "/", action.lstrip("/"))
        tested.append(upload_url)
        # OPTIONS to see allowed methods (best-effort).
        opt = _safe_request(upload_url, method="OPTIONS", budget=budget)
        allow = ""
        if opt:
            allow = (opt.get("headers") or {}).get("allow", "")
        if "put" in (allow or "").lower():
            risky.append({"url": upload_url, "allow": allow})

    severity = "moderate" if risky else "low"
    summary = "File upload surface detected"
    recommendation = "Ensure upload endpoints enforce authz, MIME/type validation, size limits, storage isolation, and malware scanning."
    if risky:
        summary = "File upload surface with risky HTTP methods observed (PUT allowed)"
        recommendation = "Disable direct PUT uploads unless required; enforce authz, validation, and scanning on all upload paths."

    return [
        ValidationFinding(
            validation_type="Input Handling Validation",
            severity=severity,
            summary=summary,
            recommendation=recommendation,
            tested_url=base_url,
            status_code=response.get("status"),
            evidence={"upload_form": True, "tested_actions": tested, "risky": risky},
            rationale="Upload endpoints are a common source of RCE and data exposure if validation and isolation are weak.",
        )
    ]


def _validate_auth_surface_exposure(base_url: str, budget: dict, candidates: list[str]) -> list[ValidationFinding]:
    """
    Safe auth surface exposure checks (no brute force, no login attempts).
    We look for endpoints that are typically protected, and flag only if they return
    likely-sensitive data without an auth challenge.
    """
    # Commonly sensitive endpoints across web apps and APIs.
    paths = (
        "/admin/",
        "/admin",
        "/api/admin",
        "/api/users",
        "/api/v1/users",
        "/api/me",
        "/me",
        "/users",
        "/internal",
    )

    # Use base_url + a couple discovered candidates to resolve relative paths.
    bases = candidates[:2] if candidates else [base_url]
    tested: list[str] = []
    for base in bases:
        for path in paths:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            tested.append(url)
            resp = _safe_request(url, budget=budget)
            if not resp:
                continue
            status = int(resp.get("status") or 0)
            headers = resp.get("headers") or {}
            body = resp.get("body") or ""
            content_type = (headers.get("content-type") or "").lower()

            # If the server challenges (401/403) or redirects to a login page, that's expected.
            if status in {401, 403}:
                continue
            location = (headers.get("location") or "")
            if status in {301, 302, 303, 307, 308} and ("login" in location.lower() or "signin" in location.lower()):
                continue

            # If 200 and JSON looks like user data or admin content, flag.
            if status == 200:
                body_l = body.lower()
                sensitive_markers = ("\"email\"", "\"token\"", "\"refresh\"", "\"access\"", "\"role\"", "\"is_staff\"", "\"is_admin\"", "\"password\"")
                if "application/json" in content_type and any(m in body_l for m in sensitive_markers):
                    return [
                        ValidationFinding(
                            validation_type="Access Control Validation",
                            severity="high",
                            summary="Potential unauthenticated access to sensitive endpoint",
                            recommendation="Require authentication and enforce authorization for user/admin endpoints. Return 401/403 for unauthenticated requests.",
                            tested_url=url,
                            status_code=status,
                            evidence={"path": path, "content_type": content_type, "tested": tested[-6:]},
                            rationale="Endpoint returned JSON containing user/admin-like fields without an authentication challenge.",
                        )
                    ]
                # Non-JSON admin panels sometimes return HTML with admin markers.
                admin_markers = ("admin panel", "dashboard", "users", "roles", "manage", "administrator")
                if "text/html" in content_type and any(m in body_l for m in admin_markers) and "/admin" in path:
                    return [
                        ValidationFinding(
                            validation_type="Access Control Validation",
                            severity="moderate",
                            summary="Administrative surface appears accessible without an auth challenge",
                            recommendation="Restrict administrative interfaces behind authentication and trusted network controls (VPN/bastion).",
                            tested_url=url,
                            status_code=status,
                            evidence={"path": path, "content_type": content_type, "tested": tested[-6:]},
                            rationale="Admin-like HTML content was returned without an authentication challenge.",
                        )
                    ]

    return []


def _validate_open_redirect(base_url: str, budget: dict) -> list[ValidationFinding]:
    # Safe heuristic: check common redirect parameters.
    tests = [
        ("next", "https://example.com"),
        ("url", "https://example.com"),
        ("redirect", "https://example.com"),
        ("return", "https://example.com"),
        ("continue", "https://example.com"),
    ]
    findings: list[ValidationFinding] = []
    for key, value in tests:
        probe_url = f"{base_url}?{key}={value}"
        resp = _safe_request(probe_url, budget=budget)
        if not resp:
            continue
        location = (resp.get("headers") or {}).get("location", "")
        if location.startswith("https://example.com"):
            findings.append(
                ValidationFinding(
                    validation_type="Redirect Handling",
                    severity="moderate",
                    summary="Potential open redirect behavior detected",
                    recommendation="Validate redirect parameters against an allowlist and avoid redirecting to user-supplied absolute URLs.",
                    tested_url=probe_url,
                    status_code=resp.get("status"),
                    evidence={"parameter": key, "location": location[:200]},
                    rationale="The response contained a redirect Location header based on a user-supplied parameter.",
                )
            )
            break
    return findings


def _validate_graphql_introspection(base_url: str, budget: dict) -> list[ValidationFinding]:
    candidates = ("/graphql", "/api/graphql", "/graphql/", "/api/graphql/")
    payload = {
        "query": "query IntrospectionQuery { __schema { queryType { name } } }",
        "operationName": "IntrospectionQuery",
    }
    findings: list[ValidationFinding] = []
    for path in candidates:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        resp = _safe_request(url, method="POST", payload=payload, budget=budget)
        if not resp:
            continue
        body = resp.get("body") or ""
        if "__schema" in body and resp.get("status") in {200, 201}:
            findings.append(
                ValidationFinding(
                    validation_type="GraphQL Exposure",
                    severity="moderate",
                    summary="GraphQL introspection appears enabled",
                    recommendation="Disable GraphQL introspection in production or require authentication/authorization for schema queries.",
                    tested_url=url,
                    status_code=resp.get("status"),
                    evidence={"introspection": True, "path": path},
                    rationale="GraphQL schema keywords were present in the introspection query response.",
                )
            )
            break
    return findings


def _validate_graphql_complexity_controls(base_url: str, budget: dict) -> list[ValidationFinding]:
    """
    GraphQL cost/complexity control heuristic (safe):
    - Send a moderately nested query to see if the server returns a "too complex/depth" style error.
    - This is intentionally bounded (no large payloads, no tight loops).
    """
    candidates = ("/graphql", "/api/graphql", "/graphql/", "/api/graphql/")
    # Keep this small. Depth ~8 with repeated fields; should be rejected in hardened configs.
    payload = {
        "query": "query CostProbe { __schema { types { name fields { name args { name type { name kind } } type { name kind ofType { name kind } } } } } }",
        "operationName": "CostProbe",
    }
    for path in candidates:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        resp = _safe_request(url, method="POST", payload=payload, budget=budget)
        if not resp:
            continue
        body_l = (resp.get("body") or "").lower()
        # If introspection is off, we don't conclude anything about complexity controls.
        if resp.get("status") in {401, 403}:
            continue
        if any(m in body_l for m in ("query is too complex", "complexity", "depth limit", "max depth", "too deep", "cost limit")):
            return [
                ValidationFinding(
                    validation_type="GraphQL Hardening",
                    severity="low",
                    summary="GraphQL complexity/depth controls appear to be enforced (heuristic)",
                    recommendation="Keep complexity/depth limits enabled in production and ensure per-field costs align with risk.",
                    tested_url=url,
                    status_code=resp.get("status"),
                    evidence={"complexity_control_observed": True, "path": path},
                    rationale="The response included an error marker consistent with GraphQL complexity/depth enforcement.",
                )
            ]
        # If we get a successful response containing schema data, controls were not observed.
        if resp.get("status") in {200, 201} and any(k in body_l for k in ("__schema", "\"types\"", "\"fields\"")):
            return [
                ValidationFinding(
                    validation_type="GraphQL Hardening",
                    severity="moderate",
                    summary="GraphQL complexity/depth controls were not observed (heuristic)",
                    recommendation="Implement GraphQL query depth/complexity limits, disable introspection in prod, and rate-limit GraphQL endpoints.",
                    tested_url=url,
                    status_code=resp.get("status"),
                    evidence={"complexity_control_observed": False, "path": path},
                    rationale="A moderately nested query returned schema data; if GraphQL is exposed in production, add cost controls to reduce abuse risk.",
                )
            ]
    return []


def _validate_rate_limiting(base_url: str, budget: dict) -> list[ValidationFinding]:
    # Safe burst: small number of requests; we don't attempt DoS.
    max_requests = 12
    statuses: list[int] = []
    retry_after = ""
    for _ in range(max_requests):
        resp = _safe_request(base_url, budget=budget)
        if not resp:
            continue
        statuses.append(int(resp.get("status") or 0))
        if int(resp.get("status") or 0) == 429:
            retry_after = (resp.get("headers") or {}).get("retry-after", "")
            break
    if not statuses:
        return []
    if 429 in statuses:
        return [
            ValidationFinding(
                validation_type="Rate Limiting",
                severity="low",
                summary="Rate limiting appears to be enabled (429 observed)",
                recommendation="Ensure rate limiting is applied consistently to authentication and sensitive API endpoints.",
                tested_url=base_url,
                status_code=429,
                evidence={"statuses": statuses, "retry_after": retry_after},
                rationale="A 429 response indicates throttling is active.",
            )
        ]
    return [
        ValidationFinding(
            validation_type="Rate Limiting",
            severity="low",
            summary="Rate limiting was not observed during a small safe burst",
            recommendation="Consider adding request throttling (429/Retry-After) on authentication and high-risk endpoints.",
            tested_url=base_url,
            status_code=statuses[-1],
            evidence={"statuses": statuses},
            rationale="No throttling response was observed in a small request burst; this is a heuristic signal only.",
        )
    ]


def _fetch_openapi_spec(base_url: str, budget: dict) -> tuple[dict | None, str]:
    # Cache within this validation run to avoid repeated spec fetches.
    if isinstance(budget, dict) and "_openapi_cached" in budget:
        return budget.get("_openapi_cached"), str(budget.get("_openapi_cached_url") or "")

    spec_paths = ("/openapi.json", "/swagger/v1/swagger.json", "/swagger.json")
    for path in spec_paths:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        resp = _safe_request(url, budget=budget)
        if not resp or resp.get("status") != 200:
            continue
        body = resp.get("body") or ""
        if not body.strip().startswith(("{", "[")):
            continue
        try:
            spec = json.loads(body)
        except Exception:
            continue
        if isinstance(spec, dict) and isinstance(spec.get("paths"), dict):
            if isinstance(budget, dict):
                budget["_openapi_cached"] = spec
                budget["_openapi_cached_url"] = url
            return spec, url
    if isinstance(budget, dict):
        budget["_openapi_cached"] = None
        budget["_openapi_cached_url"] = ""
    return None, ""


def _iter_openapi_operations(spec: dict):
    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    for p, methods in paths.items():
        if not isinstance(p, str) or not isinstance(methods, dict):
            continue
        for m, op in methods.items():
            if not isinstance(m, str) or m.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            if not isinstance(op, dict):
                continue
            yield p, m.lower(), op


def _openapi_op_requires_auth(spec: dict, op: dict) -> bool | None:
    """
    Best-effort interpretation of OpenAPI security:
    - If op has "security": [] explicitly, it's unauthenticated.
    - If op has non-empty "security", it's authenticated.
    - Else inherit global "security" if present.
    Returns None when inconclusive.
    """
    if "security" in op:
        sec = op.get("security")
        if sec == []:
            return False
        if isinstance(sec, list) and len(sec) > 0:
            return True
        return None
    global_sec = spec.get("security")
    if global_sec == []:
        return False
    if isinstance(global_sec, list) and len(global_sec) > 0:
        return True
    return None


def _extract_schema_properties(schema: dict | None) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    props = schema.get("properties")
    if isinstance(props, dict):
        return {str(k) for k in props.keys()}
    return set()


def _schema_from_ref(spec: dict, ref: str) -> dict | None:
    # Only support local component refs.
    if not ref.startswith("#/"):
        return None
    node: object = spec
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _resolve_schema(spec: dict, schema: dict | None) -> dict | None:
    if not isinstance(schema, dict):
        return None
    if "$ref" in schema and isinstance(schema.get("$ref"), str):
        return _schema_from_ref(spec, schema["$ref"])
    return schema


def _extract_request_body_schema(spec: dict, op: dict) -> dict | None:
    rb = op.get("requestBody") if isinstance(op.get("requestBody"), dict) else None
    if not rb:
        return None
    content = rb.get("content") if isinstance(rb.get("content"), dict) else {}
    for ct in ("application/json", "application/*+json"):
        if ct in content and isinstance(content.get(ct), dict):
            schema = content[ct].get("schema")
            return _resolve_schema(spec, schema if isinstance(schema, dict) else None)
    # fallback: pick any json-ish schema
    for v in content.values():
        if isinstance(v, dict) and isinstance(v.get("schema"), dict):
            return _resolve_schema(spec, v.get("schema"))
    return None


def _extract_response_schema(spec: dict, op: dict) -> dict | None:
    responses = op.get("responses") if isinstance(op.get("responses"), dict) else {}
    for code in ("200", "201"):
        r = responses.get(code)
        if not isinstance(r, dict):
            continue
        content = r.get("content") if isinstance(r.get("content"), dict) else {}
        for ct in ("application/json", "application/*+json"):
            if ct in content and isinstance(content.get(ct), dict):
                schema = content[ct].get("schema")
                return _resolve_schema(spec, schema if isinstance(schema, dict) else None)
        for v in content.values():
            if isinstance(v, dict) and isinstance(v.get("schema"), dict):
                return _resolve_schema(spec, v.get("schema"))
    return None


def _validate_openapi_auth_requirements(base_url: str, budget: dict) -> list[ValidationFinding]:
    """
    Auth requirement validation (safe):
    - If OpenAPI is exposed, identify operations that appear to require auth (per spec)
      and verify that unauthenticated requests are challenged (401/403) for a small sample.
    """
    spec, spec_url = _fetch_openapi_spec(base_url, budget=budget)
    if not spec:
        return []

    checked: list[dict] = []
    for path, method, op in _iter_openapi_operations(spec):
        requires = _openapi_op_requires_auth(spec, op)
        if requires is not True:
            continue
        # Prefer GET endpoints for safe negative tests.
        if method != "get":
            continue
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/").replace("{id}", "1").replace("{pk}", "1").replace("{uuid}", "00000000-0000-0000-0000-000000000001"))
        resp = _safe_request(url, budget=budget)
        checked.append({"path": path, "url": url, "status": (resp.get("status") if resp else None)})
        if not resp:
            continue
        status = int(resp.get("status") or 0)
        if status in {401, 403}:
            if len(checked) >= 3:
                break
            continue
        # If the spec claims auth is required but we got a 200, that's a high signal.
        if status == 200:
            return [
                ValidationFinding(
                    validation_type="API Authorization (Spec)",
                    severity="high",
                    summary="OpenAPI indicates an endpoint requires auth, but unauthenticated request returned 200",
                    recommendation="Ensure authentication middleware is enforced for all endpoints requiring authorization; verify routing/middleware order and deployments.",
                    tested_url=spec_url,
                    status_code=200,
                    evidence={"openapi_spec": spec_url, "checked": checked[-3:]},
                    rationale="Spec-defined security requirements appear inconsistent with observed unauthenticated access. Confirm with an authenticated test and server logs.",
                )
            ]
        if len(checked) >= 3:
            break

    return []


def _validate_jwt_negative_token_handling(base_url: str, budget: dict) -> list[ValidationFinding]:
    """
    JWT/auth token validation analysis (safe, negative tests):
    - If OpenAPI is exposed and indicates bearer auth, pick a small sample of secured GET endpoints
      and verify that an invalid Bearer token is rejected (401/403).

    This does not attempt to obtain or brute-force credentials.
    """
    spec, spec_url = _fetch_openapi_spec(base_url, budget=budget)
    if not spec:
        return []

    schemes = ((spec.get("components") or {}).get("securitySchemes") or {}) if isinstance(spec.get("components"), dict) else {}
    bearer_like = False
    if isinstance(schemes, dict):
        for v in schemes.values():
            if not isinstance(v, dict):
                continue
            if (v.get("type") or "").lower() == "http" and (v.get("scheme") or "").lower() == "bearer":
                bearer_like = True
                break
    if not bearer_like:
        return []

    checked: list[dict] = []
    headers = {"Authorization": "Bearer aegis.invalid.token"}
    for path, method, op in _iter_openapi_operations(spec):
        if method != "get":
            continue
        requires = _openapi_op_requires_auth(spec, op)
        if requires is not True:
            continue
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/").replace("{id}", "1").replace("{pk}", "1").replace("{uuid}", "00000000-0000-0000-0000-000000000001"))
        resp = _safe_request_with_headers(url, headers=headers, method="GET", budget=budget)
        checked.append({"path": path, "status": (resp.get("status") if resp else None), "duration_ms": (resp.get("duration_ms") if resp else None)})
        if not resp:
            if len(checked) >= 2:
                break
            continue
        status = int(resp.get("status") or 0)
        if status == 200:
            body = resp.get("body") or ""
            return [
                ValidationFinding(
                    validation_type="Authentication Validation",
                    severity="high",
                    summary="Invalid Bearer token was accepted for a secured endpoint (critical auth weakness)",
                    recommendation="Ensure JWT/Bearer token validation is enforced (signature, issuer/audience, exp/nbf, algorithm allowlist) and reject invalid tokens with 401/403.",
                    tested_url=spec_url,
                    status_code=200,
                    evidence={"openapi_spec": spec_url, "checked": checked[-2:], "response_snippet": body[:200]},
                    rationale="A request with a clearly invalid Bearer token returned 200. This indicates token validation may be missing or bypassable.",
                )
            ]
        if status in {401, 403} and len(checked) >= 2:
            break

    if not checked:
        return []
    # If we observed rejections, that's good; keep it informational.
    if any(c.get("status") in {401, 403} for c in checked):
        return [
            ValidationFinding(
                validation_type="Authentication Validation",
                severity="low",
                summary="Bearer token validation appears to reject invalid tokens (heuristic)",
                recommendation="Continue enforcing strict JWT validation (signature, exp, iss/aud) and log token validation failures.",
                tested_url=spec_url,
                status_code=checked[0].get("status"),
                evidence={"openapi_spec": spec_url, "checked": checked},
                rationale="A small sample of secured endpoints rejected an invalid Bearer token as expected.",
            )
        ]
    return []


def _validate_rate_limit_consistency_from_openapi(base_url: str, budget: dict) -> list[ValidationFinding]:
    """
    Enumeration / rate-limit bypass analysis (safe heuristic):
    - Select a few "sensitive" endpoints from OpenAPI (auth/admin/user-ish paths) and perform a small burst
      to check for consistent 429 + Retry-After / rate limit headers.

    We do not attempt evasion (no X-Forwarded-For spoofing, no distributed bypass).
    """
    spec, spec_url = _fetch_openapi_spec(base_url, budget=budget)
    if not spec:
        return []

    sensitive_terms = ("auth", "login", "token", "password", "admin", "users", "accounts", "session")
    candidates: list[str] = []
    for path, method, _op in _iter_openapi_operations(spec):
        if method != "get":
            continue
        p_l = path.lower()
        if any(t in p_l for t in sensitive_terms):
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            candidates.append(url)
        if len(candidates) >= 3:
            break

    if not candidates:
        # fall back to base_url only
        candidates = [base_url]

    observed_429 = False
    saw_rate_headers = False
    checked: list[dict] = []
    for url in candidates[:3]:
        statuses: list[int] = []
        retry_after = ""
        rate_hdrs: dict = {}
        for _ in range(6):
            resp = _safe_request(url, budget=budget)
            if not resp:
                continue
            status = int(resp.get("status") or 0)
            statuses.append(status)
            headers = resp.get("headers") or {}
            # Common rate limit header families.
            for k in ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset"):
                if k in headers:
                    rate_hdrs[k] = headers.get(k)
            if status == 429:
                observed_429 = True
                retry_after = headers.get("retry-after") or ""
                break
        if rate_hdrs:
            saw_rate_headers = True
        checked.append({"url": url, "statuses": statuses, "retry_after": retry_after, "rate_headers": rate_hdrs})

    if observed_429:
        return [
            ValidationFinding(
                validation_type="Rate Limiting",
                severity="low",
                summary="Rate limiting observed on sensitive endpoints (429)",
                recommendation="Ensure rate limiting is consistently applied across auth and data endpoints and includes Retry-After / rate limit headers.",
                tested_url=spec_url,
                status_code=429,
                evidence={"openapi_spec": spec_url, "checked": checked[:3]},
                rationale="A small safe burst triggered a 429 response, suggesting throttling exists on at least one sensitive endpoint.",
            )
        ]
    if not saw_rate_headers:
        return [
            ValidationFinding(
                validation_type="Rate Limiting",
                severity="moderate",
                summary="Rate limiting was not observed on a small burst to sensitive endpoints (heuristic)",
                recommendation="Add throttling to auth and enumeration-prone endpoints and emit Retry-After / RateLimit-* headers for clients.",
                tested_url=spec_url,
                status_code=checked[0]["statuses"][-1] if checked and checked[0].get("statuses") else None,
                evidence={"openapi_spec": spec_url, "checked": checked[:3]},
                rationale="No 429 responses or standard rate limit headers were observed in a small burst. This is a heuristic signal only; validate at the gateway/WAF layer too.",
            )
        ]
    return []

def _validate_mass_assignment_from_openapi(base_url: str, budget: dict) -> list[ValidationFinding]:
    """
    Mass assignment detection (safe, schema-based):
    - Identify request body schemas that allow sensitive fields that should typically be server-controlled.
    - No write requests are sent.
    """
    spec, spec_url = _fetch_openapi_spec(base_url, budget=budget)
    if not spec:
        return []

    sensitive_fields = {
        "role",
        "roles",
        "permission",
        "permissions",
        "is_admin",
        "is_staff",
        "is_superuser",
        "admin",
        "balance",
        "credit",
        "quota",
        "tier",
        "plan",
        "price",
        "owner",
        "organization_id",
        "org_id",
        "user_id",
        "account_id",
        "status",
        "enabled",
        "deleted",
    }

    hits: list[dict] = []
    for path, method, op in _iter_openapi_operations(spec):
        if method not in {"post", "put", "patch"}:
            continue
        schema = _extract_request_body_schema(spec, op)
        props = _extract_schema_properties(schema)
        intersect = sorted([p for p in props if p.lower() in sensitive_fields])
        if not intersect:
            continue
        hits.append({"path": path, "method": method, "fields": intersect[:12]})
        if len(hits) >= 6:
            break

    if not hits:
        return []

    return [
        ValidationFinding(
            validation_type="API Schema Review",
            severity="moderate",
            summary="Potential mass-assignment risk: sensitive fields appear writable in OpenAPI request schemas",
            recommendation="Mark server-controlled fields as readOnly in schemas, enforce allowlists on serializers/binders, and validate role/permission fields server-side.",
            tested_url=spec_url,
            status_code=200,
            evidence={"openapi_spec": spec_url, "examples": hits},
            rationale="OpenAPI request body schemas include fields commonly associated with privilege/ownership changes. This is a schema-based signal; validate server-side enforcement.",
        )
    ]


def _validate_excessive_data_exposure_from_openapi(base_url: str, budget: dict) -> list[ValidationFinding]:
    """
    Excessive data exposure detection (safe, schema-based + small runtime sample):
    - Flag response schemas that include sensitive fields (e.g., tokens, secrets, passwords).
    - If OpenAPI indicates unauthenticated access, optionally sample a GET response and look for sensitive markers.
    """
    spec, spec_url = _fetch_openapi_spec(base_url, budget=budget)
    if not spec:
        return []

    sensitive_keys = {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access",
        "refresh",
        "token",
        "private_key",
        "ssn",
        "credit_card",
        "card_number",
        "cvv",
    }

    exposures: list[dict] = []
    for path, method, op in _iter_openapi_operations(spec):
        if method != "get":
            continue
        schema = _extract_response_schema(spec, op)
        props = _extract_schema_properties(schema)
        intersect = sorted([p for p in props if p.lower() in sensitive_keys])
        if not intersect:
            continue
        requires = _openapi_op_requires_auth(spec, op)
        exposures.append({"path": path, "fields": intersect[:12], "requires_auth": requires})
        if len(exposures) >= 6:
            break

    if not exposures:
        return []

    # If any look unauthenticated per spec, do a tiny runtime sample to strengthen confidence.
    runtime_checked: list[dict] = []
    for ex in exposures:
        if ex.get("requires_auth") is not False:
            continue
        url = urljoin(base_url.rstrip("/") + "/", str(ex["path"]).lstrip("/"))
        resp = _safe_request(url, budget=budget)
        if not resp:
            continue
        body_l = (resp.get("body") or "").lower()
        runtime_checked.append({"path": ex["path"], "status": resp.get("status")})
        if resp.get("status") == 200 and any(k in body_l for k in ("password", "token", "refresh", "access", "secret", "api_key")):
            return [
                ValidationFinding(
                    validation_type="API Data Exposure",
                    severity="high",
                    summary="Potential excessive data exposure: unauthenticated API response appears to include sensitive fields (heuristic)",
                    recommendation="Apply response filtering (DTOs), remove secrets/tokens from general responses, and enforce auth for sensitive resources.",
                    tested_url=url,
                    status_code=200,
                    evidence={"openapi_spec": spec_url, "openapi_flags": exposures[:4], "runtime_checked": runtime_checked[:3]},
                    rationale="OpenAPI response schemas and a sample runtime response suggest sensitive fields may be returned without authentication. Confirm with authenticated/role-based tests.",
                )
            ]
        if len(runtime_checked) >= 2:
            break

    return [
        ValidationFinding(
            validation_type="API Data Exposure",
            severity="moderate",
            summary="Potential excessive data exposure: sensitive fields appear in OpenAPI response schemas",
            recommendation="Review API response models for over-sharing. Ensure sensitive fields are excluded or returned only to authorized roles.",
            tested_url=spec_url,
            status_code=200,
            evidence={"openapi_spec": spec_url, "examples": exposures[:6]},
            rationale="OpenAPI response schemas include fields commonly considered sensitive. This is schema-based and may include internal/admin-only responses; confirm endpoint protections.",
        )
    ]


def _validate_bola_from_openapi(base_url: str, budget: dict) -> list[ValidationFinding]:
    """
    Heuristic BOLA/IDOR check:
    - If OpenAPI spec is exposed, locate a few GET paths with {id}/{uuid} and probe two identifiers unauthenticated.
    - Flag only when responses are 200 and appear to contain sensitive fields.
    """
    spec, spec_url = _fetch_openapi_spec(base_url, budget=budget)
    if not isinstance(spec, dict):
        return []

    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    candidates: list[str] = []
    for p, methods in paths.items():
        if not isinstance(p, str) or "{" not in p or "}" not in p:
            continue
        if "{id}" in p or "{pk}" in p or "{uuid}" in p:
            if isinstance(methods, dict) and "get" in {k.lower() for k in methods.keys()}:
                candidates.append(p)
        if len(candidates) >= 5:
            break

    sensitive_keys = ("email", "token", "api_key", "secret", "password", "ssn", "credit", "card", "refresh", "access")
    for path_tmpl in candidates:
        first = path_tmpl.replace("{id}", "1").replace("{pk}", "1").replace("{uuid}", "00000000-0000-0000-0000-000000000001")
        second = path_tmpl.replace("{id}", "2").replace("{pk}", "2").replace("{uuid}", "00000000-0000-0000-0000-000000000002")
        url1 = urljoin(base_url.rstrip("/") + "/", first.lstrip("/"))
        url2 = urljoin(base_url.rstrip("/") + "/", second.lstrip("/"))
        r1 = _safe_request(url1, budget=budget)
        r2 = _safe_request(url2, budget=budget)
        if not r1 or not r2:
            continue
        if r1.get("status") != 200 or r2.get("status") != 200:
            continue
        b1 = (r1.get("body") or "")[:2048]
        b2 = (r2.get("body") or "")[:2048]
        if b1 == b2:
            continue
        merged = (b1 + " " + b2).lower()
        if not any(k in merged for k in sensitive_keys):
            continue
        return [
            ValidationFinding(
                validation_type="API Authorization (Heuristic)",
                severity="high",
                summary="Potential unauthenticated object access / enumeration (BOLA/IDOR indicator)",
                recommendation="Enforce object-level authorization (BOLA) on all endpoints that return user or account data.",
                tested_url=spec_url,
                status_code=200,
                evidence={"openapi_spec": spec_url, "path_template": path_tmpl, "tested": [first, second]},
                rationale="Two unauthenticated requests to ID-based endpoints returned different 200 responses containing sensitive-looking fields.",
            )
        ]
    return []
