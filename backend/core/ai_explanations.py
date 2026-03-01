def explain_code_finding(finding, role: str | None = None) -> str:
    role = (role or "").lower()
    category = getattr(finding, "category", "") or ""
    title = getattr(finding, "title", "Security finding")
    severity = getattr(finding, "severity", "moderate")

    if role == "executive":
        return (
            f"{title} was identified during a code review. "
            f"It represents a {severity} risk that may affect confidentiality or availability "
            "if not addressed. Remediation should be prioritized according to business impact."
        )
    if role == "developer":
        return (
            f"{title} detected in code. "
            "Fix guidance is provided to address the specific issue at the file/line location."
        )
    if category == "secrets":
        return (
            "A potential secret appears in source code. "
            "Exposed credentials can be misused to access systems. Rotate and remove the value."
        )
    if category == "dependency":
        return (
            "A dependency appears to match a known vulnerable version. "
            "Upgrade to a patched release and validate compatibility."
        )
    return (
        "Static analysis flagged a security or configuration weakness. "
        "Address the issue and re-scan to confirm remediation."
    )


def explain_network_finding(finding, role: str | None = None) -> str:
    role = (role or "").lower()
    severity = getattr(finding, "severity", "moderate")
    summary = getattr(finding, "summary", "Network finding")
    evidence = getattr(finding, "evidence", {}) or {}
    validation_type = evidence.get("validation_type")

    if role == "executive":
        return (
            f"{summary} indicates a {severity} exposure. "
            "If left unresolved, it could increase risk to critical services."
        )
    if validation_type:
        return (
            "Safe, non-destructive validation observed response behavior without exploitation. "
            "This suggests a control gap that should be reviewed and hardened."
        )
    return (
        "Network exposure or configuration weakness detected. "
        "Restrict access, enforce secure defaults, and monitor for abuse."
    )


def explain_cloud_finding(finding, role: str | None = None) -> str:
    role = (role or "").lower()
    severity = getattr(finding, "severity", "moderate")
    title = getattr(finding, "title", "Cloud posture finding")

    if role == "executive":
        return (
            f"{title} indicates a {severity} cloud configuration risk. "
            "If left unresolved, it may expose data or increase operational risk."
        )
    if role == "developer":
        return (
            f"{title} identified in cloud configuration. "
            "Apply the recommended remediation and re-validate the posture."
        )
    return (
        "Cloud posture assessment identified a configuration gap. "
        "Apply least-privilege controls and restrict public exposure."
    )


def explain_report_summary(scope: str, severity_summary: dict) -> str:
    critical = severity_summary.get("critical", 0)
    high = severity_summary.get("high", 0)
    if critical or high:
        return (
            f"{scope.title()} scan indicates elevated risk with "
            f"{critical} critical and {high} high findings. "
            "Immediate remediation is recommended for exposed assets."
        )
    return (
        f"{scope.title()} scan indicates no critical findings. "
        "Continue routine hardening and monitoring."
    )
