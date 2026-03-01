import json
import os
import re
import zipfile
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Tuple


MAX_FILE_SIZE = 1024 * 1024

SUPPORTED_FILES = {
    "requirements.txt",
    "poetry.lock",
    "pipfile.lock",
    "package.json",
    "package-lock.json",
}

IGNORE_PATH_SEGMENTS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "dist",
    "build",
    "vendor",
    "coverage",
    "docs",
    "doc",
    "examples",
    "fixtures",
    "tests",
    "test",
    "__pycache__",
}


VULNERABILITY_DB = [
    {
        "dependency_name": "django",
        "ecosystem": "pypi",
        "vulnerable_range": ">=3.2.0,<3.2.24",
        "cve_id": "CVE-2023-46695",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "exploit_maturity": "high",
        "remediation_version": "3.2.24",
        "compliance_mapping": ["OWASP Top 10 A06", "NIST 800-53 SI-2"],
    },
    {
        "dependency_name": "requests",
        "ecosystem": "pypi",
        "vulnerable_range": "<2.20.0",
        "cve_id": "CVE-2018-18074",
        "cvss": 6.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "exploit_maturity": "medium",
        "remediation_version": "2.20.0",
        "compliance_mapping": ["OWASP Top 10 A06", "ISO 27001 A.12"],
    },
    {
        "dependency_name": "lodash",
        "ecosystem": "npm",
        "vulnerable_range": "<4.17.21",
        "cve_id": "CVE-2021-23337",
        "cvss": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "exploit_maturity": "high",
        "remediation_version": "4.17.21",
        "compliance_mapping": ["OWASP Top 10 A06", "NIST 800-53 SI-2"],
    },
    {
        "dependency_name": "axios",
        "ecosystem": "npm",
        "vulnerable_range": "<0.27.2",
        "cve_id": "CVE-2022-1214",
        "cvss": 6.1,
        "cvss_vector": "",
        "exploit_maturity": "medium",
        "remediation_version": "0.27.2",
        "compliance_mapping": ["OWASP Top 10 A06", "ISO 27001 A.12"],
    },
    {
        "dependency_name": "express",
        "ecosystem": "npm",
        "vulnerable_range": "<4.18.2",
        "cve_id": "CVE-2022-24999",
        "cvss": 7.0,
        "cvss_vector": "",
        "exploit_maturity": "medium",
        "remediation_version": "4.18.2",
        "compliance_mapping": ["OWASP Top 10 A06", "NIST 800-53 SI-2"],
    },
    {
        "dependency_name": "flask",
        "ecosystem": "pypi",
        "vulnerable_range": "<2.2.5",
        "cve_id": "CVE-2023-30861",
        "cvss": 7.5,
        "cvss_vector": "",
        "exploit_maturity": "medium",
        "remediation_version": "2.2.5",
        "compliance_mapping": ["OWASP Top 10 A06", "ISO 27001 A.12"],
    },
    {
        "dependency_name": "jinja2",
        "ecosystem": "pypi",
        "vulnerable_range": "<3.1.3",
        "cve_id": "CVE-2023-32681",
        "cvss": 7.1,
        "cvss_vector": "",
        "exploit_maturity": "medium",
        "remediation_version": "3.1.3",
        "compliance_mapping": ["OWASP Top 10 A03", "ISO 27001 A.12"],
    },
    {
        "dependency_name": "jsonwebtoken",
        "ecosystem": "npm",
        "vulnerable_range": "<9.0.0",
        "cve_id": "CVE-2022-23529",
        "cvss": 7.5,
        "cvss_vector": "",
        "exploit_maturity": "high",
        "remediation_version": "9.0.0",
        "compliance_mapping": ["OWASP Top 10 A07", "NIST 800-53 SI-2"],
    },
    {
        "dependency_name": "ws",
        "ecosystem": "npm",
        "vulnerable_range": "<8.11.0",
        "cve_id": "CVE-2022-37601",
        "cvss": 6.8,
        "cvss_vector": "",
        "exploit_maturity": "medium",
        "remediation_version": "8.11.0",
        "compliance_mapping": ["OWASP Top 10 A06", "ISO 27001 A.12"],
    },
]


@dataclass
class DependencyFinding:
    dependency_name: str
    detected_version: str
    vulnerable_range: str
    cve_id: str
    cvss_vector: str | None
    severity: str
    affected_files: List[str]
    remediation_version: str
    compliance_mapping: List[str]
    description: str


def scan_dependencies(repo_path: str) -> List[DependencyFinding]:
    if not repo_path:
        return []
    if os.path.isfile(repo_path) and repo_path.lower().endswith(".zip"):
        findings = list(_scan_zip(repo_path))
    elif os.path.isdir(repo_path):
        findings = list(_scan_directory(repo_path))
    else:
        return []

    return _match_vulnerabilities(findings)


def _scan_directory(root: str) -> Iterator[Tuple[str, str, str]]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in IGNORE_PATH_SEGMENTS]
        for filename in filenames:
            lower = filename.lower()
            if lower not in SUPPORTED_FILES:
                continue
            path = os.path.join(dirpath, filename)
            if _file_too_large(path):
                continue
            yield from _parse_dependency_file(path, filename)


def _scan_zip(zip_path: str) -> Iterator[Tuple[str, str, str]]:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                basename = os.path.basename(info.filename).lower()
                if basename not in SUPPORTED_FILES:
                    continue
                if info.file_size > MAX_FILE_SIZE:
                    continue
                try:
                    with archive.open(info) as handle:
                        content = handle.read(MAX_FILE_SIZE + 1)
                except Exception:
                    continue
                if len(content) > MAX_FILE_SIZE:
                    continue
                yield from _parse_dependency_content(content, basename, info.filename)
    except (zipfile.BadZipFile, FileNotFoundError):
        return iter(())


def _parse_dependency_file(path: str, filename: str) -> Iterator[Tuple[str, str, str]]:
    try:
        with open(path, "rb") as handle:
            content = handle.read(MAX_FILE_SIZE + 1)
    except OSError:
        return iter(())
    if len(content) > MAX_FILE_SIZE:
        return iter(())
    return _parse_dependency_content(content, filename.lower(), path)


def _parse_dependency_content(content: bytes, filename: str, path_label: str) -> Iterator[Tuple[str, str, str]]:
    if filename == "requirements.txt":
        return _parse_requirements_txt(content, path_label)
    if filename == "poetry.lock":
        return _parse_poetry_lock(content, path_label)
    if filename == "pipfile.lock":
        return _parse_pipfile_lock(content, path_label)
    if filename == "package.json":
        return _parse_package_json(content, path_label)
    if filename == "package-lock.json":
        return _parse_package_lock(content, path_label)
    return iter(())


def _parse_requirements_txt(content: bytes, path_label: str) -> Iterator[Tuple[str, str, str]]:
    text = content.decode("utf-8", errors="ignore")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = stripped.split("#", 1)[0].strip()
        if "git+" in stripped or "http://" in stripped or "https://" in stripped:
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)(.*)$", stripped)
        if not match:
            continue
        name = match.group(1)
        spec = match.group(2).strip()
        version = _extract_version_from_spec(spec)
        if version:
            yield name, version, path_label


def _parse_poetry_lock(content: bytes, path_label: str) -> Iterator[Tuple[str, str, str]]:
    text = content.decode("utf-8", errors="ignore")
    name = None
    version = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[[package]]"):
            if name and version:
                yield name, version, path_label
            name = None
            version = None
        elif stripped.startswith("name ="):
            name = stripped.split("=", 1)[1].strip().strip('"').strip("'")
        elif stripped.startswith("version ="):
            version = stripped.split("=", 1)[1].strip().strip('"').strip("'")
    if name and version:
        yield name, version, path_label


def _parse_pipfile_lock(content: bytes, path_label: str) -> Iterator[Tuple[str, str, str]]:
    try:
        data = json.loads(content.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return iter(())
    sections = ["default", "develop"]
    for section in sections:
        deps = data.get(section, {}) or {}
        for name, meta in deps.items():
            version = meta.get("version") if isinstance(meta, dict) else None
            if version:
                version = version.lstrip("=")
                yield name, version, path_label


def _parse_package_json(content: bytes, path_label: str) -> Iterator[Tuple[str, str, str]]:
    try:
        data = json.loads(content.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return iter(())
    sections = ["dependencies", "devDependencies", "optionalDependencies"]
    for section in sections:
        deps = data.get(section, {}) or {}
        for name, version in deps.items():
            if not isinstance(version, str):
                continue
            if version.startswith(("file:", "git+", "http://", "https://")):
                continue
            normalized = version.strip()
            normalized = normalized.lstrip("^~")
            if normalized in {"*", "latest"}:
                continue
            yield name, normalized, path_label


def _parse_package_lock(content: bytes, path_label: str) -> Iterator[Tuple[str, str, str]]:
    try:
        data = json.loads(content.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return iter(())
    visited = set()

    def _walk(deps: Dict[str, dict]):
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if version:
                key = f"{name}@{version}"
                if key not in visited:
                    visited.add(key)
                    yield name, version, path_label
            nested = info.get("dependencies") or {}
            if isinstance(nested, dict):
                yield from _walk(nested)

    deps = data.get("dependencies") or {}
    if isinstance(deps, dict):
        yield from _walk(deps)


def _extract_version_from_spec(spec: str) -> str | None:
    if not spec:
        return None
    for prefix in ("==", ">=", "<=", ">", "<", "~="):
        if prefix in spec:
            parts = re.split(r"[;,]", spec)
            for part in parts:
                part = part.strip()
                if part.startswith(prefix):
                    return part[len(prefix):].strip()
            return None
    return None


def _match_vulnerabilities(deps: Iterable[Tuple[str, str, str]]) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    for name, version, path_label in deps:
        for vuln in VULNERABILITY_DB:
            if vuln["dependency_name"].lower() != name.lower():
                continue
            if _is_version_vulnerable(version, vuln["vulnerable_range"]):
                severity = _severity_from_cvss(vuln["cvss"], vuln["exploit_maturity"])
                description = (
                    f"{name} {version} matches vulnerable range {vuln['vulnerable_range']} "
                    f"({vuln['cve_id']})."
                )
                findings.append(
                    DependencyFinding(
                        dependency_name=name,
                        detected_version=version,
                        vulnerable_range=vuln["vulnerable_range"],
                        cve_id=vuln["cve_id"],
                        cvss_vector=vuln.get("cvss_vector"),
                        severity=severity,
                        affected_files=[path_label],
                        remediation_version=vuln["remediation_version"],
                        compliance_mapping=vuln["compliance_mapping"],
                        description=description,
                    )
                )
    return findings


def _severity_from_cvss(cvss: float, exploit_maturity: str) -> str:
    score = cvss
    if exploit_maturity == "high":
        score += 0.5
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "moderate"
    return "low"


def _is_version_vulnerable(version: str, vuln_range: str) -> bool:
    version_tuple = _parse_version(version)
    if version_tuple is None:
        return False
    checks = [part.strip() for part in vuln_range.split(",") if part.strip()]
    for check in checks:
        match = re.match(r"(<=|>=|==|<|>)(.+)", check)
        if not match:
            continue
        op = match.group(1)
        target = _parse_version(match.group(2).strip())
        if target is None:
            continue
        if op == "==" and version_tuple != target:
            return False
        if op == "<" and not (version_tuple < target):
            return False
        if op == "<=" and not (version_tuple <= target):
            return False
        if op == ">" and not (version_tuple > target):
            return False
        if op == ">=" and not (version_tuple >= target):
            return False
    return True if checks else False


def _parse_version(version: str) -> Tuple[int, ...] | None:
    if not version:
        return None
    cleaned = re.split(r"[+\\-]", version.strip())[0]
    parts = cleaned.split(".")
    numbers: List[int] = []
    for part in parts:
        if not part.isdigit():
            digits = re.match(r"(\\d+)", part)
            if digits:
                numbers.append(int(digits.group(1)))
            else:
                return None
        else:
            numbers.append(int(part))
    return tuple(numbers)


def _file_too_large(path: str) -> bool:
    try:
        return os.path.getsize(path) > MAX_FILE_SIZE
    except OSError:
        return True
