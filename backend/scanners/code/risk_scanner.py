import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

MAX_FILE_SIZE = 1024 * 1024  # 1 MB safeguard.

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

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".htm"}
INFRA_EXTENSIONS = {".yml", ".yaml", ".tf", ".tfvars"}

PATTERNS = [
    ("auth", re.compile(r"\bAllowAny\b"), "AllowAny authorization detected", "moderate"),
    ("debug", re.compile(r"\bDEBUG\s*=\s*True\b"), "Debug mode enabled", "high"),
    ("debug", re.compile(r"\bapp\.run\([^)]*debug\s*=\s*True"), "Application debug runtime enabled", "high"),
    ("injection", re.compile(r"cursor\.execute\(\s*f?['\"]"), "Raw SQL execution detected", "moderate"),
    (
        "injection",
        re.compile(
            r"(request\.(GET|POST|args)|req\.(query|params|body)).*(cursor\.execute|raw\(|execute\(|subprocess|os\.system|eval\()",
            re.IGNORECASE,
        ),
        "Potential unsanitized user input flowing into dangerous sink",
        "high",
    ),
    (
        "injection",
        re.compile(
            r"(cursor\.execute|raw\(|execute\(|subprocess|os\.system|eval\().*(request\.(GET|POST|args)|req\.(query|params|body))",
            re.IGNORECASE,
        ),
        "Potential unsanitized user input flowing into dangerous sink",
        "high",
    ),
    ("command", re.compile(r"subprocess\.(Popen|run)\(.*shell\s*=\s*True"), "Shell execution detected", "high"),
    ("command", re.compile(r"\bos\.system\("), "Direct shell command execution detected", "high"),
    ("command", re.compile(r"\bchild_process\.(exec|execSync)\("), "Node.js command execution (exec/execSync) detected", "high"),
    ("command", re.compile(r"\bchild_process\.(spawn|spawnSync)\([^)]*shell\s*:\s*true", re.IGNORECASE), "Node.js spawn with shell:true detected", "high"),
    ("command", re.compile(r"\bRuntime\.getRuntime\(\)\.exec\("), "Java Runtime exec detected", "high"),
    ("command", re.compile(r"\bProcessBuilder\("), "Java ProcessBuilder detected", "moderate"),
    ("unsafe_deserialization", re.compile(r"\bpickle\.loads\("), "Unsafe deserialization pattern detected", "high"),
    ("unsafe_deserialization", re.compile(r"\byaml\.load\("), "Unsafe YAML load detected (use SafeLoader)", "moderate"),
    ("code_execution", re.compile(r"\beval\("), "Dynamic code evaluation detected", "high"),
    ("code_execution", re.compile(r"\bnew Function\("), "Dynamic JavaScript function construction detected", "high"),
    ("crypto", re.compile(r"\b(md5|sha1)\("), "Weak cryptographic hash usage", "moderate"),
    ("crypto", re.compile(r"verify_signature\s*:\s*False|verify\s*=\s*False", re.IGNORECASE), "Signature verification disabled", "high"),
    ("xss", re.compile(r"dangerouslySetInnerHTML|innerHTML\s*="), "Potential DOM injection sink", "moderate"),
    ("xss", re.compile(r"\bmark_safe\("), "Unsafe HTML trust boundary bypass (mark_safe)", "moderate"),
    ("third_party", re.compile(r"<script[^>]+src=['\"]http://"), "Insecure third-party script source", "moderate"),
    ("api", re.compile(r"http://[^\s'\"]+"), "Insecure HTTP endpoint usage", "low"),
    ("ssrf", re.compile(r"\b(requests\.(get|post)|fetch\(|axios\.(get|post))\("), "Outbound request call detected - validate URL allowlist", "low"),
]

INFRA_PATTERNS = [
    ("k8s", re.compile(r"privileged:\s*true"), "Privileged container configuration", "high"),
    ("k8s", re.compile(r"hostNetwork:\s*true"), "Host network enabled", "moderate"),
    ("k8s", re.compile(r"hostPath:\s*"), "HostPath volume usage", "moderate"),
]


@dataclass
class CodeRiskFinding:
    title: str
    description: str
    remediation: str
    severity: str
    file_path: str
    line_number: int
    confidence_score: int
    rationale: str
    standard_mapping: list[str]


def scan_repository(repo_path: str) -> List[CodeRiskFinding]:
    if not repo_path:
        return []

    root = Path(repo_path)
    if root.is_file() and root.suffix.lower() == ".zip":
        return []
    if not root.exists():
        return []

    findings: list[CodeRiskFinding] = []
    signature_cache: set[str] = set()
    ignore_tokens = _load_ignore_tokens(root)

    for path in _iter_files(root, ignore_tokens):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for idx, line in enumerate(handle, start=1):
                    if "aegis-ignore" in line or "nosec" in line:
                        continue
                    findings.extend(_match_line(path, idx, line, signature_cache))
        except OSError:
            continue

    findings.extend(_scan_infra_files(root, signature_cache, ignore_tokens))
    findings.extend(_scan_dockerfile(root, signature_cache))
    return findings


def _iter_files(root: Path, ignore_tokens: list[str]) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if _path_contains_ignored_segment(path):
            continue
        if _path_contains_ignore_token(path, ignore_tokens):
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        yield path


def _path_contains_ignored_segment(path: Path) -> bool:
    lowered = str(path).replace("\\", "/").lower()
    return any(f"/{segment}/" in lowered for segment in IGNORE_PATH_SEGMENTS)


def _path_contains_ignore_token(path: Path, tokens: list[str]) -> bool:
    if not tokens:
        return False
    lowered = str(path).replace("\\", "/").lower()
    return any(token in lowered for token in tokens)


def _load_ignore_tokens(root: Path) -> list[str]:
    ignore_file = root / ".aegisignore"
    if not ignore_file.exists():
        return []
    try:
        content = ignore_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    tokens = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tokens.append(line.lower())
    return tokens


def _match_line(path: Path, line_number: int, line: str, cache: set[str]) -> list[CodeRiskFinding]:
    findings: list[CodeRiskFinding] = []
    for category, pattern, title, severity in PATTERNS:
        if not pattern.search(line):
            continue
        signature = f"{path}:{line_number}:{title}"
        if signature in cache:
            continue
        cache.add(signature)
        findings.append(
            CodeRiskFinding(
                title=title,
                description=f"Potential {category} risk detected in source code.",
                remediation="Review the implementation and apply secure coding guidance.",
                severity=severity,
                file_path=str(path),
                line_number=line_number,
                confidence_score=55,
                rationale="Heuristic pattern match in source code.",
                standard_mapping=["OWASP Top 10 A05", "ISO 27001 A.14"],
            )
        )
    return findings


def _scan_infra_files(root: Path, cache: set[str], ignore_tokens: list[str]) -> list[CodeRiskFinding]:
    findings: list[CodeRiskFinding] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if _path_contains_ignored_segment(path):
            continue
        if _path_contains_ignore_token(path, ignore_tokens):
            continue
        if path.suffix.lower() not in INFRA_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for _, pattern, title, severity in INFRA_PATTERNS:
            if not pattern.search(content):
                continue
            signature = f"{path}:{title}"
            if signature in cache:
                continue
            cache.add(signature)
            findings.append(
                CodeRiskFinding(
                    title=title,
                    description="Potential infrastructure hardening issue detected in configuration.",
                    remediation="Review infrastructure configuration and apply least-privilege defaults.",
                    severity=severity,
                    file_path=str(path),
                    line_number=1,
                    confidence_score=60,
                    rationale="Configuration pattern matched known risky settings.",
                    standard_mapping=["CIS Controls 4", "ISO 27001 A.13"],
                )
            )
    return findings


def _scan_dockerfile(root: Path, cache: set[str]) -> list[CodeRiskFinding]:
    dockerfile = root / "Dockerfile"
    if not dockerfile.exists():
        return []
    try:
        content = dockerfile.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if re.search(r"^\s*USER\s+root", content, flags=re.MULTILINE):
        signature = f"{dockerfile}:USER root"
        if signature in cache:
            return []
        cache.add(signature)
        return [
            CodeRiskFinding(
                title="Container runs as root",
                description="Dockerfile specifies USER root, increasing risk if the container is compromised.",
                remediation="Use a non-root user where possible and limit capabilities.",
                severity="moderate",
                file_path=str(dockerfile),
                line_number=1,
                confidence_score=65,
                rationale="Dockerfile explicitly sets USER root.",
                standard_mapping=["CIS Docker Benchmark 4.1", "ISO 27001 A.12"],
            )
        ]
    if not re.search(r"^\s*USER\s+", content, flags=re.MULTILINE):
        signature = f"{dockerfile}:missing USER"
        if signature in cache:
            return []
        cache.add(signature)
        return [
            CodeRiskFinding(
                title="Container user not specified",
                description="Dockerfile does not specify a non-root USER directive.",
                remediation="Define a dedicated non-root user for runtime.",
                severity="low",
                file_path=str(dockerfile),
                line_number=1,
                confidence_score=50,
                rationale="No USER directive detected in Dockerfile.",
                standard_mapping=["CIS Docker Benchmark 4.1", "ISO 27001 A.12"],
            )
        ]
    return []
