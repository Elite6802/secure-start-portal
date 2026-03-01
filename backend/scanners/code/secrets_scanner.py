import math
import os
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional


MAX_FILE_SIZE = 1024 * 1024  # 1 MB safeguard for snapshot scanning.
SCAN_WORKERS = min(8, os.cpu_count() or 4)

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

IGNORE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".mp4",
    ".mp3",
    ".lock",
}

IGNORE_FILENAMES = {
    ".env.example",
    ".env.sample",
    "example.env",
    "sample.env",
}

COMMENT_PREFIXES = ("#", "//", "--", ";")

PLACEHOLDER_PATTERNS = [
    re.compile(r"(?i)\b(example|sample|dummy|changeme|test|testing)\b"),
    re.compile(r"(?i)\b(your[_-]?key|your[_-]?token|your[_-]?secret)\b"),
    re.compile(r"(?i)\b(123456|password|secret)\b"),
]

SECRET_PATTERNS = [
    {
        "secret_type": "AWS Access Key",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": "high",
        "base_score": 80,
        "min_entropy": 3.6,
        "remediation": "Revoke the key immediately and rotate credentials in AWS IAM.",
        "rationale": "Matches AWS access key format.",
        "mapping": ["OWASP Top 10 A02", "NIST 800-53 IA-5"],
    },
    {
        "secret_type": "GitHub Token",
        "pattern": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "severity": "high",
        "base_score": 78,
        "min_entropy": 3.5,
        "remediation": "Revoke the token and replace with a scoped, short-lived token.",
        "rationale": "Matches GitHub token format.",
        "mapping": ["OWASP Top 10 A02", "ISO 27001 A.9"],
    },
    {
        "secret_type": "JWT Token",
        "pattern": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
        "severity": "high",
        "base_score": 70,
        "min_entropy": 3.2,
        "remediation": "Rotate the signing secret and invalidate issued tokens where possible.",
        "rationale": "Looks like a JWT bearer token.",
        "mapping": ["OWASP Top 10 A02", "NIST 800-53 IA-5"],
    },
    {
        "secret_type": "Generic API Key",
        "pattern": re.compile(r"\b[A-Za-z0-9_\-]{24,}\b"),
        "severity": "high",
        "base_score": 60,
        "min_entropy": 3.8,
        "remediation": "Move the key to a secrets manager and rotate the exposed value.",
        "rationale": "High-entropy string matched in sensitive context.",
        "mapping": ["OWASP Top 10 A02", "NIST 800-53 SC-12"],
        "context_hint": re.compile(r"(?i)\b(api[_-]?key|token|secret|auth|password)\b"),
    },
    {
        "secret_type": "Password Assignment",
        "pattern": re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"\\]{6,})['\"]?"),
        "severity": "high",
        "base_score": 75,
        "min_entropy": 2.8,
        "remediation": "Replace with a secret reference and rotate the password.",
        "rationale": "Explicit password assignment detected.",
        "mapping": ["OWASP Top 10 A02", "NIST 800-53 IA-5"],
        "value_group": 2,
    },
]


@dataclass
class SecretFinding:
    secret_type: str
    file_path: str
    line_number: int
    masked_value: str
    confidence_score: int
    severity: str
    rationale: str
    remediation: str
    standard_mapping: list[str]


def scan_repository(repo_path: str) -> List[SecretFinding]:
    if not repo_path:
        return []
    if os.path.isfile(repo_path) and repo_path.lower().endswith(".zip"):
        return list(_scan_zip(repo_path))
    if os.path.isdir(repo_path):
        return _scan_directory(repo_path)
    return []


def _scan_directory(root: str) -> list[SecretFinding]:
    file_paths: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in IGNORE_PATH_SEGMENTS]
        for filename in filenames:
            if _should_skip_file(filename):
                continue
            path = os.path.join(dirpath, filename)
            if _path_contains_ignored_segment(path):
                continue
            if _file_too_large(path):
                continue
            file_paths.append(path)
    file_paths.sort()

    findings: list[SecretFinding] = []

    def _scan_one(path: str):
        return list(_scan_text_file(path, path))

    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as executor:
        future_map = {executor.submit(_scan_one, path): path for path in file_paths}
        for future in as_completed(future_map):
            try:
                findings.extend(future.result())
            except Exception:
                continue
    findings.sort(key=lambda item: (item.file_path, item.line_number, item.secret_type))
    return findings


def _scan_zip(zip_path: str) -> Iterator[SecretFinding]:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if _should_skip_file(info.filename):
                    continue
                if _path_contains_ignored_segment(info.filename):
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
                yield from _scan_text_buffer(content, info.filename)
    except (zipfile.BadZipFile, FileNotFoundError):
        return iter(())


def _scan_text_file(path: str, display_path: str) -> Iterator[SecretFinding]:
    try:
        with open(path, "rb") as handle:
            content = handle.read(MAX_FILE_SIZE + 1)
    except OSError:
        return iter(())
    if len(content) > MAX_FILE_SIZE:
        return iter(())
    return _scan_text_buffer(content, display_path)


def _scan_text_buffer(content: bytes, display_path: str) -> Iterator[SecretFinding]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return iter(())
    if not text.strip():
        return iter(())

    in_block_comment = False
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("/*"):
            in_block_comment = True
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith(COMMENT_PREFIXES):
            continue
        for pattern in SECRET_PATTERNS:
            for match in pattern["pattern"].finditer(line):
                value = match.group(pattern.get("value_group", 0) or 0)
                if value is None:
                    value = match.group(0)
                if _is_placeholder(value):
                    continue
                if pattern.get("context_hint") and not pattern["context_hint"].search(line):
                    if pattern["secret_type"] == "Generic API Key":
                        continue
                entropy = _shannon_entropy(value)
                confidence = _score_confidence(
                    base=pattern["base_score"],
                    entropy=entropy,
                    min_entropy=pattern["min_entropy"],
                    line=line,
                    file_path=display_path,
                )
                if confidence < 35:
                    continue
                yield SecretFinding(
                    secret_type=pattern["secret_type"],
                    file_path=display_path,
                    line_number=idx,
                    masked_value=_mask_value(value),
                    confidence_score=confidence,
                    severity=pattern["severity"],
                    rationale=_build_rationale(pattern, entropy, line),
                    remediation=pattern["remediation"],
                    standard_mapping=pattern["mapping"],
                )


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if lowered in {"changeme", "example", "sample", "dummy", "test", "password"}:
        return True
    if len(value) < 6:
        return True
    return any(pattern.search(value) for pattern in PLACEHOLDER_PATTERNS)


def _build_rationale(pattern: dict, entropy: float, line: str) -> str:
    parts = [pattern["rationale"]]
    parts.append(f"Entropy score {entropy:.2f}.")
    if re.search(r"(?i)\b(secret|token|password|apikey)\b", line):
        parts.append("Sensitive keyword present in same line.")
    return " ".join(parts)


def _score_confidence(base: int, entropy: float, min_entropy: float, line: str, file_path: str) -> int:
    score = base
    if entropy >= min_entropy:
        score += 15
    elif entropy < min_entropy - 0.5:
        score -= 15
    if re.search(r"(?i)\b(example|sample|dummy|test)\b", line):
        score -= 20
    if _path_contains_ignored_segment(file_path):
        score -= 25
    if any(token in line.lower() for token in ["placeholder", "lorem", "todo"]):
        score -= 10
    return max(0, min(100, score))


def _mask_value(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _should_skip_file(filename: str) -> bool:
    lower = os.path.basename(filename).lower()
    if lower in IGNORE_FILENAMES:
        return True
    _, ext = os.path.splitext(lower)
    if ext in IGNORE_EXTENSIONS:
        return True
    return False


def _path_contains_ignored_segment(path: str) -> bool:
    parts = re.split(r"[\\/]+", path.lower())
    return any(part in IGNORE_PATH_SEGMENTS for part in parts)


def _file_too_large(path: str) -> bool:
    try:
        return os.path.getsize(path) > MAX_FILE_SIZE
    except OSError:
        return True
