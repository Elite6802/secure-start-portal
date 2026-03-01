import hashlib
import json
import os
import subprocess
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

MAX_FILE_SIZE = 1024 * 1024  # 1 MB safeguard.
MAX_FILES_PER_BATCH = 200
MAX_DUPLICATION_FILES = 400
HASH_WORKERS = min(8, os.cpu_count() or 4)

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

SUPPORTED_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js"},
    "react": {".jsx", ".tsx"},
    "css": {".css"},
    "html": {".html", ".htm"},
}

SEVERITY_DEFAULT = "moderate"


@dataclass
class ComplianceFinding:
    rule_id: str
    title: str
    description: str
    file_path: str
    line_number: int
    severity: str
    remediation: str
    standard_mapping: list[str]
    confidence_score: int
    rationale: str
    language: str


@dataclass
class ComplianceScanResult:
    findings: List[ComplianceFinding]
    metrics: dict
    file_hashes: dict
    files_scanned: int
    files_changed: int


def scan_repository(
    repo_path: str,
    baseline_hashes: Optional[dict] = None,
    languages: Optional[Iterable[str]] = None,
) -> ComplianceScanResult:
    if not repo_path:
        return ComplianceScanResult([], {}, {}, 0, 0)

    if os.path.isfile(repo_path) and repo_path.lower().endswith(".zip"):
        with tempfile.TemporaryDirectory() as tmpdir:
            _extract_zip(repo_path, tmpdir)
            return _scan_root(Path(tmpdir), baseline_hashes or {}, languages=languages)

    if os.path.isdir(repo_path):
        return _scan_root(Path(repo_path), baseline_hashes or {}, languages=languages)

    return ComplianceScanResult([], {}, {}, 0, 0)


def _scan_root(root: Path, baseline_hashes: dict, languages: Optional[Iterable[str]] = None) -> ComplianceScanResult:
    allowed_languages = set(languages) if languages else set(SUPPORTED_EXTENSIONS.keys())
    language_files = {
        language: _collect_files(root, exts)
        for language, exts in SUPPORTED_EXTENSIONS.items()
        if language in allowed_languages
    }
    file_hashes = _hash_files(language_files)
    changed_files = _filter_changed_files(language_files, file_hashes, baseline_hashes)

    findings: list[ComplianceFinding] = []
    metrics: dict = {
        "lint_totals": {},
        "complexity": {},
        "duplication": {},
        "incremental": {
            "files_total": sum(len(files) for files in language_files.values()),
            "files_changed": sum(len(files) for files in changed_files.values()),
        },
    }

    if "python" in changed_files:
        findings.extend(_run_pycodestyle(root, changed_files["python"]))
    if "javascript" in changed_files:
        findings.extend(_run_eslint(root, changed_files["javascript"], react=False))
    if "react" in changed_files:
        findings.extend(_run_eslint(root, changed_files["react"], react=True))
    if "css" in changed_files:
        findings.extend(_run_stylelint(root, changed_files["css"]))
    if "html" in changed_files:
        findings.extend(_run_htmlhint(root, changed_files["html"]))

    findings.sort(key=lambda item: (item.file_path, item.line_number, item.rule_id))
    metrics["lint_totals"] = {
        language: _count_language(findings, language) for language in allowed_languages
    }
    metrics["complexity"] = _python_complexity(root, changed_files.get("python", []))
    metrics["duplication"] = _duplication_metrics(root, _flatten_files(changed_files))

    files_scanned = sum(len(files) for files in language_files.values())
    files_changed = sum(len(files) for files in changed_files.values())
    return ComplianceScanResult(findings, metrics, file_hashes, files_scanned, files_changed)


def _extract_zip(zip_path: str, dest_dir: str) -> None:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(dest_dir)
    except (zipfile.BadZipFile, FileNotFoundError):
        return


def _collect_files(root: Path, extensions: Iterable[str]) -> List[str]:
    results: list[str] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if _path_contains_ignored_segment(path):
            continue
        if path.suffix.lower() not in extensions:
            continue
        if path.stat().st_size > MAX_FILE_SIZE:
            continue
        results.append(str(path))
    results.sort()
    return results


def _path_contains_ignored_segment(path: Path) -> bool:
    lowered = str(path).replace("\\", "/").lower()
    return any(f"/{segment}/" in lowered for segment in IGNORE_PATH_SEGMENTS)


def _hash_files(language_files: dict) -> dict:
    hashes: dict[str, str] = {}
    all_files = [path for files in language_files.values() for path in files]
    if not all_files:
        return hashes

    def _hash_one(path: str):
        try:
            with open(path, "rb") as handle:
                chunk = handle.read(MAX_FILE_SIZE + 1)
        except OSError:
            return None
        if len(chunk) > MAX_FILE_SIZE:
            return None
        return path, hashlib.sha256(chunk).hexdigest()

    with ThreadPoolExecutor(max_workers=HASH_WORKERS) as executor:
        futures = [executor.submit(_hash_one, path) for path in all_files]
        for future in as_completed(futures):
            result = future.result()
            if not result:
                continue
            path, digest = result
            hashes[path] = digest
    return hashes


def _filter_changed_files(language_files: dict, current_hashes: dict, baseline_hashes: dict) -> dict:
    if not baseline_hashes:
        return language_files
    changed: dict[str, list[str]] = {language: [] for language in language_files}
    for language, files in language_files.items():
        for path in files:
            if baseline_hashes.get(path) != current_hashes.get(path):
                changed[language].append(path)
    return changed


def _run_pycodestyle(root: Path, files: list[str]) -> list[ComplianceFinding]:
    if not files:
        return []
    output_chunks: list[str] = []
    for chunk in _chunk_list(files, MAX_FILES_PER_BATCH):
        command = [
            "pycodestyle",
            "--format=%(path)s:%(row)d:%(col)d:%(code)s %(text)s",
            *chunk,
        ]
        output_chunks.append(_run_command(command, root))
    result = "\n".join(filter(None, output_chunks))
    findings: list[ComplianceFinding] = []
    for line in result.splitlines():
        parts = line.split(":", 3)
        if len(parts) < 4:
            continue
        path, row, col, rest = parts
        code = rest.strip().split(" ", 1)[0]
        text = rest.strip()[len(code):].strip()
        severity = "high" if code.startswith(("E9", "F")) else "moderate"
        findings.append(
            ComplianceFinding(
                rule_id=code,
                title="PEP8 compliance",
                description=text or "PEP8 violation detected.",
                file_path=path,
                line_number=int(row) if row.isdigit() else 0,
                severity=severity,
                remediation="Refactor the line to meet PEP8 formatting standards.",
                standard_mapping=["OWASP Top 10 A05", "ISO 27001 A.14"],
                confidence_score=70,
                rationale="pycodestyle reported a formatting or style issue.",
                language="python",
            )
        )
    return findings


def _run_eslint(root: Path, files: list[str], react: bool) -> list[ComplianceFinding]:
    if not files:
        return []
    config_name = "eslint.react.cjs" if react else "eslint.base.cjs"
    config_path = root / "backend" / "scanners" / "code" / "configs" / config_name
    findings: list[ComplianceFinding] = []
    for chunk in _chunk_list(files, MAX_FILES_PER_BATCH):
        command = ["eslint", "--format", "json", "--config", str(config_path), *chunk]
        output = _run_command(command, root)
        try:
            payload = json.loads(output) if output else []
        except json.JSONDecodeError:
            continue
        for file_result in payload:
            for message in file_result.get("messages", []):
                rule_id = message.get("ruleId") or "eslint"
                severity = "high" if message.get("severity") == 2 else "low"
                findings.append(
                    ComplianceFinding(
                        rule_id=rule_id,
                        title="Lint compliance",
                        description=message.get("message", "ESLint violation detected."),
                        file_path=file_result.get("filePath", ""),
                        line_number=message.get("line", 0),
                        severity=severity,
                        remediation="Resolve linting errors and align with project lint rules.",
                        standard_mapping=["OWASP Top 10 A05", "ISO 27001 A.14"],
                        confidence_score=65,
                        rationale="ESLint flagged a compliance issue.",
                        language="react" if react else "javascript",
                    )
                )
    return findings


def _run_stylelint(root: Path, files: list[str]) -> list[ComplianceFinding]:
    if not files:
        return []
    config_path = root / "backend" / "scanners" / "code" / "configs" / "stylelint.config.cjs"
    findings: list[ComplianceFinding] = []
    for chunk in _chunk_list(files, MAX_FILES_PER_BATCH):
        command = ["stylelint", "--formatter", "json", "--config", str(config_path), *chunk]
        output = _run_command(command, root)
        try:
            payload = json.loads(output) if output else []
        except json.JSONDecodeError:
            continue
        for file_result in payload:
            for warning in file_result.get("warnings", []):
                severity = "high" if warning.get("severity") == "error" else "low"
                findings.append(
                    ComplianceFinding(
                        rule_id=warning.get("rule", "stylelint"),
                        title="Stylelint compliance",
                        description=warning.get("text", "Stylelint violation detected."),
                        file_path=file_result.get("source", ""),
                        line_number=warning.get("line", 0),
                        severity=severity,
                        remediation="Update styles to comply with lint standards.",
                        standard_mapping=["OWASP Top 10 A05", "ISO 27001 A.14"],
                        confidence_score=60,
                        rationale="Stylelint reported a linting violation.",
                        language="css",
                    )
                )
    return findings


def _run_htmlhint(root: Path, files: list[str]) -> list[ComplianceFinding]:
    if not files:
        return []
    config_path = root / "backend" / "scanners" / "code" / "configs" / "htmlhint.json"
    findings: list[ComplianceFinding] = []
    for chunk in _chunk_list(files, MAX_FILES_PER_BATCH):
        command = ["htmlhint", "--format", "json", "--config", str(config_path), *chunk]
        output = _run_command(command, root)
        try:
            payload = json.loads(output) if output else []
        except json.JSONDecodeError:
            continue
        for file_result in payload:
            for message in file_result.get("messages", []):
                severity = "high" if message.get("type") == "error" else "low"
                findings.append(
                    ComplianceFinding(
                        rule_id=message.get("rule", "htmlhint"),
                        title="HTML compliance",
                        description=message.get("message", "HTML lint violation detected."),
                        file_path=file_result.get("file", ""),
                        line_number=message.get("line", 0),
                        severity=severity,
                        remediation="Update markup to comply with HTML lint rules.",
                        standard_mapping=["OWASP Top 10 A05", "ISO 27001 A.14"],
                        confidence_score=60,
                        rationale="HTMLHint flagged a compliance issue.",
                        language="html",
                    )
                )
    return findings


def _python_complexity(root: Path, files: list[str]) -> dict:
    if not files:
        return {}
    payload: dict = {}
    for chunk in _chunk_list(files, MAX_FILES_PER_BATCH):
        command = ["radon", "cc", "-s", "-j", *chunk]
        output = _run_command(command, root)
        try:
            partial = json.loads(output) if output else {}
        except json.JSONDecodeError:
            continue
        payload.update(partial)
    total = 0
    count = 0
    for entries in payload.values():
        for entry in entries:
            total += entry.get("complexity", 0)
            count += 1
    if count == 0:
        return {}
    return {"python_avg_cc": round(total / count, 2), "python_items": count}


def _duplication_metrics(root: Path, files: list[str]) -> dict:
    if not files:
        return {}
    if len(files) > MAX_DUPLICATION_FILES:
        files = files[:MAX_DUPLICATION_FILES]
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "jscpd-report.json"
        command = [
            "jscpd",
            "--reporters",
            "json",
            "--output",
            str(report_path),
            "--min-lines",
            "5",
            "--min-tokens",
            "70",
            "--silent",
            *files,
        ]
        _run_command(command, root)
        if not report_path.exists():
            return {}
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    duplication = payload.get("statistics", {}).get("total", {})
    percentage = duplication.get("percentage", 0)
    duplicates = duplication.get("clones", 0)
    return {"percentage": percentage, "duplicates": duplicates}


def _run_command(command: list[str], root: Path) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout or ""


def _flatten_files(language_files: dict) -> list[str]:
    merged: list[str] = []
    for files in language_files.values():
        merged.extend(files)
    merged.sort()
    return merged


def _chunk_list(files: list[str], chunk_size: int) -> list[list[str]]:
    if chunk_size <= 0:
        return [files]
    return [files[i : i + chunk_size] for i in range(0, len(files), chunk_size)]


def _count_language(findings: list[ComplianceFinding], language: str) -> int:
    return sum(1 for finding in findings if finding.language == language)
