import hashlib
import os
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse


SNAPSHOT_DIR_ENV = "AEGIS_REPO_SNAPSHOT_DIR"
DEFAULT_SNAPSHOT_DIR = "/app/repo_snapshots"


@dataclass
class RepoSnapshot:
    repo_url: str
    snapshot_path: str
    source: str


def ensure_repo_snapshot(repo_url: str) -> RepoSnapshot | None:
    repo_url = (repo_url or "").strip()
    if not repo_url:
        return None

    if repo_url.startswith("file://"):
        local_path = repo_url[7:]
        if os.path.exists(local_path):
            return RepoSnapshot(repo_url=repo_url, snapshot_path=local_path, source="file")
        return None

    if not repo_url.startswith(("http://", "https://")):
        return None

    github = _normalize_github_url(repo_url)
    if not github:
        return None

    base_dir = os.getenv(SNAPSHOT_DIR_ENV, DEFAULT_SNAPSHOT_DIR)
    if not base_dir:
        return None
    os.makedirs(base_dir, exist_ok=True)
    slug = hashlib.sha256(github.encode("utf-8")).hexdigest()[:16]
    snapshot_path = os.path.join(base_dir, f"{slug}.zip")
    if os.path.exists(snapshot_path):
        return RepoSnapshot(repo_url=repo_url, snapshot_path=snapshot_path, source="cache")

    archive_url = _github_archive_url(github)
    if not archive_url:
        return None
    if _download_archive(archive_url, snapshot_path):
        return RepoSnapshot(repo_url=repo_url, snapshot_path=snapshot_path, source="github")
    return None


def _normalize_github_url(repo_url: str) -> str | None:
    try:
        parsed = urlparse(repo_url)
    except ValueError:
        return None
    if parsed.netloc.lower() != "github.com":
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    return f"https://github.com/{owner}/{repo}"


def _github_archive_url(repo_url: str) -> str | None:
    normalized = _normalize_github_url(repo_url)
    if not normalized:
        return None
    owner, repo = normalized.rsplit("/", 2)[-2:]
    return f"https://api.github.com/repos/{owner}/{repo}/zipball/HEAD"


def _download_archive(url: str, dest_path: str) -> bool:
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_ACCESS_TOKEN")
    headers = {
        "User-Agent": "AegisScanner/1.0",
        "Accept": "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            content = response.read()
        if not content:
            return False
        with open(dest_path, "wb") as handle:
            handle.write(content)
        return True
    except Exception:
        if os.path.exists(dest_path):
            try:
                os.remove(dest_path)
            except OSError:
                pass
        return False
