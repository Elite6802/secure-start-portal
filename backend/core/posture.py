from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PostureScore:
    score: int  # 0..100, higher is better
    grade: str  # A..F
    penalty: float
    breakdown: dict[str, float]
    attack_surface_units: float


def _clamp_int(value: float, lo: int = 0, hi: int = 100) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return int(round(value))


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_posture_score(
    *,
    severity_counts: dict[str, int] | None,
    metadata: dict[str, Any] | None,
) -> PostureScore:
    """
    Compute a posture score from scan findings and basic exposure metrics.

    This is intentionally conservative and "explainable":
    - We do not infer findings that are not present.
    - We treat confidence/coverage as informational, not as a score booster.

    Inputs:
    - severity_counts: dict with keys {critical, high, moderate, low}
    - metadata: scan metrics (hosts_alive, open_ports, endpoints_scanned, repositories_scanned, etc.)

    Output:
    - 0..100 score where 100 is best posture (no meaningful exposure signals)
    """
    severity_counts = severity_counts or {}
    metadata = metadata or {}

    critical = int(severity_counts.get("critical") or 0)
    high = int(severity_counts.get("high") or 0)
    moderate = int(severity_counts.get("moderate") or severity_counts.get("medium") or 0)
    low = int(severity_counts.get("low") or 0)

    # Base penalty is absolute: a single critical issue should always move the score materially.
    base_penalty = (critical * 18.0) + (high * 9.0) + (moderate * 4.0) + (low * 1.0)

    hosts_alive = float(metadata.get("hosts_alive") or metadata.get("hosts_scanned") or 0)
    open_ports = float(metadata.get("open_ports") or 0)
    endpoints = float(metadata.get("endpoints_scanned") or metadata.get("endpoints_assessed") or 0)
    repos = float(metadata.get("repositories_scanned") or metadata.get("repos_scanned") or 0)

    # Exposure penalty is capped so a large environment isn't punished just for being large.
    # Values tuned to keep the scale stable across scan types.
    exposure_penalty = min(
        20.0,
        (open_ports * 0.6) + (hosts_alive * 0.08) + (endpoints * 0.04) + (repos * 0.6),
    )

    # Attack surface units are used for trend context, not as the primary score driver.
    attack_surface_units = max(1.0, open_ports + (hosts_alive * 0.2) + (endpoints * 0.2) + (repos * 1.0))

    penalty = min(100.0, base_penalty + exposure_penalty)
    score = _clamp_int(100.0 - penalty)
    grade = grade_for_score(score)

    breakdown = {
        "base_penalty": base_penalty,
        "exposure_penalty": exposure_penalty,
        "critical": float(critical),
        "high": float(high),
        "moderate": float(moderate),
        "low": float(low),
        "hosts_alive": hosts_alive,
        "open_ports": open_ports,
        "endpoints": endpoints,
        "repos": repos,
    }

    return PostureScore(
        score=score,
        grade=grade,
        penalty=penalty,
        breakdown=breakdown,
        attack_surface_units=attack_surface_units,
    )


def posture_payload(score: PostureScore) -> dict[str, Any]:
    return {
        "score": score.score,
        "grade": score.grade,
        "penalty": score.penalty,
        "attack_surface_units": score.attack_surface_units,
        "breakdown": score.breakdown,
    }

