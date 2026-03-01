from __future__ import annotations

import math
from dataclasses import dataclass


class CvssError(ValueError):
    pass


@dataclass(frozen=True)
class CvssResult:
    version: str
    vector: str
    base_score: float
    severity: str


def _roundup_1_decimal(value: float) -> float:
    """
    CVSS v3.1 Roundup as defined by FIRST (see Appendix A implementer guidance).
    Uses integer arithmetic to avoid float artifacts.
    """
    int_input = int(round(value * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int(int_input / 10000) + 1) / 10.0


def _severity_from_score(score: float) -> str:
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def score_cvss3(vector: str) -> CvssResult:
    """
    Compute CVSS v3.0/v3.1 Base Score from a vector string.
    Supports vectors starting with "CVSS:3.0/" or "CVSS:3.1/".
    """
    if not vector or not isinstance(vector, str):
        raise CvssError("CVSS vector must be a non-empty string.")
    vector = vector.strip()
    if not (vector.startswith("CVSS:3.0/") or vector.startswith("CVSS:3.1/")):
        raise CvssError("Unsupported CVSS vector version. Expected CVSS:3.0 or CVSS:3.1.")

    version = vector.split("/", 1)[0].split(":", 1)[1]
    parts = vector.split("/")[1:]
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        metrics[k] = v

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = sorted(required - set(metrics.keys()))
    if missing:
        raise CvssError(f"Missing base metrics in vector: {', '.join(missing)}.")

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(metrics["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(metrics["AC"])
    ui = {"N": 0.85, "R": 0.62}.get(metrics["UI"])
    scope = metrics["S"]
    if scope not in {"U", "C"}:
        raise CvssError("Invalid Scope (S) value.")

    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["C"])
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["I"])
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["A"])

    if av is None or ac is None or ui is None or c is None or i is None or a is None:
        raise CvssError("Invalid metric value in vector.")

    pr_raw = metrics["PR"]
    if pr_raw not in {"N", "L", "H"}:
        raise CvssError("Invalid Privileges Required (PR) value.")
    if scope == "U":
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}[pr_raw]
    else:
        pr = {"N": 0.85, "L": 0.68, "H": 0.50}[pr_raw]

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow((iss - 0.02), 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    else:
        if scope == "U":
            base_score = _roundup_1_decimal(min(impact + exploitability, 10.0))
        else:
            base_score = _roundup_1_decimal(min(1.08 * (impact + exploitability), 10.0))

    base_score = float(f"{base_score:.1f}")
    return CvssResult(version=version, vector=vector, base_score=base_score, severity=_severity_from_score(base_score))

