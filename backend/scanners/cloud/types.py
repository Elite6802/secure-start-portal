from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CloudFindingResult:
    title: str
    severity: str
    description: str
    remediation: str
    evidence: dict
    compliance: list[str]
