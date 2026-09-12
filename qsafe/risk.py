"""Turning an inventory into a migration order.

The organising idea is Mosca's inequality. Let

    X = how long the data must stay confidential, in years
    Y = how long the migration itself will take, in years
    Z = years until a cryptographically relevant quantum computer exists

If X + Y > Z, data encrypted today is already exposed, because an adversary
recording traffic now can decrypt it later. This is the Harvest Now, Decrypt
Later problem, and it is why "we will deal with it when quantum computers
arrive" is not a position.

Z is unknowable. The tool takes it as an explicit assumption so the number can
be argued with rather than buried.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from .algorithms import RISK_WEIGHT, Risk, lookup, unknown
from .scanner import Finding

CONFIDENCE_WEIGHT = {"certain": 1.0, "high": 0.9, "medium": 0.65, "low": 0.35}

# Priority is the primary sort key. Score only breaks ties within a band, so a
# classically broken algorithm always sits above a quantum-broken one however
# the multipliers fall out — you fix what is exploitable today first.
PRIORITY_RANK = {"immediate": 0, "high": 1, "medium": 2, "low": 3, "none": 4}

# Milestones from the DST task force roadmap under the National Quantum Mission.
DST_MILESTONES = [
    (2026, "Tier-1 and Tier-2 PQC testing and certification laboratories operational"),
    (2027, "Cryptographic inventories complete across critical information infrastructure"),
    (2028, "High-priority systems migrated to post-quantum algorithms"),
    (2029, "Full post-quantum adoption across government and regulated sectors"),
]


@dataclass
class Profile:
    """What the organisation is and how long its data matters."""
    organisation: str = "Unnamed organisation"
    sector: str = "general"
    data_lifetime_years: int = 10
    migration_years: int = 3
    crqc_year: int = 2035
    is_critical_infrastructure: bool = False

    @property
    def years_to_crqc(self) -> int:
        return max(0, self.crqc_year - date.today().year)

    @property
    def mosca_exposure(self) -> int:
        """X + Y - Z. Positive means already exposed."""
        return self.data_lifetime_years + self.migration_years - self.years_to_crqc

    @property
    def mosca_breached(self) -> bool:
        return self.mosca_exposure > 0

    @property
    def deadline_year(self) -> int:
        return 2027 if self.is_critical_infrastructure else 2029

    @property
    def start_by_year(self) -> int:
        """The latest year migration can begin and still finish in time."""
        return self.deadline_year - self.migration_years


@dataclass
class Assessed:
    finding: Finding
    risk: Risk
    rationale: str
    replacement: str | None
    nist_standard: str | None
    family: str
    score: float
    priority: str

    def as_dict(self) -> dict:
        return {
            "path": self.finding.path,
            "line": self.finding.line,
            "algorithm": self.finding.algorithm,
            "rule_id": self.finding.rule_id,
            "description": self.finding.description,
            "confidence": self.finding.confidence,
            "evidence": self.finding.evidence,
            "key_size": self.finding.key_size,
            "detail": self.finding.detail,
            "risk": self.risk.value,
            "rationale": self.rationale,
            "replacement": self.replacement,
            "nist_standard": self.nist_standard,
            "family": self.family,
            "score": round(self.score, 1),
            "priority": self.priority,
        }


@dataclass
class Assessment:
    profile: Profile
    items: list[Assessed]
    scanned_path: str
    generated_on: str = field(default_factory=lambda: date.today().isoformat())

    def by_risk(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.risk.value] = counts.get(item.risk.value, 0) + 1
        return counts

    def by_priority(self) -> dict[str, int]:
        counts = {"immediate": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
        for item in self.items:
            counts[item.priority] = counts.get(item.priority, 0) + 1
        return counts

    def by_algorithm(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.finding.algorithm] = counts.get(item.finding.algorithm, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    @property
    def readiness_score(self) -> int:
        """0 to 100. 100 means nothing in the inventory needs replacing."""
        if not self.items:
            return 100
        total = sum(
            RISK_WEIGHT[item.risk] * CONFIDENCE_WEIGHT.get(item.finding.confidence, 0.5)
            for item in self.items
        )
        worst = sum(
            100 * CONFIDENCE_WEIGHT.get(item.finding.confidence, 0.5)
            for item in self.items
        )
        return int(round(100 * (1 - total / worst))) if worst else 100

    @property
    def found_nothing(self) -> bool:
        return not self.items

    @property
    def verdict(self) -> str:
        # An empty result is not a pass. It far more often means the scan was
        # pointed at the wrong place, or at an estate this tool cannot read,
        # than that the organisation uses no cryptography at all.
        if self.found_nothing:
            return "No cryptography detected — verify the scan target"
        score = self.readiness_score
        if score >= 90:
            return "Largely quantum-safe"
        if score >= 70:
            return "Partial exposure"
        if score >= 40:
            return "Substantial exposure"
        return "Critical exposure"


def _priority(risk: Risk, confidence: str, profile: Profile) -> tuple[float, str]:
    base = float(RISK_WEIGHT[risk])
    score = base * CONFIDENCE_WEIGHT.get(confidence, 0.5)

    if risk in (Risk.BROKEN_BY_QUANTUM, Risk.WEAKENED_BY_QUANTUM):
        if profile.mosca_breached:
            score *= 1.25
        if profile.is_critical_infrastructure:
            score *= 1.15

    if risk is Risk.CLASSICALLY_BROKEN:
        label = "immediate"
    elif score >= 75:
        label = "high"
    elif score >= 40:
        label = "medium"
    elif score > 0:
        label = "low"
    else:
        label = "none"
    return score, label


def assess(findings: list[Finding], profile: Profile, scanned_path: str) -> Assessment:
    items: list[Assessed] = []
    for finding in findings:
        algorithm = lookup(finding.algorithm) or unknown(finding.algorithm)
        risk = algorithm.risk
        rationale = algorithm.rationale

        # An RSA key below 3072 bits is weak on classical grounds too, and that
        # is a much easier conversation than the quantum one.
        if finding.algorithm == "RSA" and finding.key_size and finding.key_size < 2048:
            risk = Risk.CLASSICALLY_BROKEN
            rationale = (
                f"RSA-{finding.key_size} is below the NIST minimum of 2048 bits "
                "and is weak against classical attack, before quantum is considered."
            )

        score, label = _priority(risk, finding.confidence, profile)
        items.append(Assessed(
            finding=finding, risk=risk, rationale=rationale,
            replacement=algorithm.replacement, nist_standard=algorithm.nist_standard,
            family=algorithm.family, score=score, priority=label,
        ))

    items.sort(key=lambda item: (
        PRIORITY_RANK.get(item.priority, 9),
        -item.score,
        item.finding.path,
        item.finding.line,
    ))
    return Assessment(profile=profile, items=items, scanned_path=scanned_path)
